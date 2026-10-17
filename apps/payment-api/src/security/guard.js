import { safeEqual, hashPassword, verifyPassword, verifyTotp, randomToken } from './crypto.js';
import { SessionManager, SESSION_COOKIE, parseCookies } from './session.js';
import { ObserverVerifier } from './observer-auth.js';
import { RateLimiter, clientIp } from './rate-limit.js';

/**
 * Route classification. A request is checked against these in order; the first
 * match decides which credential it needs. Anything under /api/v1/admin/ is
 * owner-only by default, so a NEW admin route is protected automatically.
 */
export const RouteClass = Object.freeze({
  PUBLIC: 'public',
  OWNER: 'owner',
  OBSERVER: 'observer',
  ANDROID: 'android',
  DEV_ONLY: 'dev_only'
});

const OWNER_PREFIXES = ['/api/v1/admin/', '/api/services', '/api/logs/'];

// Pairing is a bootstrap: the phone has no key yet, so it presents a one-time
// pairing token that only the signed-in owner can mint.
const ANDROID_PAIR_PATHS = new Set(['/api/v1/pollers/android/pair', '/api/v1/observers/sms/pair']);
const ANDROID_PATHS = new Set([
  '/api/v1/pollers/android/events', '/api/v1/observers/sms',
  '/api/v1/pollers/android/heartbeat', '/api/v1/pollers/heartbeat', '/api/v1/observers/heartbeat'
]);
const OBSERVER_PATHS = new Set(['/api/v1/pollers/events', '/api/v1/pollers/gmail-config']);
// Gmail / SMS observers poll this; it only reveals amounts of live sessions.
const OBSERVER_READ_PATHS = new Set(['/api/v1/pollers/active-window']);
const DEV_ONLY_RE = /^\/api\/v1\/checkout\/[^/]+\/simulate-observation$/;

export function classifyRoute(method, pathname) {
  if (OWNER_PREFIXES.some(p => pathname === p || pathname.startsWith(p) || pathname === p.replace(/\/$/, ''))) {
    return RouteClass.OWNER;
  }
  if (ANDROID_PAIR_PATHS.has(pathname)) return RouteClass.ANDROID;
  if (ANDROID_PATHS.has(pathname)) return RouteClass.ANDROID;
  if (OBSERVER_PATHS.has(pathname) || OBSERVER_READ_PATHS.has(pathname)) return RouteClass.OBSERVER;
  if (DEV_ONLY_RE.test(pathname)) return RouteClass.DEV_ONLY;
  return RouteClass.PUBLIC;
}

/** Test bypass needs BOTH flags and is impossible in production. */
export function insecureTestModeEnabled(env = process.env) {
  return env.NODE_ENV === 'test' && env.YOUPI_INSECURE_TEST_MODE === '1';
}

export function isProduction(env = process.env) {
  return env.NODE_ENV === 'production' || env.YOUPI_MODE === 'production' || Boolean(env.RENDER);
}

const WEAK_VALUES = new Set([
  'android_pairing_enrollment_secret_key_32_chars',
  'youpi_sms_pair_token_secure',
  'super_secret_jwt_key_change_in_production_min_32_chars',
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  'AdminSecurePassword123!'
]);

/**
 * Reads the security configuration from the environment and reports every
 * problem at once. In production a bad configuration is fatal (fail closed).
 */
export function loadSecurityConfig(env = process.env) {
  const problems = [];
  const production = isProduction(env);

  const sessionSecret = env.ADMIN_SESSION_SECRET || '';
  if (sessionSecret.length < 32) problems.push('ADMIN_SESSION_SECRET must be set to at least 32 random characters.');
  if (WEAK_VALUES.has(sessionSecret)) problems.push('ADMIN_SESSION_SECRET is a known default value.');

  const ownerEmail = (env.ADMIN_EMAIL || '').trim().toLowerCase();
  const passwordHash = env.ADMIN_PASSWORD_HASH || '';
  const totpSecret = env.ADMIN_TOTP_SECRET || '';
  const ssoUserIds = (env.ADMIN_SSO_USER_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
  const supabaseUrl = (env.SUPABASE_URL || '').replace(/\/+$/, '');

  const passwordLoginConfigured = Boolean(ownerEmail && passwordHash && totpSecret);
  const ssoConfigured = Boolean(supabaseUrl && ssoUserIds.length);
  if (!passwordLoginConfigured && !ssoConfigured) {
    problems.push('Configure owner access: ADMIN_EMAIL + ADMIN_PASSWORD_HASH + ADMIN_TOTP_SECRET, and/or SUPABASE_URL + ADMIN_SSO_USER_IDS.');
  }
  if (passwordHash && !passwordHash.startsWith('scrypt$')) problems.push('ADMIN_PASSWORD_HASH must be produced by `npm run admin:setup`.');

  const observerSecret = env.OBSERVER_INGEST_SECRET || '';
  if (observerSecret && observerSecret.length < 32) problems.push('OBSERVER_INGEST_SECRET must be at least 32 characters.');
  if (WEAK_VALUES.has(observerSecret)) problems.push('OBSERVER_INGEST_SECRET is a known default value.');

  return {
    production,
    problems,
    ok: problems.length === 0,
    sessionSecret,
    ownerEmail,
    passwordHash,
    totpSecret,
    ssoUserIds,
    supabaseUrl,
    supabaseAnonKey: env.SUPABASE_ANON_KEY || '',
    observerSecret,
    allowedOrigins: (env.ADMIN_ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean)
  };
}

/**
 * Central request guard. Install once with `server.use(guard.middleware)`;
 * it runs before every route handler.
 */
export class SecurityGuard {
  /**
   * @param {{
   *   config: ReturnType<typeof loadSecurityConfig>,
   *   env?: NodeJS.ProcessEnv,
   *   now?: () => number,
   *   resolveAndroidDevice?: (deviceId: string) => any
   * }} opts
   */
  constructor({ config, env = process.env, now = () => Date.now(), resolveAndroidDevice = null }) {
    this.config = config;
    this.env = env;
    this.now = now;
    this.insecureTest = insecureTestModeEnabled(env);
    this.sessions = new SessionManager({ secret: config.sessionSecret, now });
    this.observer = new ObserverVerifier({ secret: config.observerSecret, now });
    this.limiter = new RateLimiter({ now });
    this.usedTotpSteps = new Map();
    this.resolveAndroidDevice = resolveAndroidDevice;
    this.productionLocked = config.production && !config.ok;
  }

  secureCookies() {
    return this.config.production || this.env.ADMIN_COOKIE_SECURE === '1';
  }

  /** Returns the owner session for a request, or null. */
  ownerSession(req) {
    if (this.insecureTest) return { sub: 'test-owner', method: 'insecure-test' };
    const cookies = parseCookies(req.headers.cookie);
    const fromCookie = this.sessions.verify(cookies[SESSION_COOKIE]);
    if (fromCookie) return fromCookie;
    const auth = String(req.headers.authorization || '');
    if (auth.startsWith('Bearer ')) return this.sessions.verify(auth.slice(7).trim());
    return null;
  }

  /**
   * @returns {Promise<{ ok: true } | { ok: false, status: number, error: string }>}
   */
  async check(req, pathname, rawSearch, readRawBody) {
    const cls = classifyRoute(req.method, pathname);
    if (cls === RouteClass.PUBLIC) return { ok: true };

    if (this.productionLocked) {
      return { ok: false, status: 503, error: 'Gateway security is not configured. See server logs.' };
    }

    if (cls === RouteClass.OWNER) {
      return this.ownerSession(req) ? { ok: true } : { ok: false, status: 401, error: 'Owner authentication required.' };
    }

    if (cls === RouteClass.DEV_ONLY) {
      if (this.config.production) return { ok: false, status: 404, error: `Route not found: ${req.method} ${pathname}` };
      return this.ownerSession(req) ? { ok: true } : { ok: false, status: 401, error: 'Owner authentication required.' };
    }

    if (cls === RouteClass.OBSERVER) {
      if (this.insecureTest) return { ok: true };
      const raw = req.method === 'GET' ? '' : await readRawBody();
      const verdict = this.observer.verify(req, pathname + (rawSearch || ''), raw);
      return verdict.ok ? { ok: true } : { ok: false, status: 401, error: `Observer authentication failed: ${verdict.reason}` };
    }

    if (cls === RouteClass.ANDROID) {
      // Pairing: checked by the handler against a one-time owner-minted token.
      // Events / heartbeat: the handler enforces the per-device HMAC (mandatory).
      return { ok: true };
    }
    return { ok: false, status: 403, error: 'Forbidden' };
  }

  // -- Owner login --------------------------------------------------------------

  /** Password + TOTP login. Throttled per IP and per account. */
  login({ email, password, code }, req) {
    const ip = clientIp(req);
    const ipLimit = this.limiter.hit(`login:ip:${ip}`, 10, 15 * 60_000);
    const acctLimit = this.limiter.hit(`login:acct:${String(email || '').toLowerCase()}`, 5, 15 * 60_000);
    if (!ipLimit.allowed || !acctLimit.allowed) {
      return { ok: false, status: 429, error: 'Too many attempts. Try again later.', retryAfterSec: Math.max(ipLimit.retryAfterSec, acctLimit.retryAfterSec) };
    }
    const cfg = this.config;
    if (!cfg.ownerEmail || !cfg.passwordHash || !cfg.totpSecret) {
      return { ok: false, status: 401, error: 'Invalid credentials.' };
    }
    // Always evaluate every factor so response time does not reveal which failed.
    const emailOk = safeEqual(String(email || '').trim().toLowerCase(), cfg.ownerEmail);
    const passOk = verifyPassword(password, cfg.passwordHash);
    const step = verifyTotp(cfg.totpSecret, code, this.now());
    const stepFresh = step !== null && !this.usedTotpSteps.has(step);
    if (!(emailOk && passOk && stepFresh)) {
      return { ok: false, status: 401, error: 'Invalid credentials.' };
    }
    this.usedTotpSteps.set(step, this.now() + 120_000);
    for (const [s, exp] of this.usedTotpSteps) if (exp <= this.now()) this.usedTotpSteps.delete(s);
    this.limiter.reset(`login:acct:${cfg.ownerEmail}`);
    return { ok: true, session: this.sessions.create({ sub: cfg.ownerEmail, email: cfg.ownerEmail, method: 'password+totp' }) };
  }

  /**
   * Single sign-on from the Oneleven admin: verifies a Supabase access token
   * by asking Supabase itself, then requires the user to be an allow-listed
   * owner who signed in with a second factor (aal2).
   */
  async sso(accessToken, req, fetchImpl = fetch) {
    const ip = clientIp(req);
    const lim = this.limiter.hit(`sso:ip:${ip}`, 20, 15 * 60_000);
    if (!lim.allowed) return { ok: false, status: 429, error: 'Too many attempts. Try again later.' };
    const cfg = this.config;
    if (!cfg.supabaseUrl || !cfg.ssoUserIds.length || !cfg.supabaseAnonKey) {
      return { ok: false, status: 401, error: 'SSO is not configured.' };
    }
    if (typeof accessToken !== 'string' || accessToken.split('.').length !== 3) {
      return { ok: false, status: 401, error: 'Invalid token.' };
    }
    let user;
    try {
      const res = await fetchImpl(`${cfg.supabaseUrl}/auth/v1/user`, {
        headers: { Authorization: `Bearer ${accessToken}`, apikey: cfg.supabaseAnonKey },
        signal: AbortSignal.timeout(8000)
      });
      if (!res.ok) return { ok: false, status: 401, error: 'Invalid token.' };
      user = await res.json();
    } catch {
      return { ok: false, status: 502, error: 'Could not verify token.' };
    }
    if (!user?.id || !cfg.ssoUserIds.includes(user.id)) {
      return { ok: false, status: 403, error: 'Not an authorized owner.' };
    }
    // The Supabase session's assurance level is carried in the JWT payload.
    let aal = 'aal1';
    try {
      aal = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64url').toString('utf8')).aal || 'aal1';
    } catch { /* treated as aal1 */ }
    if (aal !== 'aal2') return { ok: false, status: 403, error: 'Second factor (2FA) required.' };
    return { ok: true, session: this.sessions.create({ sub: user.id, email: user.email, method: 'sso' }) };
  }
}

export { hashPassword, randomToken };
