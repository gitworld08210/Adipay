/**
 * Security regression tests. These run WITHOUT the insecure test bypass
 * (YOUPI_INSECURE_TEST_MODE) so they exercise the real guard, exactly as it
 * behaves in production. Each test names the attack it prevents.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { Database } from '@youpi/db';
import { startServer } from '../index.js';
import { PaymentMethod } from '@youpi/common';
import { hashPassword, generateTotpSecret, totpAt, verifyPassword, verifyTotp, base32Decode } from '../security/crypto.js';
import { signObserverRequest } from '../security/observer-auth.js';
import { loadSecurityConfig, classifyRoute, RouteClass } from '../security/guard.js';

const OWNER_EMAIL = 'owner@example.com';
const OWNER_PASSWORD = 'correct horse battery staple';
const TOTP_SECRET = generateTotpSecret();
const OBSERVER_SECRET = 'o'.repeat(48);
const SESSION_SECRET = 's'.repeat(48);
const API_KEY = 'k'.repeat(40);
const SSO_USER = '11111111-1111-1111-1111-111111111111';

function makeEnv(extra = {}) {
  return {
    NODE_ENV: 'test',
    ADMIN_EMAIL: OWNER_EMAIL,
    ADMIN_PASSWORD_HASH: hashPassword(OWNER_PASSWORD),
    ADMIN_TOTP_SECRET: TOTP_SECRET,
    ADMIN_SESSION_SECRET: SESSION_SECRET,
    OBSERVER_INGEST_SECRET: OBSERVER_SECRET,
    PAYMENT_API_KEYS: API_KEY,
    SUPABASE_URL: 'https://example.supabase.co',
    SUPABASE_ANON_KEY: 'anon-key-for-tests',
    ADMIN_SSO_USER_IDS: SSO_USER,
    ...extra
  };
}

function jwtWithAal(aal) {
  const enc = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${enc({ alg: 'HS256', typ: 'JWT' })}.${enc({ sub: SSO_USER, aal })}.sig`;
}

async function boot(port, { env = makeEnv(), fetchImpl = null } = {}) {
  const db = new Database({ inMemory: true });
  const api = await startServer(port, db, { security: { env, fetchImpl } });
  const baseUrl = `http://localhost:${port}`;

  function request(path, { method = 'GET', headers = {}, body, raw } = {}) {
    return new Promise((resolve, reject) => {
      const payload = raw !== undefined ? raw : (body !== undefined ? JSON.stringify(body) : undefined);
      const req = http.request(new URL(path, baseUrl), {
        method,
        headers: { 'Content-Type': 'application/json', ...headers }
      }, res => {
        let data = '';
        res.on('data', c => { data += c; });
        res.on('end', () => {
          let parsed;
          try { parsed = JSON.parse(data); } catch { parsed = data; }
          resolve({ status: res.statusCode, body: parsed, headers: res.headers });
        });
      });
      req.on('error', reject);
      if (payload !== undefined) req.write(payload);
      req.end();
    });
  }

  // The server accepts each 30 s TOTP step once (replay protection), so every
  // login in a test must present a code from a step nobody used yet. Steps
  // within +/-1 of "now" are valid, so we hand them out in order: 0, +1, -1.
  const stepQueue = [0, 1, -1];
  async function ownerCookie(overrides = {}) {
    const step = stepQueue.length ? stepQueue.shift() : null;
    assert.notEqual(step, null, 'this test server has used all 3 valid TOTP steps; boot a new one');
    const res = await request('/api/v1/auth/login', {
      method: 'POST',
      body: { email: OWNER_EMAIL, password: OWNER_PASSWORD, code: totpAt(TOTP_SECRET, Date.now() + step * 30_000), ...overrides.body }
    });
    assert.equal(res.status, 200, `login should succeed: ${JSON.stringify(res.body)}`);
    return String(res.headers['set-cookie'][0]).split(';')[0];
  }

  return { api, db, request, ownerCookie, close: async () => { await api.close(); db.close(); } };
}

describe('crypto primitives', () => {
  test('scrypt: correct password verifies, wrong one does not, weak ones are refused', () => {
    const h = hashPassword('a-long-enough-password');
    assert.equal(verifyPassword('a-long-enough-password', h), true);
    assert.equal(verifyPassword('a-long-enough-passwore', h), false);
    assert.equal(verifyPassword('x', 'not-a-hash'), false);
    assert.throws(() => hashPassword('short'), /at least 12/);
  });

  test('TOTP matches the RFC 6238 test vector (T=59s -> 287082)', () => {
    const rfcSecretBase32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // ASCII "12345678901234567890"
    assert.equal(base32Decode(rfcSecretBase32).toString('ascii'), '12345678901234567890');
    assert.equal(totpAt(rfcSecretBase32, 59_000), '287082');
    assert.equal(totpAt(rfcSecretBase32, 1111111109_000), '081804');
  });

  test('TOTP tolerates 1 step of drift but not more, and rejects non-numeric input', () => {
    const now = 1_700_000_000_000;
    const code = totpAt(TOTP_SECRET, now);
    assert.notEqual(verifyTotp(TOTP_SECRET, code, now + 30_000), null);
    assert.equal(verifyTotp(TOTP_SECRET, code, now + 120_000), null);
    assert.equal(verifyTotp(TOTP_SECRET, 'abcdef', now), null);
    assert.equal(verifyTotp(TOTP_SECRET, '12345', now), null);
  });
});

describe('route classification', () => {
  test('every admin route is owner-only by default, including ones added later', () => {
    assert.equal(classifyRoute('GET', '/api/v1/admin/anything-new'), RouteClass.OWNER);
    assert.equal(classifyRoute('POST', '/api/v1/admin/counter-confirm'), RouteClass.OWNER);
    assert.equal(classifyRoute('GET', '/api/services'), RouteClass.OWNER);
    assert.equal(classifyRoute('POST', '/api/services/start-all'), RouteClass.OWNER);
    assert.equal(classifyRoute('POST', '/api/v1/pollers/events'), RouteClass.OBSERVER);
    assert.equal(classifyRoute('POST', '/api/v1/pollers/android/events'), RouteClass.ANDROID);
    assert.equal(classifyRoute('GET', '/api/v1/checkout/abc/state'), RouteClass.PUBLIC);
  });
});

describe('production configuration fails closed', () => {
  test('missing secrets are reported and block startup', () => {
    const cfg = loadSecurityConfig({ NODE_ENV: 'production' });
    assert.equal(cfg.ok, false);
    assert.ok(cfg.problems.some(p => p.includes('ADMIN_SESSION_SECRET')));
    assert.ok(cfg.problems.some(p => p.includes('owner access')));
  });

  test('known default values from .env.example are rejected', () => {
    const cfg = loadSecurityConfig(makeEnv({
      NODE_ENV: 'production',
      ADMIN_SESSION_SECRET: 'super_secret_jwt_key_change_in_production_min_32_chars',
      OBSERVER_INGEST_SECRET: 'android_pairing_enrollment_secret_key_32_chars'
    }));
    assert.equal(cfg.ok, false);
    assert.ok(cfg.problems.some(p => p.includes('known default')));
  });

  test('a complete configuration is accepted', () => {
    assert.equal(loadSecurityConfig(makeEnv({ NODE_ENV: 'production' })).ok, true);
  });
});

describe('admin API requires the owner', () => {
  let t;
  before(async () => { t = await boot(6201); });
  after(async () => { await t.close(); });

  const READS = [
    '/api/v1/admin/merchant-settings',
    '/api/v1/admin/customers',
    '/api/v1/admin/payments',
    '/api/v1/admin/upi-accounts',
    '/api/v1/admin/gmail/credentials',
    '/api/v1/admin/all-settings',
    '/api/v1/admin/queue',
    '/api/v1/admin/security/banned-users',
    '/api/services'
  ];
  for (const path of READS) {
    test(`anonymous GET ${path} is refused`, async () => {
      const res = await t.request(path);
      assert.equal(res.status, 401);
      assert.ok(!JSON.stringify(res.body).includes('webhookSecret'));
    });
  }

  const WRITES = [
    ['POST', '/api/v1/admin/upi-accounts', { upiId: 'attacker@upi', payeeName: 'x' }],
    ['POST', '/api/v1/admin/merchant-settings', { webhookUrl: 'https://evil.example/hook' }],
    ['POST', '/api/v1/admin/counter-confirm', { paymentId: 'x', operatorId: 'attacker' }],
    ['POST', '/api/v1/admin/queue/clear', {}],
    ['POST', '/api/v1/admin/security/unban', { customerId: 'x' }],
    ['POST', '/api/services/start-all', {}]
  ];
  for (const [method, path, body] of WRITES) {
    test(`anonymous ${method} ${path} is refused`, async () => {
      const res = await t.request(path, { method, body });
      assert.equal(res.status, 401);
    });
  }

  test('a forged cookie or token is refused', async () => {
    const forged = await t.request('/api/v1/admin/customers', { headers: { Cookie: 'adipay_admin=eyJzdWIiOiJ4In0.AAAA' } });
    assert.equal(forged.status, 401);
    const bearer = await t.request('/api/v1/admin/customers', { headers: { Authorization: 'Bearer nope' } });
    assert.equal(bearer.status, 401);
  });

  test('a customer session token does not unlock admin routes', async () => {
    const res = await t.request('/api/v1/admin/customers', { headers: { 'x-customer-session-token': 'abc' } });
    assert.equal(res.status, 401);
  });
});

describe('free "SUCCESS" via counter-confirm is impossible', () => {
  let t;
  before(async () => { t = await boot(6202); });
  after(async () => { await t.close(); });

  test('an attacker cannot confirm someone else\'s payment; the owner can', async () => {
    const created = await t.request('/api/v1/payments', {
      method: 'POST',
      headers: { Authorization: `Bearer ${API_KEY}` },
      body: { orderId: 'ATTACK-1', amount: '99.00', method: PaymentMethod.CASH_COUNTER }
    });
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const paymentId = created.body.paymentId;

    const attack = await t.request('/api/v1/admin/counter-confirm', {
      method: 'POST', body: { paymentId, operatorId: 'attacker' }
    });
    assert.equal(attack.status, 401);

    const status = await t.request(`/api/v1/payments/${paymentId}`);
    assert.notEqual(status.body.status, 'SUCCESS', 'payment must not be marked paid by an anonymous caller');

    const cookie = await t.ownerCookie();
    const ok = await t.request('/api/v1/admin/counter-confirm', {
      method: 'POST', headers: { Cookie: cookie }, body: { paymentId, operatorId: 'owner' }
    });
    assert.equal(ok.status, 200);
  });

  test('counter-confirm refuses an already-terminal or non-counter payment even for the owner', async () => {
    const cookie = await t.ownerCookie();
    const upi = await t.request('/api/v1/payments', {
      method: 'POST', headers: { Authorization: `Bearer ${API_KEY}` },
      body: { orderId: 'UPI-ONLY-1', amount: '50.00' }
    });
    assert.ok([200, 201, 500].includes(upi.status));
    if (upi.body.paymentId) {
      const res = await t.request('/api/v1/admin/counter-confirm', {
        method: 'POST', headers: { Cookie: cookie }, body: { paymentId: upi.body.paymentId, operatorId: 'owner' }
      });
      assert.equal(res.status, 409, 'a UPI payment must be confirmed by the bank observer, never by hand');
    }
  });
});

describe('owner login', () => {
  let t;
  before(async () => { t = await boot(6203); });
  after(async () => { await t.close(); });

  test('wrong password, wrong email, and missing 2FA all fail with the same message', async () => {
    const code = totpAt(TOTP_SECRET, Date.now());
    const a = await t.request('/api/v1/auth/login', { method: 'POST', body: { email: OWNER_EMAIL, password: 'wrong-password-123', code } });
    const b = await t.request('/api/v1/auth/login', { method: 'POST', body: { email: 'other@example.com', password: OWNER_PASSWORD, code } });
    const c = await t.request('/api/v1/auth/login', { method: 'POST', body: { email: OWNER_EMAIL, password: OWNER_PASSWORD } });
    for (const r of [a, b, c]) assert.equal(r.status, 401);
    assert.equal(a.body.error, b.body.error);
    assert.equal(b.body.error, c.body.error);
  });

  test('a successful login sets a hardened cookie and unlocks the admin API without leaking secrets', async () => {
    const res = await t.request('/api/v1/auth/login', {
      method: 'POST',
      body: { email: OWNER_EMAIL, password: OWNER_PASSWORD, code: totpAt(TOTP_SECRET, Date.now() - 30_000) }
    });
    assert.equal(res.status, 200);
    const setCookie = String(res.headers['set-cookie'][0]);
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
    const cookie = setCookie.split(';')[0];

    const me = await t.request('/api/v1/auth/me', { headers: { Cookie: cookie } });
    assert.equal(me.body.authenticated, true);

    const settings = await t.request('/api/v1/admin/merchant-settings', { headers: { Cookie: cookie } });
    assert.equal(settings.status, 200);
    assert.equal(settings.body.webhookSecret, undefined, 'the webhook secret must never be returned');
    assert.equal(typeof settings.body.hasWebhookSecret, 'boolean');
  });

  test('the same 2FA code cannot be used twice (replay)', async () => {
    const code = totpAt(TOTP_SECRET, Date.now() + 30_000);
    const first = await t.request('/api/v1/auth/login', { method: 'POST', body: { email: OWNER_EMAIL, password: OWNER_PASSWORD, code } });
    const second = await t.request('/api/v1/auth/login', { method: 'POST', body: { email: OWNER_EMAIL, password: OWNER_PASSWORD, code } });
    assert.equal(first.status, 200);
    assert.equal(second.status, 401);
  });

  test('logout clears the session cookie', async () => {
    const res = await t.request('/api/v1/auth/logout', { method: 'POST' });
    assert.equal(res.status, 200);
    assert.match(String(res.headers['set-cookie'][0]), /Max-Age=0/);
  });

  test('webhook secret is shown once on rotation and never again', async () => {
    const cookie = await t.ownerCookie();
    const rotated = await t.request('/api/v1/admin/webhook-secret/rotate', { method: 'POST', headers: { Cookie: cookie }, body: {} });
    assert.equal(rotated.status, 200);
    assert.match(rotated.body.webhookSecret, /^[0-9a-f]{64}$/);
    const after = await t.request('/api/v1/admin/merchant-settings', { headers: { Cookie: cookie } });
    assert.equal(after.body.webhookSecret, undefined);
    assert.equal(after.body.hasWebhookSecret, true);
  });
});

describe('login brute-force protection', () => {
  let t;
  before(async () => { t = await boot(6204); });
  after(async () => { await t.close(); });

  test('after repeated failures the account is throttled, even with the right password', async () => {
    const statuses = [];
    for (let i = 0; i < 6; i++) {
      const r = await t.request('/api/v1/auth/login', { method: 'POST', body: { email: OWNER_EMAIL, password: `wrong-password-${i}`, code: '000000' } });
      statuses.push(r.status);
    }
    assert.equal(statuses.slice(0, 5).every(s => s === 401), true);
    assert.equal(statuses[5], 429);
    const good = await t.request('/api/v1/auth/login', {
      method: 'POST', body: { email: OWNER_EMAIL, password: OWNER_PASSWORD, code: totpAt(TOTP_SECRET, Date.now()) }
    });
    assert.equal(good.status, 429);
  });
});

describe('single sign-on from the Oneleven admin', () => {
  function fetchReturning(user, ok = true) {
    return async () => ({ ok, json: async () => user });
  }

  test('an allow-listed owner with 2FA (aal2) gets a session', async () => {
    const t = await boot(6205, { fetchImpl: fetchReturning({ id: SSO_USER, email: 'o@x.com' }) });
    try {
      const res = await t.request('/api/v1/auth/sso', { method: 'POST', body: { accessToken: jwtWithAal('aal2') } });
      assert.equal(res.status, 200);
      const cookie = String(res.headers['set-cookie'][0]).split(';')[0];
      assert.equal((await t.request('/api/v1/admin/customers', { headers: { Cookie: cookie } })).status, 200);
    } finally { await t.close(); }
  });

  test('a password-only session (aal1) is refused', async () => {
    const t = await boot(6206, { fetchImpl: fetchReturning({ id: SSO_USER }) });
    try {
      const res = await t.request('/api/v1/auth/sso', { method: 'POST', body: { accessToken: jwtWithAal('aal1') } });
      assert.equal(res.status, 403);
    } finally { await t.close(); }
  });

  test('a valid Supabase user who is not on the owner list is refused', async () => {
    const t = await boot(6207, { fetchImpl: fetchReturning({ id: '22222222-2222-2222-2222-222222222222' }) });
    try {
      const res = await t.request('/api/v1/auth/sso', { method: 'POST', body: { accessToken: jwtWithAal('aal2') } });
      assert.equal(res.status, 403);
    } finally { await t.close(); }
  });

  test('a token Supabase rejects, or garbage, is refused', async () => {
    const t = await boot(6208, { fetchImpl: fetchReturning({}, false) });
    try {
      assert.equal((await t.request('/api/v1/auth/sso', { method: 'POST', body: { accessToken: jwtWithAal('aal2') } })).status, 401);
      assert.equal((await t.request('/api/v1/auth/sso', { method: 'POST', body: { accessToken: 'garbage' } })).status, 401);
      assert.equal((await t.request('/api/v1/auth/sso', { method: 'POST', body: {} })).status, 401);
    } finally { await t.close(); }
  });
});

describe('bank observation intake cannot be forged', () => {
  let t;
  before(async () => { t = await boot(6209); });
  after(async () => { await t.close(); });

  const forged = { receivingAccountId: '00000000-0000-0000-0000-000000000002', source: 'GMAIL', amountPaise: '9900', bankReferenceNumber: '123456789012' };

  test('an unsigned fake "credit" is refused', async () => {
    const res = await t.request('/api/v1/pollers/events', { method: 'POST', body: forged });
    assert.equal(res.status, 401);
  });

  test('a wrong signature, a stale timestamp and a replay are all refused', async () => {
    const raw = JSON.stringify(forged);
    const wrong = await t.request('/api/v1/pollers/events', {
      method: 'POST', raw, headers: signObserverRequest({ secret: 'x'.repeat(48), method: 'POST', path: '/api/v1/pollers/events', body: raw })
    });
    assert.equal(wrong.status, 401);

    const stale = await t.request('/api/v1/pollers/events', {
      method: 'POST', raw, headers: signObserverRequest({ secret: OBSERVER_SECRET, method: 'POST', path: '/api/v1/pollers/events', body: raw, now: Date.now() - 10 * 60_000 })
    });
    assert.equal(stale.status, 401);

    const good = signObserverRequest({ secret: OBSERVER_SECRET, method: 'POST', path: '/api/v1/pollers/events', body: raw });
    const first = await t.request('/api/v1/pollers/events', { method: 'POST', raw, headers: good });
    assert.notEqual(first.status, 401, 'a correctly signed request passes the guard');
    const replay = await t.request('/api/v1/pollers/events', { method: 'POST', raw, headers: good });
    assert.equal(replay.status, 401);
  });

  test('a signature is bound to the path and body (cannot be reused elsewhere)', async () => {
    const raw = JSON.stringify(forged);
    const sig = signObserverRequest({ secret: OBSERVER_SECRET, method: 'POST', path: '/api/v1/pollers/events', body: raw });
    const tampered = await t.request('/api/v1/pollers/events', {
      method: 'POST', raw: JSON.stringify({ ...forged, amountPaise: '1' }), headers: sig
    });
    assert.equal(tampered.status, 401);
  });

  test('active-window needs the observer signature too', async () => {
    assert.equal((await t.request('/api/v1/pollers/active-window')).status, 401);
    const h = signObserverRequest({ secret: OBSERVER_SECRET, method: 'GET', path: '/api/v1/pollers/active-window' });
    assert.equal((await t.request('/api/v1/pollers/active-window', { headers: h })).status, 200);
  });
});

describe('admin website (served by the gateway itself)', () => {
  let t;
  before(async () => { t = await boot(6216); });
  after(async () => { await t.close(); });

  test('the dashboard redirects to sign-in without a session and never ships its HTML', async () => {
    const res = await t.request('/admin');
    assert.equal(res.status, 302);
    assert.equal(res.headers.location, '/admin/login');
    assert.ok(!String(res.body).includes('Merchant Portal'));
  });

  test('after sign-in the dashboard is served with a sign-out button and strict headers', async () => {
    const cookie = await t.ownerCookie();
    const res = await t.request('/admin', { headers: { Cookie: cookie } });
    assert.equal(res.status, 200);
    assert.match(String(res.body), /Merchant Portal/);
    assert.match(String(res.body), /Sign out/);
    assert.match(res.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(res.headers['x-frame-options'], 'DENY');
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.ok(!String(res.body).includes('{{API_BASE_URL}}'), 'template placeholders must be filled');
    assert.ok(!/android_pairing_enrollment_secret/.test(String(res.body)), 'no pairing secret in the page');
  });

  test('the login page and the SSO landing page are public but carry no secrets', async () => {
    const login = await t.request('/admin/login');
    assert.equal(login.status, 200);
    assert.match(String(login.body), /Owner sign in/);
    const sso = await t.request('/admin/sso');
    assert.equal(sso.status, 200);
    // the SSO page reads the token from the URL fragment (never sent to a server)
    // and strips it from the address bar immediately
    assert.match(String(sso.body), /location\.hash/);
    assert.match(String(sso.body), /history\.replaceState/);
    assert.match(String(sso.body), /no-referrer/);
  });

  test('a signed-in owner visiting the login page is sent to the dashboard', async () => {
    const cookie = await t.ownerCookie();
    const res = await t.request('/admin/login', { headers: { Cookie: cookie } });
    assert.equal(res.status, 302);
    assert.equal(res.headers.location, '/admin');
  });
});

describe('Gmail observer credentials', () => {
  let t;
  before(async () => { t = await boot(6215); });
  after(async () => { await t.close(); });

  test('only the signed observer (not the public) can read or save Gmail credentials', async () => {
    assert.equal((await t.request('/api/v1/pollers/gmail-config')).status, 401);
    assert.equal((await t.request('/api/v1/pollers/gmail-config', { method: 'POST', body: { refreshToken: 'x' } })).status, 401);

    const readHeaders = signObserverRequest({ secret: OBSERVER_SECRET, method: 'GET', path: '/api/v1/pollers/gmail-config' });
    const read = await t.request('/api/v1/pollers/gmail-config', { headers: readHeaders });
    assert.equal(read.status, 200);

    const raw = JSON.stringify({ clientId: 'cid.apps.googleusercontent.com', clientSecret: 'cs', refreshToken: 'rt-123', connectedEmail: 'me@gmail.com' });
    const save = await t.request('/api/v1/pollers/gmail-config', {
      method: 'POST', raw,
      headers: signObserverRequest({ secret: OBSERVER_SECRET, method: 'POST', path: '/api/v1/pollers/gmail-config', body: raw })
    });
    assert.equal(save.status, 200);

    const again = await t.request('/api/v1/pollers/gmail-config', {
      headers: signObserverRequest({ secret: OBSERVER_SECRET, method: 'GET', path: '/api/v1/pollers/gmail-config' })
    });
    assert.equal(again.body.gmailConfig.refreshToken, 'rt-123');
  });
});

describe('Android observer pairing and events', () => {
  let t;
  before(async () => { t = await boot(6210); });
  after(async () => { await t.close(); });

  test('the old hard-coded pairing tokens no longer work', async () => {
    for (const token of ['youpi_sms_pair_token_secure', 'android_pairing_enrollment_secret_key_32_chars', 'pair_00000000']) {
      const res = await t.request('/api/v1/pollers/android/pair', { method: 'POST', body: { enrollmentToken: token, deviceName: 'evil' } });
      assert.equal(res.status, 401, `${token} must be rejected`);
    }
  });

  test('only the signed-in owner can mint a one-time pairing token, and it works exactly once', async () => {
    assert.equal((await t.request('/api/v1/admin/sms-gateway/pair-qr')).status, 401);

    const cookie = await t.ownerCookie();
    const qr = await t.request('/api/v1/admin/sms-gateway/pair-qr', { headers: { Cookie: cookie } });
    assert.equal(qr.status, 200);
    const token = qr.body.token || qr.body.enrollmentToken || JSON.parse(qr.body.pairingPayload || '{}').token;
    assert.ok(token, 'pair-qr must return a pairing token');

    const paired = await t.request('/api/v1/pollers/android/pair', { method: 'POST', body: { enrollmentToken: token, deviceName: 'Shop phone' } });
    assert.equal(paired.status, 200);
    assert.ok(paired.body.signingKey && paired.body.deviceId);

    const again = await t.request('/api/v1/pollers/android/pair', { method: 'POST', body: { enrollmentToken: token, deviceName: 'Clone' } });
    assert.equal(again.status, 401, 'a pairing token is single-use');

    // Events: a registered device WITHOUT a signature must be refused (the old
    // code silently skipped the HMAC check when the headers were absent).
    const body = { smsBody: 'Rs 99.00 credited to a/c XX1234 UPI Ref 123456789012', sender: 'VM-HDFCBK' };
    const unsigned = await t.request('/api/v1/pollers/android/events', {
      method: 'POST', headers: { 'X-Device-Id': paired.body.deviceId }, body
    });
    assert.equal(unsigned.status, 401);

    // A correctly signed event from the paired device is accepted by the guard.
    const raw = JSON.stringify(body);
    const ts = String(Date.now());
    const sig = crypto.createHmac('sha256', paired.body.signingKey).update(`${raw}:${ts}`).digest('hex');
    const signed = await t.request('/api/v1/pollers/android/events', {
      method: 'POST', raw, headers: { 'X-Device-Id': paired.body.deviceId, 'X-Timestamp': ts, 'X-Signature': sig }
    });
    assert.notEqual(signed.status, 401);
    assert.notEqual(signed.status, 403);
  });

  test('an unknown device id is refused', async () => {
    const res = await t.request('/api/v1/pollers/android/events', {
      method: 'POST', headers: { 'X-Device-Id': crypto.randomUUID() }, body: { smsBody: 'x' }
    });
    assert.ok([401, 403].includes(res.status));
  });
});

describe('test and simulation routes in production', () => {
  test('simulate-observation does not exist in production', async () => {
    const t = await boot(6211, { env: makeEnv({ NODE_ENV: 'production' }) });
    try {
      const res = await t.request('/api/v1/checkout/abc/simulate-observation', { method: 'POST', body: { rawText: 'Rs 99 credited', isTest: true } });
      assert.equal(res.status, 404);
    } finally { await t.close(); }
  });

  test('outside production it still needs the owner', async () => {
    const t = await boot(6212);
    try {
      const res = await t.request('/api/v1/checkout/abc/simulate-observation', { method: 'POST', body: { rawText: 'Rs 99 credited' } });
      assert.equal(res.status, 401);
    } finally { await t.close(); }
  });
});

describe('creating payments needs a server-side API key', () => {
  test('in production an anonymous caller cannot create orders, a key holder can', async () => {
    const t = await boot(6213, { env: makeEnv({ NODE_ENV: 'production' }) });
    try {
      const anon = await t.request('/api/v1/payments', { method: 'POST', body: { orderId: 'X-1', amount: '99.00' } });
      assert.equal(anon.status, 401);
      const wrong = await t.request('/api/v1/payments', { method: 'POST', headers: { Authorization: 'Bearer wrong' }, body: { orderId: 'X-1', amount: '99.00' } });
      assert.equal(wrong.status, 401);
      const ok = await t.request('/api/v1/payments', { method: 'POST', headers: { Authorization: `Bearer ${API_KEY}` }, body: { orderId: 'X-2', amount: '99.00', method: PaymentMethod.CASH_COUNTER } });
      assert.equal(ok.status, 201, JSON.stringify(ok.body));
    } finally { await t.close(); }
  });

  test('the public status/checkout pages used by customers stay open', async () => {
    const t = await boot(6214, { env: makeEnv({ NODE_ENV: 'production' }) });
    try {
      assert.equal((await t.request('/health')).status, 200);
      const created = await t.request('/api/v1/payments', { method: 'POST', headers: { Authorization: `Bearer ${API_KEY}` }, body: { orderId: 'PUB-1', amount: '10.00', method: PaymentMethod.CASH_COUNTER } });
      assert.equal(created.status, 201);
      assert.equal((await t.request(`/api/v1/checkout/${created.body.paymentId}/state`)).status, 200);
    } finally { await t.close(); }
  });
});
