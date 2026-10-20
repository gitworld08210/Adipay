import crypto from 'node:crypto';
import { b64url, safeEqual } from './crypto.js';

export const SESSION_COOKIE = 'adipay_admin';

/**
 * Stateless signed session cookie. The payload is signed (HMAC-SHA256) with
 * ADMIN_SESSION_SECRET, so sessions survive restarts and an ephemeral disk.
 * Revocation is by rotating the secret (logs everyone out).
 */
export class SessionManager {
  /**
   * @param {{ secret: string, ttlMs?: number, now?: () => number }} opts
   */
  constructor({ secret, ttlMs = 8 * 60 * 60 * 1000, now = () => Date.now() }) {
    this.secret = secret;
    this.ttlMs = ttlMs;
    this.now = now;
  }

  sign(payloadB64) {
    return crypto.createHmac('sha256', this.secret).update(payloadB64).digest('base64url');
  }

  /** @returns {string} cookie value */
  create({ sub, email, method }) {
    const iat = this.now();
    const payload = { sub, email, method, iat, exp: iat + this.ttlMs, jti: crypto.randomUUID() };
    const body = b64url(JSON.stringify(payload));
    return `${body}.${this.sign(body)}`;
  }

  /** @returns {{ sub: string, email?: string, method: string, exp: number } | null} */
  verify(value) {
    if (!this.secret || typeof value !== 'string') return null;
    const [body, sig] = value.split('.');
    if (!body || !sig || !safeEqual(this.sign(body), sig)) return null;
    try {
      const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
      if (!p || typeof p.exp !== 'number' || p.exp <= this.now()) return null;
      return p;
    } catch {
      return null;
    }
  }

  cookieHeader(value, { secure }) {
    const maxAge = Math.floor(this.ttlMs / 1000);
    return [
      `${SESSION_COOKIE}=${value}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${maxAge}`,
      ...(secure ? ['Secure'] : [])
    ].join('; ');
  }

  clearCookieHeader({ secure }) {
    return [`${SESSION_COOKIE}=`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0', ...(secure ? ['Secure'] : [])].join('; ');
  }
}

export function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
