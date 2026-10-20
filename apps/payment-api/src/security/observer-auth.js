import crypto from 'node:crypto';
import { safeEqual } from './crypto.js';

export const OBSERVER_TS_HEADER = 'x-observer-timestamp';
export const OBSERVER_SIG_HEADER = 'x-observer-signature';

function message(ts, method, pathWithQuery, body) {
  return `${ts}.${String(method).toUpperCase()}.${pathWithQuery}.${body || ''}`;
}

/**
 * Headers an observer (Gmail / SMS / SDK) must send. The signature covers the
 * timestamp, method, path+query and raw body, so a captured request cannot be
 * replayed against another path or with another body.
 */
export function signObserverRequest({ secret, method, path, body = '', now = Date.now() }) {
  const ts = String(now);
  const sig = crypto.createHmac('sha256', secret).update(message(ts, method, path, body)).digest('hex');
  return { 'X-Observer-Timestamp': ts, 'X-Observer-Signature': `sha256=${sig}` };
}

/**
 * Verifies an observer-signed request. Rejects clock drift > maxDriftMs and
 * exact replays (same signature seen again inside the window).
 */
export class ObserverVerifier {
  constructor({ secret, maxDriftMs = 60_000, now = () => Date.now() }) {
    this.secret = secret;
    this.maxDriftMs = maxDriftMs;
    this.now = now;
    this.seen = new Map(); // signature -> expiry
  }

  /** @returns {{ ok: true } | { ok: false, reason: string }} */
  verify(req, pathWithQuery, rawBody) {
    if (!this.secret) return { ok: false, reason: 'OBSERVER_AUTH_NOT_CONFIGURED' };
    const ts = req.headers[OBSERVER_TS_HEADER];
    const sigHeader = String(req.headers[OBSERVER_SIG_HEADER] || '');
    if (!ts || !sigHeader) return { ok: false, reason: 'MISSING_SIGNATURE' };

    const t = Number(ts);
    if (!Number.isFinite(t) || Math.abs(this.now() - t) > this.maxDriftMs) {
      return { ok: false, reason: 'TIMESTAMP_DRIFT' };
    }
    const expected = `sha256=${crypto.createHmac('sha256', this.secret)
      .update(message(ts, req.method, pathWithQuery, rawBody)).digest('hex')}`;
    if (!safeEqual(expected, sigHeader)) return { ok: false, reason: 'BAD_SIGNATURE' };

    this.prune();
    if (this.seen.has(sigHeader)) return { ok: false, reason: 'REPLAY' };
    this.seen.set(sigHeader, this.now() + this.maxDriftMs * 2);
    return { ok: true };
  }

  prune() {
    const now = this.now();
    for (const [k, exp] of this.seen) if (exp <= now) this.seen.delete(k);
  }
}
