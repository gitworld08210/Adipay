/**
 * Small in-memory sliding-window limiter. Good enough for a single instance;
 * it stops password / OTP guessing and WhatsApp-OTP spam.
 */
export class RateLimiter {
  constructor({ now = () => Date.now() } = {}) {
    this.now = now;
    this.hits = new Map(); // key -> number[]
  }

  /**
   * Records a hit and reports whether it is allowed.
   * @returns {{ allowed: boolean, retryAfterSec: number }}
   */
  hit(key, limit, windowMs) {
    const now = this.now();
    const fresh = (this.hits.get(key) || []).filter(t => now - t < windowMs);
    if (fresh.length >= limit) {
      this.hits.set(key, fresh);
      return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((windowMs - (now - fresh[0])) / 1000)) };
    }
    fresh.push(now);
    this.hits.set(key, fresh);
    if (this.hits.size > 5000) this.sweep(windowMs);
    return { allowed: true, retryAfterSec: 0 };
  }

  reset(key) {
    this.hits.delete(key);
  }

  sweep(windowMs) {
    const now = this.now();
    for (const [k, arr] of this.hits) {
      if (!arr.some(t => now - t < windowMs)) this.hits.delete(k);
    }
  }
}

export function clientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.socket?.remoteAddress || 'unknown';
}
