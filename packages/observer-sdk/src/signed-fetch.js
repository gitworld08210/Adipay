import crypto from 'node:crypto';

/**
 * Headers for an observer-signed request. Must match the server's
 * ObserverVerifier: HMAC-SHA256 over `${ts}.${METHOD}.${path+query}.${body}`.
 */
export function observerHeaders({ secret, method, url, body = '', now = Date.now() }) {
  const u = new URL(url);
  const ts = String(now);
  const sig = crypto.createHmac('sha256', secret)
    .update(`${ts}.${String(method).toUpperCase()}.${u.pathname}${u.search}.${body}`)
    .digest('hex');
  return { 'X-Observer-Timestamp': ts, 'X-Observer-Signature': `sha256=${sig}` };
}

/**
 * fetch() that signs the request with OBSERVER_INGEST_SECRET when it is set.
 * Without the secret it behaves like plain fetch (works against a local
 * gateway that has no secret configured; a hardened gateway will answer 401).
 */
export function signedFetch(url, init = {}, secret = process.env.OBSERVER_INGEST_SECRET) {
  if (!secret) return fetch(url, init);
  const method = init.method || 'GET';
  const body = typeof init.body === 'string' ? init.body : '';
  return fetch(url, {
    ...init,
    headers: { ...(init.headers || {}), ...observerHeaders({ secret, method, url, body }) }
  });
}
