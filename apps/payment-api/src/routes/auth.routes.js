import { HttpServer } from '../server.js';

/**
 * Owner authentication endpoints. These are the only admin-related routes
 * that are reachable without a session (they ARE the way to get one).
 *
 *   POST /api/v1/auth/login   { email, password, code }   password + TOTP
 *   POST /api/v1/auth/sso     { accessToken }              Oneleven admin (Supabase, 2FA)
 *   POST /api/v1/auth/logout
 *   GET  /api/v1/auth/me
 */
export function registerAuthRoutes(server, ctx) {
  const { security } = ctx;

  function setSession(res, sessionValue, extra = {}) {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': security.sessions.cookieHeader(sessionValue, { secure: security.secureCookies() }),
      'Cache-Control': 'no-store'
    });
    res.end(JSON.stringify({ authenticated: true, ...extra }));
  }

  function fail(res, result) {
    const headers = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
    if (result.retryAfterSec) headers['Retry-After'] = String(result.retryAfterSec);
    res.writeHead(result.status, headers);
    res.end(JSON.stringify({ authenticated: false, error: result.error }));
  }

  server.post('/api/v1/auth/login', async (req, res) => {
    const body = await HttpServer.parseBody(req).catch(() => ({}));
    const result = security.login({ email: body.email, password: body.password, code: body.code }, req);
    if (!result.ok) return fail(res, result);
    const session = security.sessions.verify(result.session);
    setSession(res, result.session, { method: session?.method });
  });

  server.post('/api/v1/auth/sso', async (req, res) => {
    const body = await HttpServer.parseBody(req).catch(() => ({}));
    const result = await security.sso(body.accessToken, req, security.fetchImpl);
    if (!result.ok) return fail(res, result);
    const session = security.sessions.verify(result.session);
    setSession(res, result.session, { method: session?.method });
  });

  server.post('/api/v1/auth/logout', async (req, res) => {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': security.sessions.clearCookieHeader({ secure: security.secureCookies() }),
      'Cache-Control': 'no-store'
    });
    res.end(JSON.stringify({ authenticated: false }));
  });

  server.get('/api/v1/auth/me', async (req, res) => {
    const session = security.ownerSession(req);
    HttpServer.json(res, 200, session
      ? { authenticated: true, email: session.email || null, method: session.method }
      : { authenticated: false });
  });
}
