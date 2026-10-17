import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TEMPLATE = path.resolve(__dirname, '../../../merchant-admin/src/views/admin.html');

const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: blob: https:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'"
].join('; ');

function htmlHeaders() {
  return {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': CSP,
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer'
  };
}

// Injected into the dashboard: any API call answered with 401 sends the owner
// back to the sign-in page, and a floating button signs out.
const SESSION_GUARD = `
<script>
(function () {
  var realFetch = window.fetch.bind(window);
  window.fetch = function () {
    return realFetch.apply(null, arguments).then(function (res) {
      if (res.status === 401 && String(arguments[0] || '').indexOf('/api/v1/auth/') === -1) {
        window.location.href = '/admin/login';
      }
      return res;
    });
  };
  document.addEventListener('DOMContentLoaded', function () {
    var b = document.createElement('button');
    b.textContent = 'Sign out';
    b.setAttribute('style', 'position:fixed;right:14px;bottom:14px;z-index:99999;padding:8px 14px;border-radius:999px;border:1px solid #cbd5e1;background:#fff;color:#0f172a;font:600 13px system-ui;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.12)');
    b.onclick = function () { realFetch('/api/v1/auth/logout', { method: 'POST' }).then(function () { window.location.href = '/admin/login'; }); };
    document.body.appendChild(b);
  });
})();
</script>`;

const PAGE_STYLE = `
  *{box-sizing:border-box} body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f7f9;font:16px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1d1d1f}
  main{width:min(92vw,400px);background:#fff;border-radius:24px;padding:28px;box-shadow:0 1px 2px rgba(16,24,40,.04),0 4px 16px rgba(16,24,40,.06)}
  h1{margin:0 0 4px;font-size:22px} p.sub{margin:0 0 20px;color:#6a6d78;font-size:14px}
  label{display:block;font-size:13px;font-weight:600;margin:14px 0 6px}
  input{width:100%;padding:12px 14px;border:1px solid #e6e7ec;border-radius:14px;font:inherit;background:#eef0f4}
  input:focus{outline:2px solid #1f6bff;background:#fff}
  button{width:100%;margin-top:20px;padding:13px;border:0;border-radius:999px;background:#1f6bff;color:#fff;font:600 15px system-ui;cursor:pointer}
  button:disabled{opacity:.5} .err{margin-top:14px;color:#dc2626;font-size:14px;min-height:20px}
`;

const LOGIN_PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Adipay - Owner sign in</title><meta name="robots" content="noindex"><style>${PAGE_STYLE}</style></head><body><main>
<h1>Owner sign in</h1><p class="sub">Adipay payments. Owner access only.</p>
<form id="f" autocomplete="off">
<label for="email">Email</label><input id="email" type="email" required autocomplete="username">
<label for="password">Password</label><input id="password" type="password" required autocomplete="current-password">
<label for="code">2FA code</label><input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code" placeholder="6 digits">
<button id="go" type="submit">Sign in</button><div id="err" class="err" role="alert"></div></form>
<script>
document.getElementById('f').addEventListener('submit', async function (e) {
  e.preventDefault();
  var go = document.getElementById('go'), err = document.getElementById('err');
  go.disabled = true; err.textContent = '';
  try {
    var res = await fetch('/api/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.value, password: password.value, code: code.value }) });
    var body = await res.json().catch(function () { return {}; });
    if (res.ok) { window.location.href = '/admin'; return; }
    err.textContent = body.error || 'Sign in failed.';
  } catch (x) { err.textContent = 'Network error. Try again.'; }
  go.disabled = false;
});
</script></main></body></html>`;

const SSO_PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Adipay - Signing in</title><meta name="robots" content="noindex"><meta name="referrer" content="no-referrer"><style>${PAGE_STYLE}</style></head><body><main>
<h1>Signing you in...</h1><p class="sub" id="msg">Verifying your Oneleven admin session.</p><div id="err" class="err" role="alert"></div>
<script>
(async function () {
  var token = new URLSearchParams(window.location.hash.slice(1)).get('t');
  history.replaceState(null, '', window.location.pathname);   // remove the token from the URL right away
  if (!token) { location.replace('/admin/login'); return; }
  try {
    var res = await fetch('/api/v1/auth/sso', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ accessToken: token }) });
    var body = await res.json().catch(function () { return {}; });
    if (res.ok) { location.replace('/admin'); return; }
    document.getElementById('msg').textContent = 'Could not sign you in.';
    document.getElementById('err').textContent = (body.error || 'Unknown error') + ' You can sign in with your password instead.';
    setTimeout(function () { location.replace('/admin/login'); }, 2500);
  } catch (x) { document.getElementById('err').textContent = 'Network error.'; }
})();
</script></main></body></html>`;

/**
 * Serves the payments admin dashboard from the SAME service as the API, so one
 * Render service + one database back everything. The dashboard itself is
 * unchanged HTML; only a sign-in gate and a sign-out button are added.
 *
 *   GET /admin         dashboard (redirects to /admin/login without a session)
 *   GET /admin/login   email + password + 2FA
 *   GET /admin/sso     landing page for "Payments" clicked inside Oneleven admin
 */
export function registerAdminUiRoutes(server, ctx) {
  const { security } = ctx;

  function redirect(res, location) {
    res.writeHead(302, { Location: location, 'Cache-Control': 'no-store' });
    res.end();
  }

  function render() {
    const template = fs.readFileSync(TEMPLATE, 'utf8');
    const html = template.replaceAll('{{API_BASE_URL}}', '');
    return html.includes('</body>') ? html.replace('</body>', `${SESSION_GUARD}</body>`) : html + SESSION_GUARD;
  }

  server.get('/admin/login', async (req, res) => {
    if (security.ownerSession(req)) return redirect(res, '/admin');
    res.writeHead(200, htmlHeaders());
    res.end(LOGIN_PAGE);
  });

  server.get('/admin/sso', async (req, res) => {
    res.writeHead(200, htmlHeaders());
    res.end(SSO_PAGE);
  });

  server.get('/admin', async (req, res) => {
    if (!security.ownerSession(req)) return redirect(res, '/admin/login');
    res.writeHead(200, htmlHeaders());
    res.end(render());
  });
}
