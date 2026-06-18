/*
 * Terminal 1: cd auth-concepts/sso && npm install && npm run vulnerable
 * WorkHub (SP) + CorpID (IdP) — unvalidated redirect_uri (port 3064)
 */

const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const PORT = 3064;

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── SP (WorkHub) session store ─────────────────────────────────────────────
const sessions = new Map();

// ─── IdP (CorpID) session store — survives SP logout ────────────────────────
const idpSessions = new Map();

// ⚠️ VULNERABLE — weak IdP signing secret ('idp-secret'); predictable in real deployments.
// Same brute-force path as jwt-bearer: capture one assertion JWT, offline dictionary attack
// recovers the secret, attacker forges assertions for any user without ever seeing a password.
const IDP_SECRET = 'idp-secret';

// ⚠️ VULNERABLE — no redirect_uri allowlist; IdP accepts any callback URL.
// Attacker crafts: /idp/login?client_id=workhub-client-id&redirect_uri=http://attacker.com/steal
// Victim sees legitimate CorpID login, enters credentials, IdP redirects assertion token to attacker.
// Attacker logs into WorkHub as victim. Victim has no indication anything went wrong.
const REGISTERED_SPS = {
  workhub: { name: 'WorkHub', clientId: 'workhub-client-id' },
};

const IDP_USERS = [
  { id: 1, username: 'alice@corp.com', password: 'pass1234', name: 'Alice Chen', role: 'employee' },
  { id: 2, username: 'bob@corp.com', password: 'qwerty123', name: 'Bob Martinez', role: 'employee' },
  { id: 3, username: 'admin@corp.com', password: 'admin456', name: 'Admin User', role: 'admin' },
];

const PROJECTS = [
  { name: 'Q2 Platform Migration', status: 'On track', members: 8 },
  { name: 'Customer Portal Redesign', status: 'At risk', members: 5 },
  { name: 'API Gateway v3', status: 'Planning', members: 3 },
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

function requireWhSession(req, res, next) {
  const session = getWhSession(req);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.whSession = session;
  next();
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
  // ⚠️ VULNERABLE — redirect to whatever redirect_uri was provided; no allowlist check.
  // Assertion JWT lands on attacker's server via query string — visible in logs, history, Referer.
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
    redirectUri: redirectUri, // ⚠️ VULNERABLE — passed through without validation against allowlist.
    // Attacker supplies redirect_uri=http://attacker.com/steal in query string; IdP renders it in the form
    // and POST /idp/authenticate redirects the signed assertion JWT to that host after victim logs in.
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
  // ⚠️ VULNERABLE — WorkHub sends its own callback URI, but IdP never verifies it matches registration.
  // An attacker can substitute any redirect_uri in the authorize URL and receive the assertion instead.
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

// GET /dashboard — WorkHub SPA (session data via /api/me + /api/projects)
app.get('/dashboard', function (req, res) {
  const session = getWhSession(req);
  if (!session) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/config', function (_req, res) {
  res.json({ mode: 'vulnerable', port: PORT });
});

app.get('/api/me', requireWhSession, function (req, res) {
  res.json({
    name: req.whSession.name,
    email: req.whSession.email,
    role: req.whSession.role,
  });
});

app.get('/api/projects', requireWhSession, function (_req, res) {
  res.json(PROJECTS);
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
