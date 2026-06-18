/*
 * Terminal 3: cd auth-concepts/sso && npm run secure
 * WorkHub (SP) + CorpID (IdP) — redirect_uri allowlist + state validation (port 3066)
 */

const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = 3066;

app.use(cors({ origin: 'http://localhost:3065' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const sessions = new Map();
const idpSessions = new Map();
const pendingStates = new Set();

// ✅ PROTECTED — cryptographically strong IdP signing secret (512-bit CSPRNG).
// Assertion JWTs cannot be forged offline; attacker must compromise the server or steal a live token.
const IDP_SECRET = crypto.randomBytes(64).toString('hex');

// ✅ PROTECTED — explicit redirect_uri allowlist with exact string match only.
// No prefix matching, no wildcards. Unknown URI → 400 before login form is shown or credentials entered.
const ALLOWED_REDIRECT_URIS = {
  'workhub-client-id': [
    'http://localhost:3066/callback',
    'http://localhost:3064/callback', // cross-demo testing
  ],
};

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

function isRedirectAllowed(clientId, redirectUri) {
  const allowed = ALLOWED_REDIRECT_URIS[clientId] || [];
  return allowed.includes(redirectUri);
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
  // NOTE: token in URL is a demo simplification. Production uses authorization code flow:
  // IdP sends a short-lived code → SP exchanges it server-to-server for the actual token.
  // This prevents tokens from appearing in logs, history, and Referer headers.
  const redirectUrl = redirectUri + '?token=' + assertionToken + '&state=' + encodeURIComponent(state || '');
  console.log('[IdP] Redirecting to allowed URI: ' + redirectUrl);
  res.redirect(redirectUrl);
}

function IDP_LOGIN_HTML(opts) {
  const clientName = opts.clientName || 'Unknown App';
  const redirectUri = opts.redirectUri || '';
  const state = opts.state || '';
  const clientId = opts.clientId || 'workhub-client-id';
  const error = opts.error || '';
  const loggedOut = opts.loggedOut;

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
    .safe-banner {
      background: #052e16;
      border: 1px solid #16a34a;
      color: #4ade80;
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
      border: 1px solid #16a34a;
      color: #4ade80;
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
    <div class="safe-banner">✅ HARDENED: redirect_uri validated against exact allowlist before authentication. Attacker's redirect_uri → 400 Bad Request.</div>
    ${loggedOut ? '<div class="info-banner">ℹ You signed out of WorkHub. Your CorpID session may still be active — clicking sign-in again will log you in immediately without a password.</div>' : ''}
    <div class="redirect-uri">redirect_uri: ${escHtml(redirectUri)} ✓</div>
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
    <div class="footer">CorpID Identity Provider · port 3066/idp</div>
  </div>
</body>
</html>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// IdP routes — CorpID Identity Provider (hardened)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/idp/login', function (req, res) {
  const clientId = req.query.client_id;
  const redirectUri = req.query.redirect_uri;
  const state = req.query.state || '';
  const allowed = ALLOWED_REDIRECT_URIS[clientId] || [];

  // ✅ PROTECTED — reject unknown redirect_uri before showing login form or accepting credentials.
  // Checked at GET /idp/login: attacker cannot phish victims into authenticating to attacker.com.
  if (!allowed.includes(redirectUri)) {
    console.log('[IdP] SECURITY: rejected redirect_uri ' + redirectUri + ' for ' + clientId);
    return res.status(400).send(
      '<h1>Invalid redirect_uri</h1><p>' + redirectUri + ' is not registered for ' + clientId + '</p>'
    );
  }

  const idpUser = getIdpUser(req);
  if (idpUser) {
    console.log('[IdP] Existing CorpID session for ' + idpUser.username + ' — SSO, no password prompt');
    return redirectWithAssertion(res, idpUser, redirectUri, state);
  }

  res.send(IDP_LOGIN_HTML({
    clientName: 'WorkHub',
    redirectUri: redirectUri,
    state: state,
    clientId: clientId,
    error: req.query.error ? decodeURIComponent(String(req.query.error).replace(/\+/g, ' ')) : '',
    loggedOut: req.query.logged_out === '1',
  }));
});

app.post('/idp/authenticate', function (req, res) {
  const clientId = req.body.client_id;
  const redirectUri = req.body.redirect_uri;
  const state = req.body.state || '';
  const allowed = ALLOWED_REDIRECT_URIS[clientId] || [];

  // ✅ PROTECTED — exact allowlist match on POST /idp/authenticate as well.
  // Prevents bypass: attacker cannot submit a valid URI on GET then swap redirect_uri in POST body.
  if (!isRedirectAllowed(clientId, redirectUri)) {
    console.log('[IdP] SECURITY: rejected authenticate redirect_uri ' + redirectUri);
    return res.status(400).json({ error: 'redirect_uri not in allowlist', provided: redirectUri });
  }

  const user = IDP_USERS.find(function (u) {
    return u.username === req.body.username && u.password === req.body.password;
  });

  if (!user) {
    return res.redirect(
      '/idp/login?error=Invalid+credentials&client_id=' + encodeURIComponent(clientId) +
      '&redirect_uri=' + encodeURIComponent(redirectUri) + '&state=' + encodeURIComponent(state)
    );
  }

  const idpSid = crypto.randomBytes(32).toString('hex');
  idpSessions.set(idpSid, user.id);
  res.setHeader('Set-Cookie', 'corpid_session=' + idpSid + '; Path=/idp; SameSite=Lax; HttpOnly');

  redirectWithAssertion(res, user, redirectUri, state);
});

// Validation endpoint for guide live tester
app.get('/idp/validate-redirect', function (req, res) {
  const clientId = req.query.client_id;
  const redirectUri = req.query.redirect_uri;
  const allowed = ALLOWED_REDIRECT_URIS[clientId] || [];
  const ok = allowed.includes(redirectUri);
  res.json({
    allowed: ok,
    reason: ok ? 'Exact match found' : 'Not in registered allowlist for ' + clientId,
    allowedUris: allowed,
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SP routes — WorkHub Service Provider
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/', function (req, res) {
  if (getWhSession(req)) return res.redirect('/dashboard');

  const state = crypto.randomBytes(16).toString('hex');
  // ✅ PROTECTED — state stored server-side in pendingStates and verified on callback.
  // SP generates crypto.randomBytes(16) before redirect; callback rejects mismatched or missing state.
  // Prevents CSRF: attacker cannot trick victim into completing login with attacker's assertion.
  pendingStates.add(state);

  const loggedOut = req.query.logged_out === '1' ? '&logged_out=1' : '';
  const loginUrl = '/idp/login?client_id=workhub-client-id&redirect_uri=' +
    encodeURIComponent('http://localhost:3066/callback') + '&state=' + state + loggedOut;
  res.redirect(loginUrl);
});

app.get('/callback', function (req, res) {
  const token = req.query.token;
  const state = req.query.state;

  // ✅ PROTECTED — verify state matches what SP issued before accepting assertion token.
  // pendingStates.delete(state) ensures single-use; replay of callback URL fails on second attempt.
  if (!state || !pendingStates.has(state)) {
    return res.status(400).send('Invalid or missing state parameter — possible CSRF attempt');
  }
  pendingStates.delete(state);

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

app.get('/dashboard', function (req, res) {
  const session = getWhSession(req);
  if (!session) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/config', function (_req, res) {
  res.json({ mode: 'secure', port: PORT });
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

app.get('/logout', function (req, res) {
  const sid = getCookie(req, 'wh_session');
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', 'wh_session=; Path=/; Max-Age=0');
  res.redirect('/?logged_out=1');
});

app.listen(PORT, function () {
  console.log('WorkHub + CorpID (hardened allowlist) running at http://localhost:' + PORT);
});
