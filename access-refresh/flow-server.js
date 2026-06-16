/*
 * Terminal 1: cd auth-concepts/access-refresh && npm install && npm run vulnerable
 * FlowAPI — refresh tokens without rotation (port 3061)
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = 3061;

app.use(cors({ origin: 'http://localhost:3062' }));
app.use(express.json());

// ⚠️ VULNERABILITY: weak secrets, no rotation, refresh tokens never expire
const ACCESS_SECRET = 'access-secret-weak';
const ACCESS_EXPIRY = '15m';
// REFRESH_SECRET unused — refresh tokens are opaque bytes stored in Map (see prompt note #2)
const REFRESH_SECRET = 'refresh-secret-weak';

const refreshTokenStore = new Map();

const USERS = [
  { id: 1, username: 'alice', password: 'pass1234', role: 'user' },
  { id: 2, username: 'bob', password: 'qwerty123', role: 'user' },
  { id: 3, username: 'admin', password: 'admin456', role: 'admin' },
];

function issueAccessToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role, type: 'access' },
    ACCESS_SECRET,
    { expiresIn: ACCESS_EXPIRY, algorithm: 'HS256' }
  );
}

function issueRefreshToken(user) {
  const token = crypto.randomBytes(40).toString('hex');
  // ⚠️ VULNERABILITY: stored forever, never rotated
  refreshTokenStore.set(token, {
    userId: user.id,
    username: user.username,
    issuedAt: Date.now(),
  });
  return token;
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FlowAPI — Token Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a;
      color: #f1f5f9;
      min-height: 100vh;
    }
    .banner {
      background: #422006;
      border-bottom: 2px solid #f59e0b;
      color: #fcd34d;
      padding: 0.65rem 1.5rem;
      font-size: 0.85rem;
    }
    .topbar {
      background: #1e293b;
      border-bottom: 1px solid #334155;
      padding: 1rem 2rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .logo { font-size: 1.25rem; font-weight: 700; }
    .logo span { color: #0ea5e9; }
    .tagline { font-size: 0.8rem; color: #94a3b8; margin-top: 0.15rem; }
    .btn-signout {
      background: transparent;
      border: 1px solid #475569;
      color: #e2e8f0;
      padding: 0.4rem 0.85rem;
      border-radius: 6px;
      font-size: 0.8rem;
      cursor: pointer;
      display: none;
    }
    .container { max-width: 1000px; margin: 0 auto; padding: 2rem 1.5rem; }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .card h2 { font-size: 1rem; margin-bottom: 1rem; color: #e2e8f0; }
    .login-input {
      width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #475569;
      border-radius: 6px; font-size: 0.95rem; color: #f1f5f9;
      background: #0f172a; outline: none; box-sizing: border-box; font-family: inherit;
      margin-bottom: 0.85rem;
    }
    .btn {
      background: #0ea5e9;
      color: #0f172a;
      border: none;
      padding: 0.6rem 1.1rem;
      border-radius: 6px;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      margin-right: 0.5rem;
      margin-bottom: 0.5rem;
    }
    .btn:hover { background: #38bdf8; }
    .btn.secondary { background: #334155; color: #e2e8f0; }
    .token-box {
      font-family: 'Courier New', Courier, monospace;
      font-size: 0.7rem;
      word-break: break-all;
      background: #0f172a;
      padding: 0.75rem;
      border-radius: 6px;
      line-height: 1.5;
      min-height: 60px;
    }
    .warn-box {
      margin-top: 0.75rem;
      padding: 0.6rem;
      background: #7f1d1d;
      border-radius: 6px;
      font-size: 0.8rem;
      color: #fca5a5;
      line-height: 1.5;
    }
    pre.response {
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 6px;
      padding: 1rem;
      font-size: 0.78rem;
      color: #cbd5e1;
      white-space: pre-wrap;
      word-break: break-all;
      min-height: 60px;
      font-family: 'Courier New', Courier, monospace;
      margin-top: 0.75rem;
    }
    label { display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.25rem; }
    #err { color: #f87171; font-size: 0.85rem; margin-top: 0.5rem; }
  </style>
</head>
<body>
  <div class="banner">
    ⚠ VULNERABLE: Refresh tokens never expire and are never rotated on use.
  </div>
  <header class="topbar">
    <div>
      <div class="logo">Flow<span>API</span></div>
      <div class="tagline">Ship faster, stay secure</div>
    </div>
    <button type="button" class="btn-signout" id="btn-signout">Sign Out</button>
  </header>
  <div class="container">
    <div class="card" id="login-panel">
      <h2>1. Login — Issue Access + Refresh Tokens</h2>
      <label>Username</label>
      <input class="login-input" type="text" id="username" value="alice">
      <label>Password</label>
      <input class="login-input" type="password" id="password" value="pass1234">
      <button class="btn" id="btn-login">Sign In</button>
      <p id="err"></p>
    </div>

    <div class="card" id="token-status" style="display:none">
      <h2>2. Token Status</h2>
      <div style="margin-bottom:1rem">
        <label>ACCESS TOKEN (expires in 15 min)</label>
        <div class="token-box" id="access-token-display" style="color:#a78bfa"></div>
      </div>
      <div>
        <label>REFRESH TOKEN (never expires ⚠)</label>
        <div class="token-box" id="refresh-token-display" style="color:#f87171"></div>
      </div>
      <div class="warn-box">
        ⚠ Vulnerable: If an attacker captures this refresh token (e.g. from logs, MITM, XSS),
        they can get new access tokens indefinitely — there is no way to invalidate the specific token
        without clearing the entire store.
      </div>
    </div>

    <div class="card" id="api-panel" style="display:none">
      <h2>3. Test API (Access Token)</h2>
      <button class="btn secondary" id="btn-me">GET /api/me</button>
      <button class="btn secondary" id="btn-projects">GET /api/projects</button>
      <pre class="response" id="api-output">Click an endpoint</pre>
    </div>

    <div class="card" id="refresh-panel" style="display:none">
      <h2>4. Refresh Access Token</h2>
      <p style="font-size:0.85rem;color:#94a3b8;margin-bottom:0.75rem">
        When access token expires (15 min), use the refresh token to get a new one.
        On this server, the old refresh token stays valid forever.
      </p>
      <button class="btn" id="btn-refresh">POST /api/refresh</button>
      <pre class="response" id="refresh-output">–</pre>
    </div>
  </div>
  <script>
  // DEMO ONLY: both tokens in memory so they are visible. Production: refresh → httpOnly cookie.
  var liveAccessToken = null;
  var liveRefreshToken = null;

  document.getElementById('btn-login').addEventListener('click', async function () {
    document.getElementById('err').textContent = '';
    var res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value
      })
    });
    var data = await res.json();
    if (!res.ok) {
      document.getElementById('err').textContent = data.error;
      return;
    }
    liveAccessToken = data.accessToken;
    liveRefreshToken = data.refreshToken;
    document.getElementById('access-token-display').textContent = data.accessToken;
    document.getElementById('refresh-token-display').textContent = data.refreshToken;
    document.getElementById('login-panel').style.display = 'none';
    document.getElementById('token-status').style.display = '';
    document.getElementById('api-panel').style.display = '';
    document.getElementById('refresh-panel').style.display = '';
    document.getElementById('btn-signout').style.display = '';
  });

  function callApi(path, outId) {
    fetch(path, { headers: { 'Authorization': 'Bearer ' + liveAccessToken } })
      .then(function (res) { return res.json().then(function (d) { return { ok: res.ok, status: res.status, data: d }; }); })
      .then(function (r) {
        document.getElementById(outId).textContent = JSON.stringify(r.data, null, 2);
      });
  }

  document.getElementById('btn-me').addEventListener('click', function () { callApi('/api/me', 'api-output'); });
  document.getElementById('btn-projects').addEventListener('click', function () { callApi('/api/projects', 'api-output'); });

  document.getElementById('btn-refresh').addEventListener('click', async function () {
    var res = await fetch('/api/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: liveRefreshToken })
    });
    var data = await res.json();
    document.getElementById('refresh-output').textContent = JSON.stringify(data, null, 2);
    if (res.ok) {
      liveAccessToken = data.accessToken;
      document.getElementById('access-token-display').textContent = data.accessToken;
      document.getElementById('refresh-token-display').textContent =
        liveRefreshToken + '\\n\\n⚠ OLD refresh token still valid — no rotation';
    }
  });

  document.getElementById('btn-signout').addEventListener('click', async function () {
    if (liveRefreshToken) {
      await fetch('/api/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: liveRefreshToken })
      }).catch(function () {});
    }
    liveAccessToken = null;
    liveRefreshToken = null;
    document.getElementById('token-status').style.display = 'none';
    document.getElementById('api-panel').style.display = 'none';
    document.getElementById('refresh-panel').style.display = 'none';
    document.getElementById('btn-signout').style.display = 'none';
    document.getElementById('login-panel').style.display = '';
  });
  </script>
</body>
</html>`;

app.post('/api/login', function (req, res) {
  const { username, password } = req.body;
  const user = USERS.find(function (u) {
    return u.username === username && u.password === password;
  });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  res.json({
    accessToken: issueAccessToken(user),
    refreshToken: issueRefreshToken(user),
    tokenType: 'Bearer',
    expiresIn: '15m',
    note: '⚠ Refresh token never expires and is never rotated — if stolen, attacker has permanent access',
  });
});

// ⚠️ VULNERABILITY: issues new access token WITHOUT invalidating the old refresh token
app.post('/api/refresh', function (req, res) {
  const { refreshToken } = req.body;
  const stored = refreshToken ? refreshTokenStore.get(refreshToken) : null;
  if (!stored) return res.status(401).json({ error: 'Invalid refresh token' });

  const user = USERS.find(function (u) { return u.id === stored.userId; });
  res.json({
    accessToken: issueAccessToken(user),
    tokenType: 'Bearer',
    expiresIn: '15m',
    warning: '⚠ Old refresh token still valid — no rotation. Token count in store: ' + refreshTokenStore.size,
  });
});

function requireAccess(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Access token required' });
  try {
    req.user = jwt.verify(token, ACCESS_SECRET, { algorithms: ['HS256'] });
    next();
  } catch (err) {
    res.status(401).json({
      error: err.name === 'TokenExpiredError' ? 'Access token expired — use refresh token' : 'Invalid token',
    });
  }
}

app.get('/api/projects', requireAccess, function (req, res) {
  res.json([
    { id: 1, name: 'Auth Concepts Demo', status: 'active' },
    { id: 2, name: 'Security Audit Q3', status: 'pending' },
  ]);
});

app.get('/api/me', requireAccess, function (req, res) {
  res.json({
    sub: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    tokenExpiresAt: new Date(req.user.exp * 1000).toISOString(),
  });
});

// ⚠️ VULNERABILITY: only removes this one token; attacker's copy still works
app.post('/api/logout', function (req, res) {
  const { refreshToken } = req.body;
  if (refreshToken && refreshTokenStore.has(refreshToken)) {
    refreshTokenStore.delete(refreshToken);
    res.json({ message: 'Logged out — this refresh token deleted', tokensRemaining: refreshTokenStore.size });
  } else {
    res.status(400).json({ error: 'Refresh token not found or already revoked' });
  }
});

app.get('/', function (req, res) {
  res.send(DASHBOARD_HTML);
});

app.listen(PORT, function () {
  console.log('FlowAPI (vulnerable refresh) running at http://localhost:' + PORT);
});
