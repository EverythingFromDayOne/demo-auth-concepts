/*
 * Terminal 3: cd auth-concepts/access-refresh && npm run strong
 * FlowAPI — refresh token rotation + revocation (port 3063)
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = 3063;

app.use(cors({ origin: 'http://localhost:3062' }));
app.use(express.json());

// ✅ PROTECTED: cryptographically strong secrets generated at startup
const ACCESS_SECRET = crypto.randomBytes(64).toString('hex');
const REFRESH_SECRET = crypto.randomBytes(64).toString('hex');
const ACCESS_EXPIRY = '15m';
const REFRESH_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

// token → { userId, username, familyId, version, issuedAt }
const refreshTokenStore = new Map();
// In production: store revoked families in Redis with a TTL matching max refresh token lifetime
const revokedFamilies = new Set();
const rotatedTokens = new Map();

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
  const familyId = crypto.randomUUID();
  refreshTokenStore.set(token, {
    userId: user.id,
    username: user.username,
    familyId: familyId,
    version: 1,
    issuedAt: Date.now(),
  });
  return token;
}

function revokeFamily(familyId) {
  revokedFamilies.add(familyId);
  for (const [tok, data] of refreshTokenStore.entries()) {
    if (data.familyId === familyId) refreshTokenStore.delete(tok);
  }
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FlowAPI — Token Dashboard (Hardened)</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a;
      color: #f1f5f9;
      min-height: 100vh;
    }
    .banner {
      background: #052e16;
      border-bottom: 2px solid #22c55e;
      color: #86efac;
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
    .btn.danger { background: #dc2626; color: #fff; }
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
    .ok-box {
      margin-top: 0.75rem;
      padding: 0.6rem;
      background: #052e16;
      border: 1px solid #16a34a;
      border-radius: 6px;
      font-size: 0.8rem;
      color: #86efac;
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
    ✅ HARDENED: Refresh tokens rotate on every use, expire after 7 days, and are revoked on password change.
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
        <label>REFRESH TOKEN (rotates on use, 7-day max age)</label>
        <div class="token-box" id="refresh-token-display" style="color:#4ade80"></div>
      </div>
      <div class="ok-box">
        ✅ Each /api/refresh call invalidates the old refresh token and issues a new one.
        Reusing an old token triggers family revocation (reuse detection).
      </div>
    </div>

    <div class="card" id="api-panel" style="display:none">
      <h2>3. Test API (Access Token)</h2>
      <button class="btn secondary" id="btn-me">GET /api/me</button>
      <button class="btn secondary" id="btn-projects">GET /api/projects</button>
      <pre class="response" id="api-output">Click an endpoint</pre>
    </div>

    <div class="card" id="refresh-panel" style="display:none">
      <h2>4. Refresh + Security Actions</h2>
      <button class="btn" id="btn-refresh">POST /api/refresh (rotates token)</button>
      <button class="btn danger" id="btn-change-pw">POST /api/change-password (revoke all sessions)</button>
      <pre class="response" id="refresh-output">–</pre>
    </div>
  </div>
  <script>
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
      .then(function (res) { return res.json().then(function (d) { return { data: d }; }); })
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
      liveRefreshToken = data.refreshToken;
      document.getElementById('access-token-display').textContent = data.accessToken;
      document.getElementById('refresh-token-display').textContent =
        data.refreshToken + '\\n\\n✅ Old refresh token invalidated (rotation applied)';
    }
  });

  document.getElementById('btn-change-pw').addEventListener('click', async function () {
    var res = await fetch('/api/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + liveAccessToken
      },
      body: JSON.stringify({ newPassword: 'pass1234' })
    });
    var data = await res.json();
    document.getElementById('refresh-output').textContent = JSON.stringify(data, null, 2);
    if (res.ok) {
      liveAccessToken = null;
      liveRefreshToken = null;
      document.getElementById('token-status').style.display = 'none';
      document.getElementById('api-panel').style.display = 'none';
      document.getElementById('refresh-panel').style.display = 'none';
      document.getElementById('btn-signout').style.display = 'none';
      document.getElementById('login-panel').style.display = '';
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
    note: '✅ Refresh token will rotate on each /api/refresh call',
  });
});

// ✅ PROTECTED: rotation + reuse detection on every refresh
app.post('/api/refresh', function (req, res) {
  const { refreshToken } = req.body;
  const stored = refreshToken ? refreshTokenStore.get(refreshToken) : null;

  if (!stored) {
    const familyId = rotatedTokens.get(refreshToken);
    if (familyId) {
      revokeFamily(familyId);
      return res.status(401).json({ error: 'Refresh token reuse detected — please log in again' });
    }
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  if (revokedFamilies.has(stored.familyId)) {
    return res.status(401).json({ error: 'Refresh token reuse detected — please log in again' });
  }

  if (Date.now() - stored.issuedAt > REFRESH_MAX_AGE_MS) {
    refreshTokenStore.delete(refreshToken);
    return res.status(401).json({ error: 'Refresh token expired — please log in again' });
  }

  const user = USERS.find(function (u) { return u.id === stored.userId; });

  refreshTokenStore.delete(refreshToken);
  rotatedTokens.set(refreshToken, stored.familyId);

  const newRefreshToken = crypto.randomBytes(40).toString('hex');
  refreshTokenStore.set(newRefreshToken, {
    userId: user.id,
    username: user.username,
    familyId: stored.familyId,
    version: stored.version + 1,
    issuedAt: stored.issuedAt,
  });

  res.json({
    accessToken: issueAccessToken(user),
    refreshToken: newRefreshToken,
    tokenType: 'Bearer',
    expiresIn: '15m',
    note: '✅ Old refresh token invalidated. New refresh token issued (rotation applied).',
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

app.post('/api/logout', function (req, res) {
  const { refreshToken } = req.body;
  if (refreshToken && refreshTokenStore.has(refreshToken)) {
    const stored = refreshTokenStore.get(refreshToken);
    refreshTokenStore.delete(refreshToken);
    rotatedTokens.set(refreshToken, stored.familyId);
    res.json({ message: 'Logged out — refresh token revoked', tokensRemaining: refreshTokenStore.size });
  } else {
    res.status(400).json({ error: 'Refresh token not found or already revoked' });
  }
});

// ✅ PROTECTED: revoke all refresh tokens for user on password change
app.post('/api/change-password', requireAccess, function (req, res) {
  const userId = req.user.sub;
  for (const [token, data] of refreshTokenStore.entries()) {
    if (data.userId === userId) {
      rotatedTokens.set(token, data.familyId);
      refreshTokenStore.delete(token);
      revokedFamilies.add(data.familyId);
    }
  }
  res.json({ message: '✅ Password changed. All sessions revoked — please log in again on all devices.' });
});

app.get('/', function (req, res) {
  res.send(DASHBOARD_HTML);
});

app.listen(PORT, function () {
  console.log('FlowAPI (hardened refresh) running at http://localhost:' + PORT);
});
