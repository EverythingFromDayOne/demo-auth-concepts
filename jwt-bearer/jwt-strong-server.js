/*
 * Terminal 3: cd auth-concepts/jwt-bearer && npm run strong
 * AuthFlow — JWT with strong secret (port 3060)
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = 3060;

app.use(cors({ origin: 'http://localhost:3059' }));
app.use(express.json());

// ✅ PROTECTED: 64 random bytes = 512-bit key — not brute-forceable
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
// Generated once at startup. In production: load from environment variable.
console.log('[JWT] Secret generated (64 bytes). In production: store in JWT_SECRET env var.');
// ✅ PROTECTED: short expiry limits window if token is stolen
const JWT_EXPIRES_IN = '15m';

const USERS = [
  { id: 1, username: 'alice', password: 'pass1234', role: 'user', fullName: 'Alice Chen' },
  { id: 2, username: 'bob', password: 'qwerty123', role: 'user', fullName: 'Bob Martinez' },
  { id: 3, username: 'admin', password: 'admin456', role: 'admin', fullName: 'Admin User' },
];

const PLAYGROUND_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AuthFlow — JWT Playground</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a;
      color: #f8fafc;
      min-height: 100vh;
    }
    .banner {
      background: #052e16;
      border-bottom: 2px solid #22c55e;
      color: #86efac;
      padding: 0.65rem 1.5rem;
      font-size: 0.85rem;
      line-height: 1.5;
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
    .logo span { color: #8b5cf6; }
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
    .btn-signout:hover { background: #334155; }
    .signout-note {
      font-size: 0.72rem;
      color: #94a3b8;
      max-width: 320px;
      text-align: right;
      line-height: 1.4;
      display: none;
    }
    .container { max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .card h2 { font-size: 1rem; margin-bottom: 1rem; color: #e2e8f0; }
    label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.35rem; }
    .login-input {
      width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #475569;
      border-radius: 6px; font-size: 0.95rem; color: #f8fafc;
      background: #0f172a; outline: none; box-sizing: border-box; font-family: inherit;
      margin-bottom: 0.85rem;
    }
    .login-input:focus { border-color: #8b5cf6; box-shadow: 0 0 0 3px rgba(139,92,246,0.2); }
    .btn {
      background: #8b5cf6;
      color: #fff;
      border: none;
      padding: 0.6rem 1.1rem;
      border-radius: 6px;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
    }
    .btn:hover { background: #7c3aed; }
    .btn.secondary { background: #334155; margin-right: 0.5rem; margin-bottom: 0.5rem; }
    .btn.secondary:hover { background: #475569; }
    #err { color: #f87171; font-size: 0.85rem; margin-top: 0.5rem; min-height: 1.2rem; }
    .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.75rem; }
    pre.box {
      background: #0f172a;
      padding: 0.5rem;
      border-radius: 4px;
      font-size: 0.72rem;
      white-space: pre-wrap;
      word-break: break-all;
      min-height: 100px;
      font-family: 'Courier New', Courier, monospace;
    }
    #raw-token {
      font-family: 'Courier New', Courier, monospace;
      font-size: 0.72rem;
      word-break: break-all;
      background: #0f172a;
      padding: 0.75rem;
      border-radius: 6px;
      margin-top: 0.25rem;
      line-height: 1.6;
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
      min-height: 80px;
      font-family: 'Courier New', Courier, monospace;
      margin-top: 0.75rem;
    }
    @media (max-width: 768px) { .grid-3 { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="banner">
    ✅ STRONG JWT: 64-byte random secret, 15-minute expiry, HS256 algorithm whitelisted.
  </div>
  <header class="topbar">
    <div>
      <div class="logo">Auth<span>Flow</span></div>
      <div class="tagline">Stateless auth for modern apps</div>
    </div>
    <div style="display:flex;align-items:center;gap:1rem">
      <p class="signout-note" id="signout-note">
        This secret was generated with crypto.randomBytes(64) at startup.
        In production, set JWT_SECRET as an environment variable (never commit to git).
        Expiry: 15 minutes — user must refresh or re-login.
      </p>
      <button type="button" class="btn-signout" id="btn-signout">Sign Out</button>
    </div>
  </header>
  <div class="container">
    <div class="card" id="login-panel">
      <h2>1. Login — Issue JWT</h2>
      <label for="username">Username</label>
      <input class="login-input" type="text" id="username" value="alice" autocomplete="username">
      <label for="password">Password</label>
      <input class="login-input" type="password" id="password" value="pass1234" autocomplete="current-password">
      <button class="btn" id="btn-login">Sign In → Get JWT</button>
      <p id="err"></p>
    </div>

    <div class="card" id="token-display" style="display:none">
      <h2>2. JWT Structure</h2>
      <div style="margin-bottom:1rem">
        <label style="font-size:0.75rem;color:#94a3b8">Raw JWT:</label>
        <div id="raw-token"></div>
      </div>
      <div class="grid-3">
        <div>
          <div style="font-size:0.72rem;color:#f87171;font-weight:600;margin-bottom:0.25rem">HEADER (base64url)</div>
          <pre class="box" id="jwt-header" style="color:#fca5a5"></pre>
        </div>
        <div>
          <div style="font-size:0.72rem;color:#a78bfa;font-weight:600;margin-bottom:0.25rem">PAYLOAD (base64url)</div>
          <pre class="box" id="jwt-payload" style="color:#c4b5fd"></pre>
        </div>
        <div>
          <div style="font-size:0.72rem;color:#60a5fa;font-weight:600;margin-bottom:0.25rem">SIGNATURE (HS256)</div>
          <pre class="box" id="jwt-sig" style="color:#93c5fd"></pre>
        </div>
      </div>
    </div>

    <div class="card" id="api-panel" style="display:none">
      <h2>3. Test API with Bearer Token</h2>
      <div>
        <button class="btn secondary" id="btn-me">GET /api/me</button>
        <button class="btn secondary" id="btn-tasks">GET /api/tasks</button>
        <button class="btn secondary" id="btn-admin">GET /api/admin/users</button>
      </div>
      <pre class="response" id="api-output">Click an endpoint to call the API</pre>
    </div>
  </div>
  <script>
  // Stored in memory — cleared on page refresh. For persistent auth, use httpOnly cookie + refresh token.
  var currentToken = null;

  function b64Decode(str) {
    try { return JSON.parse(atob(str.replace(/-/g, '+').replace(/_/g, '/'))); }
    catch (e) { return str; }
  }

  function displayToken(token) {
    var parts = token.split('.');
    document.getElementById('raw-token').innerHTML =
      '<span style="color:#f87171">' + parts[0] + '</span>' +
      '<span style="color:#475569">.</span>' +
      '<span style="color:#a78bfa">' + parts[1] + '</span>' +
      '<span style="color:#475569">.</span>' +
      '<span style="color:#60a5fa">' + parts[2] + '</span>';
    document.getElementById('jwt-header').textContent = JSON.stringify(b64Decode(parts[0]), null, 2);
    document.getElementById('jwt-payload').textContent = JSON.stringify(b64Decode(parts[1]), null, 2);
    document.getElementById('jwt-sig').textContent =
      parts[2] + '\\n\\n(HMAC-SHA256 of header.payload using the server secret)';
    document.getElementById('token-display').style.display = '';
    document.getElementById('api-panel').style.display = '';
    document.getElementById('btn-signout').style.display = '';
    document.getElementById('signout-note').style.display = '';
  }

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
    currentToken = data.token;
    document.getElementById('login-panel').style.display = 'none';
    displayToken(data.token);
  });

  function callApi(path) {
    if (!currentToken) return;
    fetch(path, { headers: { 'Authorization': 'Bearer ' + currentToken } })
      .then(function (res) { return res.json().then(function (d) { return { ok: res.ok, data: d }; }); })
      .then(function (r) {
        document.getElementById('api-output').textContent = JSON.stringify(r.data, null, 2);
      });
  }

  document.getElementById('btn-me').addEventListener('click', function () { callApi('/api/me'); });
  document.getElementById('btn-tasks').addEventListener('click', function () { callApi('/api/tasks'); });
  document.getElementById('btn-admin').addEventListener('click', function () { callApi('/api/admin/users'); });

  document.getElementById('btn-signout').addEventListener('click', function () {
    currentToken = null;
    document.getElementById('token-display').style.display = 'none';
    document.getElementById('api-panel').style.display = 'none';
    document.getElementById('btn-signout').style.display = 'none';
    document.getElementById('signout-note').style.display = 'none';
    document.getElementById('login-panel').style.display = '';
    document.getElementById('api-output').textContent = 'Click an endpoint to call the API';
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

  const payload = {
    sub: user.id,
    username: user.username,
    role: user.role,
    fullName: user.fullName,
    iat: Math.floor(Date.now() / 1000),
  };

  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    algorithm: 'HS256',
  });

  res.json({
    token: token,
    tokenType: 'Bearer',
    expiresIn: JWT_EXPIRES_IN,
    user: { id: user.id, username: user.username, role: user.role },
  });
});

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';

  if (!token) return res.status(401).json({ error: 'Bearer token required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', expiredAt: err.expiredAt });
    }
    return res.status(401).json({ error: 'Invalid token: ' + err.message });
  }
}

app.get('/api/me', requireAuth, function (req, res) {
  res.json({
    sub: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    fullName: req.user.fullName,
    issuedAt: new Date(req.user.iat * 1000).toISOString(),
    expiresAt: new Date(req.user.exp * 1000).toISOString(),
    note: 'All this data is inside the JWT itself — server checked the signature, not a database',
  });
});

app.get('/api/tasks', requireAuth, function (req, res) {
  res.json([
    { id: 1, title: 'Implement auth demo', done: true, assignee: 'alice' },
    { id: 2, title: 'Write JWT guide', done: false, assignee: 'alice' },
    { id: 3, title: 'Deploy to staging', done: false, assignee: 'bob' },
  ]);
});

app.get('/api/admin/users', requireAuth, function (req, res) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin role required' });
  res.json(USERS.map(function (u) {
    return { id: u.id, username: u.username, role: u.role };
  }));
});

app.get('/', function (req, res) {
  res.send(PLAYGROUND_HTML);
});

app.listen(PORT, function () {
  console.log('AuthFlow (strong JWT) running at http://localhost:' + PORT);
});
