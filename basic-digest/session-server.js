/*
 * Terminal 3: cd auth-concepts/basic-digest && npm run session
 * SimpleDesk — Session Token Auth (improved, port 3051)
 */

const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = 3051;

app.use(express.json());

const USERS = [
  { username: 'alice', password: 'pass1234', fullName: 'Alice Chen', role: 'user' },
  { username: 'bob', password: 'qwerty123', fullName: 'Bob Martinez', role: 'user' },
  { username: 'admin', password: 'admin456', fullName: 'Admin User', role: 'admin' },
];

const TICKETS = [
  { id: 1, title: 'Printer not working', status: 'open', priority: 'low', author: 'alice' },
  { id: 2, title: 'VPN access request', status: 'open', priority: 'medium', author: 'bob' },
  { id: 3, title: 'Software license', status: 'closed', priority: 'low', author: 'alice' },
];

const sessions = new Map();

// ✅ PROTECTED: Credentials sent once at login; subsequent requests use an opaque Bearer token that can be revoked
app.post('/api/login', function (req, res) {
  const { username, password } = req.body;
  const user = USERS.find(function (u) {
    return u.username === username && u.password === password;
  });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    username: user.username,
    fullName: user.fullName,
    role: user.role,
  });
  res.json({
    token: token,
    user: { username: user.username, fullName: user.fullName },
  });
});

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const session = sessions.get(token);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.user = session;
  req.token = token;
  next();
}

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In — SimpleDesk</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f8fafc;
      color: #1e293b;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .login-card {
      background: #fff;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 2.5rem;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.06);
    }
    .logo { font-size: 1.5rem; font-weight: 700; color: #1e293b; margin-bottom: 0.25rem; }
    .logo span { color: #2563eb; }
    .tagline { font-size: 0.85rem; color: #64748b; margin-bottom: 2rem; }
    label {
      display: block;
      font-size: 0.8rem;
      font-weight: 600;
      color: #475569;
      margin-bottom: 0.35rem;
    }
    .field-group { margin-bottom: 1.1rem; }
    .login-input {
      width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #cbd5e1;
      border-radius: 6px; font-size: 0.95rem; color: #0f172a;
      background: #fff; outline: none; box-sizing: border-box; font-family: inherit;
    }
    .login-input:focus { border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,0.15); }
    .btn-signin {
      width: 100%;
      background: #2563eb;
      color: #fff;
      border: none;
      padding: 0.75rem;
      border-radius: 6px;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      margin-top: 0.5rem;
    }
    .btn-signin:hover { background: #1d4ed8; }
    .error { color: #dc2626; font-size: 0.85rem; margin-top: 0.75rem; display: none; }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="logo">Simple<span>Desk</span></div>
    <p class="tagline">Submit and track IT support tickets</p>
    <form id="login-form">
      <div class="field-group">
        <label for="username">Username</label>
        <input class="login-input" type="text" id="username" name="username" autocomplete="username" required>
      </div>
      <div class="field-group">
        <label for="password">Password</label>
        <input class="login-input" type="password" id="password" name="password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn-signin">Sign In</button>
      <p class="error" id="login-error">Invalid credentials. Try alice / pass1234</p>
    </form>
  </div>
  <script>
    if (localStorage.getItem('sdToken')) {
      window.location.href = '/';
    }
    document.getElementById('login-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var username = document.getElementById('username').value;
      var password = document.getElementById('password').value;
      fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password })
      })
        .then(function (res) {
          if (!res.ok) throw new Error('auth failed');
          return res.json();
        })
        .then(function (data) {
          localStorage.setItem('sdToken', data.token);
          window.location.href = '/';
        })
        .catch(function () {
          document.getElementById('login-error').style.display = 'block';
        });
    });
  </script>
</body>
</html>`;

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SimpleDesk — IT Helpdesk</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f8fafc;
      color: #1e293b;
      min-height: 100vh;
    }
    .auth-banner {
      background: #f0fdf4;
      border-bottom: 2px solid #22c55e;
      color: #166534;
      padding: 0.65rem 1.5rem;
      font-size: 0.85rem;
      line-height: 1.5;
    }
    .topbar {
      background: #1e293b;
      color: #f8fafc;
      padding: 0 1.5rem;
      height: 56px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .logo { font-size: 1.15rem; font-weight: 700; }
    .logo span { color: #60a5fa; }
    .tagline { font-size: 0.75rem; color: #94a3b8; margin-left: 0.5rem; font-weight: 400; }
    .topbar-right { display: flex; align-items: center; gap: 1rem; }
    .user-info { font-size: 0.875rem; color: #cbd5e1; }
    .btn-logout {
      background: transparent;
      border: 1px solid #475569;
      color: #e2e8f0;
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      font-size: 0.8rem;
      cursor: pointer;
    }
    .btn-logout:hover { background: #334155; }
    .layout { display: flex; min-height: calc(100vh - 56px - 42px); }
    .sidebar {
      width: 200px;
      background: #f1f5f9;
      border-right: 1px solid #e2e8f0;
      padding: 1.25rem 0;
    }
    .sidebar a {
      display: block;
      padding: 0.6rem 1.25rem;
      color: #475569;
      text-decoration: none;
      font-size: 0.9rem;
    }
    .sidebar a.active {
      background: #e0e7ff;
      color: #2563eb;
      font-weight: 600;
      border-right: 3px solid #2563eb;
    }
    .main { flex: 1; padding: 1.75rem 2rem; }
    .main h2 { font-size: 1.25rem; margin-bottom: 1.25rem; color: #0f172a; }
    .auth-note {
      background: #fff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 1rem 1.25rem;
      font-size: 0.8rem;
      color: #64748b;
      line-height: 1.7;
      margin-bottom: 1.5rem;
      font-family: 'Courier New', Courier, monospace;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: #fff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      overflow: hidden;
      font-size: 0.875rem;
    }
    th {
      text-align: left;
      padding: 0.75rem 1rem;
      background: #f8fafc;
      border-bottom: 1px solid #e2e8f0;
      color: #64748b;
      font-weight: 600;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    td {
      padding: 0.85rem 1rem;
      border-bottom: 1px solid #f1f5f9;
    }
    tr:last-child td { border-bottom: none; }
    .badge {
      display: inline-block;
      padding: 0.2rem 0.55rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: lowercase;
    }
    .badge.open { background: #dbeafe; color: #1d4ed8; }
    .badge.closed { background: #f1f5f9; color: #64748b; }
    .badge.low { background: #f0fdf4; color: #15803d; }
    .badge.medium { background: #fff7ed; color: #c2410c; }
    .loading { color: #94a3b8; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="auth-banner">
    ✅ SESSION AUTH: credentials sent once at login. All subsequent requests use an opaque token.
    Token is not your password — it can be revoked instantly with logout.
  </div>
  <header class="topbar">
    <div>
      <span class="logo">Simple<span>Desk</span></span>
      <span class="tagline">Submit and track IT support tickets</span>
    </div>
    <div class="topbar-right">
      <div class="user-info" id="user-display">Loading…</div>
      <button type="button" class="btn-logout" id="btn-logout">Log Out</button>
    </div>
  </header>
  <div class="layout">
    <nav class="sidebar">
      <a href="#" class="active">Tickets</a>
      <a href="#">Profile</a>
    </nav>
    <main class="main">
      <div class="auth-note">
        What's different vs Basic Auth:<br>
        POST /api/login → credentials sent once → server returns random 64-char token<br>
        GET  /api/tickets → Authorization: Bearer a3f9b2c1... (opaque, not your password)<br>
        POST /api/logout  → sessions.delete(token) — impossible with Basic Auth
      </div>
      <h2>Support Tickets</h2>
      <p class="loading" id="loading">Loading tickets…</p>
      <table id="ticket-table" style="display:none">
        <thead>
          <tr><th>ID</th><th>Title</th><th>Priority</th><th>Status</th></tr>
        </thead>
        <tbody id="ticket-body"></tbody>
      </table>
    </main>
  </div>
  <script>
    var token = localStorage.getItem('sdToken');
    if (!token) {
      window.location.href = '/login';
    }

    function authHeaders() {
      return { 'Authorization': 'Bearer ' + token };
    }

    fetch('/api/me', { headers: authHeaders() })
      .then(function (res) {
        if (!res.ok) throw new Error('unauthorized');
        return res.json();
      })
      .then(function (data) {
        document.getElementById('user-display').textContent =
          data.fullName + ' (' + data.username + ')';
      })
      .catch(function () {
        localStorage.removeItem('sdToken');
        window.location.href = '/login';
      });

    fetch('/api/tickets', { headers: authHeaders() })
      .then(function (res) { return res.json(); })
      .then(function (tickets) {
        document.getElementById('loading').style.display = 'none';
        var table = document.getElementById('ticket-table');
        var tbody = document.getElementById('ticket-body');
        table.style.display = 'table';
        tickets.forEach(function (t) {
          var tr = document.createElement('tr');
          tr.innerHTML =
            '<td>' + t.id + '</td>' +
            '<td>' + t.title + '</td>' +
            '<td><span class="badge ' + t.priority + '">' + t.priority + '</span></td>' +
            '<td><span class="badge ' + t.status + '">' + t.status + '</span></td>';
          tbody.appendChild(tr);
        });
      });

    document.getElementById('btn-logout').addEventListener('click', function () {
      fetch('/api/logout', {
        method: 'POST',
        headers: authHeaders()
      }).finally(function () {
        localStorage.removeItem('sdToken');
        window.location.href = '/login';
      });
    });
  </script>
</body>
</html>`;

app.get('/login', function (req, res) {
  res.send(LOGIN_HTML);
});

app.get('/', function (req, res) {
  res.send(DASHBOARD_HTML);
});

app.get('/api/me', requireAuth, function (req, res) {
  res.json(req.user);
});

app.get('/api/tickets', requireAuth, function (req, res) {
  res.json(TICKETS);
});

app.post('/api/tickets', requireAuth, function (req, res) {
  const { title, priority } = req.body;
  res.json({ id: 4, title: title, priority: priority, status: 'open', author: req.user.username });
});

app.post('/api/logout', requireAuth, function (req, res) {
  sessions.delete(req.token);
  res.json({ message: 'Logged out' });
});

app.listen(PORT, function () {
  console.log('SimpleDesk (Session Auth) running at http://localhost:' + PORT);
});
