/*
 * Terminal 1: cd auth-concepts/session && npm install && npm run vulnerable
 * NoteKeep — session cookie without HttpOnly (port 3052)
 */

const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = 3052;

app.use(cors({ origin: 'http://localhost:3053', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Server-side session store — the session token is meaningless without this Map
const sessions = new Map();

const USERS = [
  { username: 'alice', password: 'pass1234', fullName: 'Alice Chen' },
  { username: 'bob', password: 'qwerty123', fullName: 'Bob Martinez' },
];

function getSid(req) {
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)nk_session=([^;]+)/);
  return match ? match[1] : null;
}

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In — NoteKeep</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #fafaf9;
      color: #292524;
      min-height: 100vh;
    }
    .auth-banner {
      background: #fffbeb;
      border-bottom: 2px solid #d97706;
      color: #92400e;
      padding: 0.65rem 1.5rem;
      font-size: 0.85rem;
      line-height: 1.5;
      text-align: center;
    }
    .login-wrap {
      min-height: calc(100vh - 42px);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem 1.5rem;
    }
    .login-card {
      background: #fff;
      border: 1px solid #e7e5e4;
      border-radius: 12px;
      padding: 2.5rem;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.06);
    }
    h1 { font-size: 1.5rem; margin-bottom: 0.35rem; color: #1c1917; }
    .tagline { font-size: 0.9rem; color: #78716c; margin-bottom: 2rem; }
    label {
      display: block;
      font-size: 0.8rem;
      font-weight: 600;
      color: #57534e;
      margin-bottom: 0.35rem;
    }
    .field-group { margin-bottom: 1.1rem; }
    .login-input {
      width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #d6d3d1;
      border-radius: 6px; font-size: 0.95rem; color: #1c1917;
      background: #fff; outline: none; box-sizing: border-box; font-family: inherit;
    }
    .login-input:focus { border-color: #d97706; box-shadow: 0 0 0 3px rgba(217,119,6,0.15); }
    .btn-signin {
      width: 100%;
      background: #d97706;
      color: #fff;
      border: none;
      padding: 0.75rem;
      border-radius: 6px;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      margin-top: 0.5rem;
    }
    .btn-signin:hover { background: #b45309; }
    #err { color: #dc2626; font-size: 0.85rem; margin-top: 0.75rem; min-height: 1.2rem; }
  </style>
</head>
<body>
  <div class="auth-banner">
    ⚠ VULNERABLE COOKIE: nk_session is set without HttpOnly — JavaScript can read document.cookie
  </div>
  <div class="login-wrap">
    <div class="login-card">
      <h1>NoteKeep 📝</h1>
      <p class="tagline">Your notes, always in sync</p>
      <form onsubmit="doLogin(event)">
        <div class="field-group">
          <label for="u">Username</label>
          <input class="login-input" type="text" id="u" name="username" autocomplete="username" required>
        </div>
        <div class="field-group">
          <label for="p">Password</label>
          <input class="login-input" type="password" id="p" name="password" autocomplete="current-password" required>
        </div>
        <button type="submit" class="btn-signin">Sign In</button>
        <p id="err"></p>
      </form>
    </div>
  </div>
  <script>
    async function doLogin(e) {
      e.preventDefault();
      var res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          username: document.getElementById('u').value,
          password: document.getElementById('p').value
        })
      });
      var data = await res.json();
      if (res.ok) window.location.href = '/dashboard';
      else document.getElementById('err').textContent = data.error;
    }
  </script>
</body>
</html>`;

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NoteKeep — My Notes</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #fafaf9;
      color: #292524;
      min-height: 100vh;
    }
    .auth-banner {
      background: #fffbeb;
      border-bottom: 2px solid #d97706;
      color: #92400e;
      padding: 0.65rem 1.5rem;
      font-size: 0.85rem;
      line-height: 1.5;
    }
    .layout { display: flex; min-height: calc(100vh - 42px); }
    .sidebar {
      width: 220px;
      background: #f5f5f4;
      border-right: 1px solid #e7e5e4;
      padding: 1.5rem 0;
      display: flex;
      flex-direction: column;
    }
    .sidebar-logo {
      font-size: 1.1rem;
      font-weight: 700;
      color: #1c1917;
      padding: 0 1.25rem 1.25rem;
      border-bottom: 1px solid #e7e5e4;
      margin-bottom: 0.75rem;
    }
    .sidebar a {
      display: block;
      padding: 0.6rem 1.25rem;
      color: #57534e;
      text-decoration: none;
      font-size: 0.9rem;
    }
    .sidebar a.active {
      background: #fef3c7;
      color: #b45309;
      font-weight: 600;
      border-right: 3px solid #d97706;
    }
    .sidebar-footer { margin-top: auto; padding: 1rem 1.25rem; }
    .btn-logout {
      width: 100%;
      background: transparent;
      border: 1px solid #d6d3d1;
      color: #57534e;
      padding: 0.5rem;
      border-radius: 6px;
      font-size: 0.85rem;
      cursor: pointer;
    }
    .btn-logout:hover { background: #e7e5e4; }
    .main { flex: 1; padding: 1.75rem 2rem; }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1.25rem;
    }
    .topbar h2 { font-size: 1.35rem; color: #1c1917; }
    .user-info { font-size: 0.875rem; color: #78716c; }
    #cookie-display {
      background: #fffbeb;
      border: 1px solid #fbbf24;
      border-radius: 8px;
      padding: 0.85rem 1rem;
      font-size: 0.82rem;
      color: #92400e;
      margin-bottom: 1.5rem;
      line-height: 1.6;
      word-break: break-all;
    }
    #cookie-display code {
      font-family: 'Courier New', Courier, monospace;
      font-size: 0.78rem;
      color: #b45309;
    }
    .notes-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
      gap: 1rem;
    }
    .note-card {
      background: #fff;
      border: 1px solid #e7e5e4;
      border-radius: 10px;
      padding: 1.25rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .note-card h3 { font-size: 1rem; margin-bottom: 0.5rem; color: #1c1917; }
    .note-card p { font-size: 0.875rem; color: #57534e; line-height: 1.55; margin-bottom: 0.75rem; }
    .note-card .meta { font-size: 0.75rem; color: #a8a29e; }
    .loading { color: #a8a29e; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="auth-banner">
    ⚠ VULNERABLE COOKIE: nk_session is set without HttpOnly — JavaScript can read document.cookie
  </div>
  <div class="layout">
    <nav class="sidebar">
      <div class="sidebar-logo">NoteKeep 📝</div>
      <a href="#" class="active">All Notes</a>
      <a href="#">Recent</a>
      <a href="#">Archived</a>
      <div class="sidebar-footer">
        <button type="button" class="btn-logout" id="btn-logout">Log Out</button>
      </div>
    </nav>
    <main class="main">
      <div class="topbar">
        <h2>My Notes</h2>
        <div class="user-info" id="user-display">Loading…</div>
      </div>
      <div id="cookie-display">
        Your session cookie (readable by JS): <code id="cookie-value">(login first to see your session cookie)</code>
      </div>
      <p class="loading" id="loading">Loading notes…</p>
      <div class="notes-grid" id="notes-grid"></div>
    </main>
  </div>
  <script>
    // Show document.cookie on the dashboard — demonstrates the vulnerability
    document.getElementById('cookie-value').textContent =
      document.cookie || '(empty — HttpOnly would hide it)';

    fetch('/api/me', { credentials: 'same-origin' })
      .then(function (res) {
        if (!res.ok) throw new Error('unauthorized');
        return res.json();
      })
      .then(function (data) {
        document.getElementById('user-display').textContent = data.fullName;
        document.getElementById('cookie-value').textContent =
          document.cookie || '(empty — HttpOnly would hide it)';
      })
      .catch(function () {
        window.location.href = '/login';
      });

    fetch('/api/notes', { credentials: 'same-origin' })
      .then(function (res) { return res.json(); })
      .then(function (notes) {
        document.getElementById('loading').style.display = 'none';
        var grid = document.getElementById('notes-grid');
        notes.forEach(function (note) {
          var card = document.createElement('div');
          card.className = 'note-card';
          card.innerHTML =
            '<h3>' + note.title + '</h3>' +
            '<p>' + note.body + '</p>' +
            '<div class="meta">Updated ' + note.updatedAt + '</div>';
          grid.appendChild(card);
        });
      })
      .catch(function () {
        window.location.href = '/login';
      });

    document.getElementById('btn-logout').addEventListener('click', function () {
      fetch('/api/logout', { method: 'POST', credentials: 'same-origin' })
        .finally(function () { window.location.href = '/login'; });
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

  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, {
    username: user.username,
    fullName: user.fullName,
    createdAt: Date.now(),
  });

  // ⚠️ VULNERABILITY: no HttpOnly — JS can read document.cookie
  res.setHeader('Set-Cookie', 'nk_session=' + sid + '; Path=/; SameSite=Lax');
  res.json({
    success: true,
    user: { username: user.username, fullName: user.fullName },
  });
});

// For API routes — unauthenticated → JSON 401
function requireSession(req, res, next) {
  const sid = getSid(req);
  const session = sid ? sessions.get(sid) : null;
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.session = session;
  req.sid = sid;
  next();
}

// For page routes — unauthenticated → redirect to /login (never return JSON)
function requirePage(req, res, next) {
  const sid = getSid(req);
  const session = sid ? sessions.get(sid) : null;
  if (!session) return res.redirect('/login');
  req.session = session;
  req.sid = sid;
  next();
}

app.post('/api/logout', requireSession, function (req, res) {
  sessions.delete(req.sid);
  res.setHeader('Set-Cookie', 'nk_session=; Path=/; Max-Age=0');
  res.json({ message: 'Logged out' });
});

app.get('/api/me', requireSession, function (req, res) {
  res.json(req.session);
});

app.get('/api/notes', requireSession, function (req, res) {
  res.json([
    { id: 1, title: 'Meeting Notes', body: 'Q3 planning: ship auth demo by June', updatedAt: '2026-06-10' },
    { id: 2, title: 'Grocery List', body: 'Milk, eggs, coffee, sourdough', updatedAt: '2026-06-12' },
    { id: 3, title: 'Project Ideas', body: 'Auth concepts lab — 7 mechanisms', updatedAt: '2026-06-14' },
  ]);
});

app.get('/login', function (req, res) {
  const sid = getSid(req);
  if (sid && sessions.has(sid)) return res.redirect('/dashboard');
  res.send(LOGIN_HTML);
});

app.get('/dashboard', requirePage, function (req, res) {
  res.send(DASHBOARD_HTML);
});

app.get('/', function (req, res) {
  const sid = getSid(req);
  res.redirect(sid && sessions.has(sid) ? '/dashboard' : '/login');
});

app.listen(PORT, function () {
  console.log('NoteKeep (vulnerable cookie) running at http://localhost:' + PORT);
});
