/*
 * Terminal 1: cd auth-concepts/basic-digest && npm install && npm run basic
 * SimpleDesk — HTTP Basic Auth demo (port 3049)
 */

const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 3049;

app.use(cors({ origin: 'http://localhost:3050' }));
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

// ⚠️ VULNERABILITY: Basic Auth sends base64(username:password) on every request — trivially decoded with atob()
function basicAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';

  if (!authHeader.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="SimpleDesk"');
    return res.status(401).json({ error: 'Authentication required' });
  }

  const base64 = authHeader.slice(6);
  const decoded = Buffer.from(base64, 'base64').toString('utf8');
  const colonIndex = decoded.indexOf(':');
  const username = decoded.substring(0, colonIndex);
  const password = decoded.substring(colonIndex + 1);

  const user = USERS.find(function (u) {
    return u.username === username && u.password === password;
  });
  if (!user) {
    res.setHeader('WWW-Authenticate', 'Basic realm="SimpleDesk"');
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  req.user = user;
  next();
}

function DASHBOARD_HTML(user) {
  return `<!DOCTYPE html>
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
      background: #fffbeb;
      border-bottom: 2px solid #f59e0b;
      color: #92400e;
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
    .user-info { font-size: 0.875rem; color: #cbd5e1; }
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
    .badge.high { background: #fef2f2; color: #b91c1c; }
    .loading { color: #94a3b8; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="auth-banner">
    ⚠ BASIC AUTH: your credentials (username:password) are sent base64-encoded with EVERY request.
    Open DevTools → Network → any request → Authorization header to see them.
  </div>
  <header class="topbar">
    <div>
      <span class="logo">Simple<span>Desk</span></span>
      <span class="tagline">Submit and track IT support tickets</span>
    </div>
    <div class="user-info" id="user-display">${user.fullName} (${user.username})</div>
  </header>
  <div class="layout">
    <nav class="sidebar">
      <a href="#" class="active">Tickets</a>
      <a href="#">Profile</a>
    </nav>
    <main class="main">
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
    fetch('/api/me', { credentials: 'same-origin' })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        document.getElementById('user-display').textContent =
          data.fullName + ' (' + data.username + ')';
      });

    fetch('/api/tickets', { credentials: 'same-origin' })
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
  </script>
</body>
</html>`;
}

// Every route requires Basic Auth — credentials sent with EVERY request
app.get('/', basicAuth, function (req, res) {
  res.send(DASHBOARD_HTML(req.user));
});

app.get('/api/me', basicAuth, function (req, res) {
  res.json({
    username: req.user.username,
    fullName: req.user.fullName,
    role: req.user.role,
  });
});

app.get('/api/tickets', basicAuth, function (req, res) {
  res.json(TICKETS);
});

app.post('/api/tickets', basicAuth, function (req, res) {
  const { title, priority } = req.body;
  res.json({ id: 4, title: title, priority: priority, status: 'open', author: req.user.username });
});

app.listen(PORT, function () {
  console.log('SimpleDesk (Basic Auth) running at http://localhost:' + PORT);
});
