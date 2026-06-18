/*
 * Terminal 3: cd auth-concepts/basic-digest && npm run secure
 * SimpleDesk — Session Token Auth (improved, port 3051)
 */

const path = require('path');
const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = 3051;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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

// ✅ PROTECTED — password sent once at POST /api/login, then discarded from the wire.
// Subsequent requests carry an opaque random token in Authorization: Bearer — not the password.
// sessions.delete(token) on logout genuinely invalidates access; server-side state makes revocation
// possible. Token is stored in localStorage and sent via Bearer header — scope-limited to this origin.
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

app.get('/api/config', function (_req, res) {
  res.json({ mode: 'secure', port: PORT });
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
  // ✅ PROTECTED — sessions.delete(token) immediately invalidates the Bearer token server-side.
  // Unlike Basic Auth, logout is real: subsequent requests with the old token receive 401.
  sessions.delete(req.token);
  res.json({ message: 'Logged out' });
});

function serveSessionApp(_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'session.html'));
}

app.get('/login', serveSessionApp);
app.get('/dashboard', serveSessionApp);
app.get('/', serveSessionApp);
app.get('*', serveSessionApp);

app.listen(PORT, function () {
  console.log('SimpleDesk (Session Auth) running at http://localhost:' + PORT);
});
