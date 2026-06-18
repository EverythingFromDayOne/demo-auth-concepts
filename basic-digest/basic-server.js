/*
 * Terminal 1: cd auth-concepts/basic-digest && npm install && npm run vulnerable
 * SimpleDesk — HTTP Basic Auth demo (port 3049)
 */

const path = require('path');
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 3049;

app.use(cors({ origin: 'http://localhost:3050' }));
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

// ⚠️ VULNERABLE — HTTP Basic Auth sends base64(username:password) on every request.
// Base64 is encoding, not encryption — atob("YWxpY2U6cGFzczEyMzQ=") instantly reveals alice:pass1234
// in any browser console. The Authorization header is attached to every API call and page load,
// so every reverse proxy, CDN access log, and packet capture contains the plaintext-equivalent
// password. There is no server-side session: credentials cannot be revoked without changing the
// password, and "logout" is impossible — the browser keeps sending the same header until cleared.
function basicAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';

  if (!authHeader.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="SimpleDesk"');
    return res.status(401).json({ error: 'Authentication required' });
  }

  const base64 = authHeader.slice(6);
  const decoded = Buffer.from(base64, 'base64').toString('utf8');
  const [username, password] = decoded.split(':');

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

app.get('/api/config', function (_req, res) {
  res.json({ mode: 'vulnerable', port: PORT });
});

app.get('/', basicAuth, function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
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

app.get('*', basicAuth, function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, function () {
  console.log('SimpleDesk (Basic Auth) running at http://localhost:' + PORT);
});
