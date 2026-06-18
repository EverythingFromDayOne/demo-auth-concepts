/*
 * Terminal 3: cd auth-concepts/session && npm run secure
 * NoteKeep — HttpOnly + SameSite=Strict session cookie (port 3054)
 */

const path = require('path');
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = 3054;

app.use(cors({ origin: 'http://localhost:3053', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

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

  // ✅ PROTECTED — HttpOnly + SameSite=Strict; JavaScript cannot read document.cookie.
  // HttpOnly: the browser sends the cookie automatically but blocks all JS access — document.cookie
  // returns "". XSS payloads cannot exfiltrate what they cannot read.
  // SameSite=Strict: cookie is not sent on cross-site navigations, eliminating CSRF for this session.
  // Production version would include `Secure` — requires HTTPS.
  // In this demo over HTTP, Secure is omitted so the browser sends the cookie.
  // In production: `nk_session=${sid}; Path=/; HttpOnly; Secure; SameSite=Strict`
  res.setHeader('Set-Cookie', 'nk_session=' + sid + '; Path=/; HttpOnly; SameSite=Strict');
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

app.get('/api/config', function (_req, res) {
  res.json({ mode: 'secure', port: PORT });
});

app.post('/api/logout', requireSession, function (req, res) {
  sessions.delete(req.sid);
  res.setHeader('Set-Cookie', 'nk_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict');
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

app.get('*', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, function () {
  console.log('NoteKeep (hardened cookie) running at http://localhost:' + PORT);
});
