/*
 * Terminal 3: cd auth-concepts/jwt-bearer && npm run secure
 * AuthFlow — JWT with strong secret (port 3060)
 */

const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = 3060;

app.use(cors({ origin: 'http://localhost:3059' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ✅ PROTECTED — 512-bit random key generated fresh at each server start.
// crypto.randomBytes(64) draws from the OS CSPRNG, producing 2^512 possible keys.
// Brute-forcing at 1 billion attempts/second would take longer than the age of the universe.
// In production, load this from a JWT_SECRET environment variable so the same key persists
// across restarts without being hardcoded in source.
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
// Generated once at startup. In production: load from environment variable.
console.log('[JWT] Secret generated (64 bytes). In production: store in JWT_SECRET env var.');
// ✅ PROTECTED — 15-minute expiry limits the damage window for a stolen token.
// Even if a token leaks, it becomes useless in at most 15 minutes. Pair with refresh token
// rotation (see access-refresh concept) so legitimate users get seamless re-authentication
// without re-entering credentials.
const JWT_EXPIRES_IN = '15m';

const USERS = [
  { id: 1, username: 'alice', password: 'pass1234', role: 'user', fullName: 'Alice Chen' },
  { id: 2, username: 'bob', password: 'qwerty123', role: 'user', fullName: 'Bob Martinez' },
  { id: 3, username: 'admin', password: 'admin456', role: 'admin', fullName: 'Admin User' },
];

app.get('/api/config', function (_req, res) {
  res.json({ mode: 'secure', port: PORT });
});

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

app.get('*', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, function () {
  console.log('AuthFlow (strong JWT) running at http://localhost:' + PORT);
});
