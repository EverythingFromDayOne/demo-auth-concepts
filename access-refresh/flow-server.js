/*
 * Terminal 1: cd auth-concepts/access-refresh && npm install && npm run vulnerable
 * FlowAPI — refresh tokens without rotation (port 3061)
 */

const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = 3061;

app.use(cors({ origin: 'http://localhost:3062', credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Refresh token travels in httpOnly cookie — not in request body
function getRefreshCookie(req) {
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)ar_refresh=([^;]+)/);
  return match ? match[1] : null;
}

// ⚠️ VULNERABLE — weak signing secret ('access-secret-weak'); same brute-force risk as jwt-bearer.
// No refresh token rotation: each /api/refresh issues a new access token but keeps the old
// refresh token valid. If stolen, an attacker can silently refresh indefinitely — legitimate user
// and attacker both have valid sessions with no signal of compromise. No refresh token expiry:
// a stolen refresh token grants permanent access unless the user logs out or the secret rotates.
// No token family tracking — token theft is invisible; two parties can use the same refresh token.
const ACCESS_SECRET = 'access-secret-weak';
const ACCESS_EXPIRY = '15m';
// REFRESH_SECRET unused — refresh tokens are opaque bytes stored in Map (see prompt note #2)
const REFRESH_SECRET = 'refresh-secret-weak';

// ⚠️ VULNERABLE — refresh tokens stored forever in Map, never rotated or expired.
// Each login adds a permanent entry; stolen cookie from browser backup or XSS exfiltration
// grants indefinite access until explicit POST /api/logout — no automatic expiry or rotation signal.
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
  // ⚠️ VULNERABLE — refresh token stored forever with no expiry or rotation metadata.
  // refreshTokenStore entry lacks expiresAt and familyId — cannot detect reuse or bound lifetime.
  refreshTokenStore.set(token, {
    userId: user.id,
    username: user.username,
    issuedAt: Date.now(),
  });
  return token;
}

app.get('/api/config', function (_req, res) {
  res.json({ mode: 'vulnerable', port: PORT });
});

// POST /api/login → sets ar_refresh httpOnly cookie + returns { accessToken }
// ⚠️ VULNERABLE — refresh cookie has no Max-Age; token never expires and is never rotated.
// Attacker who steals the cookie from a compromised browser retains access indefinitely.
app.post('/api/login', function (req, res) {
  const { username, password } = req.body;
  const user = USERS.find(function (u) {
    return u.username === username && u.password === password;
  });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const refreshToken = issueRefreshToken(user);
  res.setHeader('Set-Cookie', 'ar_refresh=' + refreshToken + '; HttpOnly; SameSite=Strict; Path=/');
  res.json({
    accessToken: issueAccessToken(user),
    tokenType: 'Bearer',
    expiresIn: '15m',
    note: '⚠ Refresh cookie never expires and is never rotated',
  });
});

// POST /api/refresh — reads cookie, issues new access token, does NOT rotate cookie
// ⚠️ VULNERABLE — same refresh cookie stays valid forever after every refresh call.
// Stolen refresh token can be replayed from any machine until explicit logout.
app.post('/api/refresh', function (req, res) {
  const refreshToken = getRefreshCookie(req);
  const stored = refreshToken ? refreshTokenStore.get(refreshToken) : null;
  if (!stored) return res.status(401).json({ error: 'No valid refresh token' });

  const user = USERS.find(function (u) { return u.id === stored.userId; });
  // ⚠️ VULNERABLE — cookie NOT rotated; same refresh token remains valid after issuing new access token.
  // Attacker and victim share the same refresh cookie value; both can call /api/refresh indefinitely.
  res.json({
    accessToken: issueAccessToken(user),
    tokenType: 'Bearer',
    expiresIn: '15m',
    warning: '⚠ Refresh cookie not rotated. Store size: ' + refreshTokenStore.size,
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

// POST /api/logout — reads cookie, deletes from store, clears cookie
app.post('/api/logout', function (req, res) {
  const refreshToken = getRefreshCookie(req);
  if (refreshToken) refreshTokenStore.delete(refreshToken);
  res.setHeader('Set-Cookie', 'ar_refresh=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ message: 'Logged out — refresh cookie cleared' });
});

app.get('*', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, function () {
  console.log('FlowAPI (vulnerable refresh) running at http://localhost:' + PORT);
});
