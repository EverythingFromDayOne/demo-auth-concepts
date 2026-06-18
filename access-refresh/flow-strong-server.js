/*
 * Terminal 3: cd auth-concepts/access-refresh && npm run secure
 * FlowAPI — refresh token rotation + revocation (port 3063)
 */

const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = 3063;

app.use(cors({ origin: 'http://localhost:3062', credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function getRefreshCookie(req) {
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)ar_refresh=([^;]+)/);
  return match ? match[1] : null;
}

function setRefreshCookie(res, token) {
  res.setHeader('Set-Cookie',
    'ar_refresh=' + token + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=' + (7 * 24 * 60 * 60)
  );
}

function clearRefreshCookie(res) {
  res.setHeader('Set-Cookie', 'ar_refresh=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
}

// ✅ PROTECTED — cryptographically strong access-token signing secret generated at startup.
// crypto.randomBytes(64) from OS CSPRNG; brute-forcing the HMAC key is computationally infeasible.
// In production: persist via environment variable so tokens survive server restarts.
const ACCESS_SECRET = crypto.randomBytes(64).toString('hex');
const ACCESS_EXPIRY = '15m';
const REFRESH_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

// ✅ PROTECTED — each refresh token entry has a family ID for reuse detection.
// Every login creates a linked "family" of refresh tokens. If an already-rotated token is
// presented again, the entire family is revoked — all sessions for that login are destroyed.
// This detects token theft even when the attacker refreshes before the legitimate user does.
const refreshTokenStore = new Map();
// In production: store revoked families in Redis with a TTL matching the max refresh token lifetime
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
  refreshTokenStore.set(token, {
    userId: user.id,
    username: user.username,
    familyId: crypto.randomUUID(),
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

app.get('/api/config', function (_req, res) {
  res.json({ mode: 'secure', port: PORT });
});

// POST /api/login — sets cookie, returns access token only
app.post('/api/login', function (req, res) {
  const { username, password } = req.body;
  const user = USERS.find(function (u) {
    return u.username === username && u.password === password;
  });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const refreshToken = issueRefreshToken(user);
  setRefreshCookie(res, refreshToken);
  res.json({
    accessToken: issueAccessToken(user),
    tokenType: 'Bearer',
    expiresIn: '15m',
    note: '✅ Refresh token in httpOnly cookie. Rotates on every /api/refresh call.',
  });
});

// ✅ PROTECTED — rotation + reuse detection on every /api/refresh call.
// Old refresh token is deleted and recorded as rotated; new token issued in Set-Cookie.
// If a stolen token is reused after rotation, revokeFamily() kills every session in that family.
app.post('/api/refresh', function (req, res) {
  const refreshToken = getRefreshCookie(req);
  const stored = refreshToken ? refreshTokenStore.get(refreshToken) : null;

  if (!stored) {
    const familyId = refreshToken ? rotatedTokens.get(refreshToken) : null;
    if (familyId) {
      revokeFamily(familyId);
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Refresh token reuse detected — all sessions revoked' });
    }
    return res.status(401).json({ error: 'No valid refresh token' });
  }

  if (revokedFamilies.has(stored.familyId)) {
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Session revoked — please log in again' });
  }

  if (Date.now() - stored.issuedAt > REFRESH_MAX_AGE_MS) {
    refreshTokenStore.delete(refreshToken);
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Refresh token expired — please log in again' });
  }

  const user = USERS.find(function (u) { return u.id === stored.userId; });

  // ✅ PROTECTED — rotation: delete old token, record in rotatedTokens, issue new cookie.
  // Attacker gets at most one refresh from a stolen token; legitimate user's next refresh
  // fails if attacker used it first, surfacing the compromise.
  refreshTokenStore.delete(refreshToken);
  rotatedTokens.set(refreshToken, stored.familyId);

  const newToken = crypto.randomBytes(40).toString('hex');
  refreshTokenStore.set(newToken, {
    userId: user.id,
    username: user.username,
    familyId: stored.familyId,
    version: stored.version + 1,
    issuedAt: stored.issuedAt,
  });

  setRefreshCookie(res, newToken);
  res.json({
    accessToken: issueAccessToken(user),
    tokenType: 'Bearer',
    expiresIn: '15m',
    note: '✅ Refresh cookie rotated — old token invalidated, new cookie set.',
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

// POST /api/logout — reads cookie, revokes, clears cookie
app.post('/api/logout', function (req, res) {
  const refreshToken = getRefreshCookie(req);
  if (refreshToken && refreshTokenStore.has(refreshToken)) {
    const stored = refreshTokenStore.get(refreshToken);
    rotatedTokens.set(refreshToken, stored.familyId);
    refreshTokenStore.delete(refreshToken);
  }
  clearRefreshCookie(res);
  res.json({ message: '✅ Logged out — refresh cookie cleared' });
});

// ✅ PROTECTED — revoke all refresh-token families on password change.
// Iterates every stored token for this userId, adds each family to revokedFamilies, clears cookie.
// Forces re-login on all devices — standard response to suspected credential compromise.
app.post('/api/change-password', requireAccess, function (req, res) {
  const userId = req.user.sub;
  for (const [token, data] of refreshTokenStore.entries()) {
    if (data.userId === userId) {
      rotatedTokens.set(token, data.familyId);
      revokedFamilies.add(data.familyId);
      refreshTokenStore.delete(token);
    }
  }
  clearRefreshCookie(res);
  res.json({ message: '✅ Password changed. All sessions revoked — please log in again on all devices.' });
});

app.get('*', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, function () {
  console.log('FlowAPI (hardened refresh) running at http://localhost:' + PORT);
});
