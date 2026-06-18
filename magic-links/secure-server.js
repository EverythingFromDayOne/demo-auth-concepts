/*
 * Terminal 3: cd auth-concepts/magic-links && npm run secure
 * Inkwell — hardened magic links (port 3078)
 */

const path = require('path');
const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = 3078;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

const USER_PROFILES = {
  'alice@example.com': {
    name: 'Alice Chen',
    plan: 'Pro',
    posts: [
      { id: 1, title: 'Getting started with web security', status: 'published', views: 1240 },
      { id: 2, title: 'Why passwords keep failing us', status: 'published', views: 892 },
      { id: 3, title: 'A guide to passkeys', status: 'draft', views: 0 },
    ],
  },
  'bob@example.com': {
    name: 'Bob Martinez',
    plan: 'Free',
    posts: [
      { id: 4, title: 'My first post on Inkwell', status: 'published', views: 47 },
    ],
  },
};

function getProfile(email) {
  return USER_PROFILES[email] || {
    name: email.split('@')[0],
    plan: 'Free',
    posts: [],
  };
}

const sessions = new Map();

// ✅ PROTECTED: expiresAt enforced, single-use via delete on verify
const magicTokens = new Map();

setInterval(function () {
  const now = Date.now();
  for (const entry of magicTokens.entries()) {
    if (now > entry[1].expiresAt) magicTokens.delete(entry[0]);
  }
}, 10 * 60 * 1000);

const sendRateLimit = new Map();
const MAX_PER_HOUR = 3;
const WINDOW_MS = 60 * 60 * 1000;

function isRateLimited(email) {
  const now = Date.now();
  const state = sendRateLimit.get(email) || { count: 0, windowStart: now };

  if (now - state.windowStart > WINDOW_MS) {
    state.count = 0;
    state.windowStart = now;
  }

  if (state.count >= MAX_PER_HOUR) {
    sendRateLimit.set(email, state);
    return true;
  }

  state.count++;
  sendRateLimit.set(email, state);
  return false;
}

// ✅ PROTECTED: crypto.randomBytes(32) — 256 bits of CSPRNG entropy
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function requireSession(req, res, next) {
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)iw_session=([^;]+)/);
  const sid = match ? match[1] : null;
  const session = sid ? sessions.get(sid) : null;
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.session = session;
  req.sessionId = sid;
  next();
}

app.post('/api/auth/send-link', function (req, res) {
  const email = req.body.email;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email address required' });
  }

  // ✅ PROTECTED: rate limited — same response when blocked (no enumeration)
  if (isRateLimited(email)) {
    return res.json({ message: 'If that email is registered, a link has been sent.' });
  }

  const token = generateToken();
  const expiresAt = Date.now() + 15 * 60 * 1000;
  magicTokens.set(token, { email: email, expiresAt: expiresAt, used: false });

  const magicLink = 'http://localhost:3078/auth/verify?token=' + token;
  console.log('[DEMO] Magic link for ' + email + ': ' + magicLink);

  res.json({
    message: 'If that email is registered, a link has been sent.',
    demoLink: magicLink,
    demoNote: 'DEMO ONLY — production never returns the link in the API response',
  });
});

app.get('/auth/verify', function (req, res) {
  const token = req.query.token;

  if (!token) return res.redirect('/?error=missing_token');

  const stored = magicTokens.get(token);

  if (!stored) {
    return res.redirect('/?error=invalid_token');
  }

  // ✅ PROTECTED: reject expired tokens
  if (Date.now() > stored.expiresAt) {
    magicTokens.delete(token);
    return res.redirect('/?error=link_expired');
  }

  // ✅ PROTECTED: delete token before creating session (single-use)
  magicTokens.delete(token);

  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { email: stored.email, createdAt: Date.now() });

  res.setHeader('Set-Cookie', 'iw_session=' + sid + '; Path=/; HttpOnly; SameSite=Lax');
  res.redirect('/dashboard');
});

app.get('/dashboard', function (req, res) {
  res.redirect('/');
});

app.get('/api/me', requireSession, function (req, res) {
  res.json({ email: req.session.email, ...getProfile(req.session.email) });
});

app.get('/api/profile', requireSession, (req, res) => {
  const email = req.session.email;
  const profile = USER_PROFILES[email] || { name: email, plan: 'free', posts: [] };
  res.json({ email, name: profile.name, plan: profile.plan, posts: profile.posts });
});

app.post('/api/logout', requireSession, function (req, res) {
  sessions.delete(req.sessionId);
  res.setHeader('Set-Cookie', 'iw_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
  res.json({ message: 'Logged out' });
});

app.get('/api/config', (_req, res) => {
  res.json({ mode: 'secure', port: PORT });
});

app.get('*', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, function () {
  console.log('Inkwell (hardened magic links) running at http://localhost:' + PORT);
});
