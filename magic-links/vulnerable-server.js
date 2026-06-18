/*
 * Terminal 1: cd auth-concepts/magic-links && npm install && npm run vulnerable
 * Inkwell — weak magic links (port 3076)
 */

const path = require('path');
const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = 3076;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// CORS for guide live demos (port 3077)
app.use(function (req, res, next) {
  if (req.headers.origin === 'http://localhost:3077') {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3077');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

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

// ⚠️ VULNERABLE — magic tokens have no expiresAt or used flag; valid forever and reusable.
// Old links in forwarded email, archived inbox, or email-provider link scanners remain credentials.
const magicTokens = new Map();

// ⚠️ VULNERABLE — Math.random() for token generation (~30 bits effective entropy).
// PRNG is seeded predictably; ~1 billion possible tokens from three .toString(36) slices.
// Attacker with high request volume or timing observation can predict valid tokens without the email.
function generateToken() {
  return Math.random().toString(36).slice(2) +
    Math.random().toString(36).slice(2) +
    Math.random().toString(36).slice(2);
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

  // ⚠️ VULNERABLE — no rate limiting on send-link; attacker can flood inbox or probe for tokens.
  const token = generateToken();
  magicTokens.set(token, { email: email, createdAt: Date.now() });

  const magicLink = 'http://localhost:3076/auth/verify?token=' + token;
  console.log('[DEMO] Magic link for ' + email + ': ' + magicLink);

  // ⚠️ DEMO ONLY: returning link in API — production sends via email provider
  res.json({
    message: 'Magic link sent! Check your email.',
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

  // ⚠️ VULNERABLE — no expiry check; token works indefinitely after creation.
  // ⚠️ VULNERABLE — token NOT deleted after use; same link works unlimited times (email scanners consume sessions).
  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { email: stored.email, createdAt: Date.now() });

  // ⚠️ VULNERABLE — session cookie missing HttpOnly and SameSite; readable by JavaScript and sent cross-site.
  res.setHeader('Set-Cookie', 'iw_session=' + sid + '; Path=/');
  res.redirect('/dashboard');
});

// ⚠️ VULNERABLE — debug endpoint lists all pending magic tokens in plain text.
// Any caller learns every active login link and can hijack sessions before victims click.
app.get('/api/debug/tokens', function (req, res) {
  const tokens = [];
  for (const entry of magicTokens.entries()) {
    const token = entry[0];
    const data = entry[1];
    tokens.push({
      token: token,
      email: data.email,
      createdAt: new Date(data.createdAt).toISOString(),
      link: 'http://localhost:3076/auth/verify?token=' + token,
    });
  }
  res.json({ count: tokens.length, tokens: tokens });
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
  res.setHeader('Set-Cookie', 'iw_session=; Path=/; Max-Age=0');
  res.json({ message: 'Logged out' });
});

app.get('/api/config', (_req, res) => {
  res.json({ mode: 'vulnerable', port: PORT });
});

app.get('*', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, function () {
  console.log('Inkwell (weak magic links) running at http://localhost:' + PORT);
});
