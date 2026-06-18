/*
 * CloudPortal (hardened WebAuthn) - port 3075
 */
const path = require('path');
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const PORT = 3075;

app.use(cors({ origin: 'http://localhost:3074' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const USERS = [
  { username: 'alice', password: 'pass1234', fullName: 'Alice Chen', role: 'user' },
  { username: 'bob', password: 'qwerty123', fullName: 'Bob Martinez', role: 'user' },
  { username: 'admin', password: 'admin456', fullName: 'Admin User', role: 'admin' },
];

const sessions = new Map();
const credentialStore = new Map();
const registrationChallenges = new Map();
const authChallenges = new Map();

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const session = sessions.get(token);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.user = session;
  req.token = token;
  next();
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find((u) => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token, hasPasskey: credentialStore.has(user.username) });
});

app.post('/api/logout', requireAuth, (req, res) => {
  sessions.delete(req.token);
  res.json({ message: 'Logged out' });
});

app.get('/api/me', requireAuth, (req, res) => {
  const cred = credentialStore.get(req.user.username);
  res.json({
    username: req.user.username,
    fullName: req.user.fullName,
    role: req.user.role,
    hasPasskey: !!cred,
    authenticatorCounter: cred ? cred.counter : 0,
  });
});

app.get('/api/resources', requireAuth, (req, res) => {
  res.json([
    { id: 'vm-001', name: 'prod-api-01', type: 'Compute Instance', region: 'us-east-1', status: 'running' },
    { id: 'db-002', name: 'primary-db', type: 'Database', region: 'us-east-1', status: 'running' },
    { id: 's3-003', name: 'assets-bucket', type: 'Object Storage', region: 'us-west-2', status: 'active' },
  ]);
});

app.get('/api/register/begin', requireAuth, async (req, res) => {
  const { username, fullName } = req.user;
  const existingCred = credentialStore.get(username);
  const excludeCredentials = existingCred
    ? [{ id: existingCred.credentialID, type: 'public-key', transports: existingCred.transports }]
    : [];

  const options = await generateRegistrationOptions({
    rpName: 'CloudPortal',
    rpID: 'localhost',
    // ✅ PROTECTED: opaque ID
    userID: Buffer.from(crypto.randomUUID()),
    userName: username,
    userDisplayName: fullName,
    attestationType: 'none',
    excludeCredentials,
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      // ✅ PROTECTED: UV required
      userVerification: 'required',
    },
    timeout: 60000,
  });

  registrationChallenges.set(username, {
    challenge: options.challenge,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });
  res.json(options);
});

app.post('/api/register/complete', requireAuth, async (req, res) => {
  const { username } = req.user;
  const stored = registrationChallenges.get(username);
  if (!stored) return res.status(400).json({ error: 'No pending registration' });
  if (Date.now() > stored.expiresAt) {
    registrationChallenges.delete(username);
    return res.status(400).json({ error: 'Registration challenge expired — start again' });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: stored.challenge,
      expectedOrigin: 'http://localhost:3075',
      expectedRPID: 'localhost',
      requireUserVerification: true,
    });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (!verification.verified) return res.status(400).json({ error: 'Registration verification failed' });

  registrationChallenges.delete(username);
  const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
  credentialStore.set(username, {
    credentialID,
    credentialPublicKey,
    counter,
    transports: req.body.response?.transports || [],
  });
  res.json({ verified: true, credentialID: Buffer.from(credentialID).toString('base64url') });
});

app.post('/api/auth/begin', async (_req, res) => {
  const options = await generateAuthenticationOptions({
    rpID: 'localhost',
    userVerification: 'required',
    timeout: 60000,
  });

  const challengeKey = crypto.randomBytes(16).toString('hex');
  authChallenges.set(challengeKey, { challenge: options.challenge, expiresAt: Date.now() + 5 * 60 * 1000 });
  res.json({ ...options, challengeKey });
});

app.post('/api/auth/complete', async (req, res) => {
  const { challengeKey, ...assertionBody } = req.body;
  const stored = authChallenges.get(challengeKey);
  if (!stored) return res.status(400).json({ error: 'No pending authentication' });
  if (Date.now() > stored.expiresAt) {
    authChallenges.delete(challengeKey);
    return res.status(400).json({ error: 'Authentication challenge expired — try again' });
  }
  // ✅ PROTECTED: single-use challenge
  authChallenges.delete(challengeKey);

  let foundUsername = null;
  let cred = null;
  for (const [username, c] of credentialStore.entries()) {
    if (Buffer.from(c.credentialID).toString('base64url') === assertionBody.id) {
      foundUsername = username;
      cred = c;
      break;
    }
  }
  if (!cred) return res.status(400).json({ error: 'Credential not found — register a passkey first' });

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: assertionBody,
      expectedChallenge: stored.challenge,
      expectedOrigin: 'http://localhost:3075',
      expectedRPID: 'localhost',
      authenticator: {
        credentialID: cred.credentialID,
        credentialPublicKey: cred.credentialPublicKey,
        counter: cred.counter,
        transports: cred.transports,
      },
      requireUserVerification: true,
    });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (!verification.verified) return res.status(400).json({ error: 'Authentication failed' });

  const prev = cred.counter;
  cred.counter = verification.authenticationInfo.newCounter;
  if (verification.authenticationInfo.newCounter > 0 && verification.authenticationInfo.newCounter <= prev) {
    console.warn(`[SECURITY] Counter anomaly for ${foundUsername}: ${prev} -> ${verification.authenticationInfo.newCounter}`);
  }

  const user = USERS.find((u) => u.username === foundUsername);
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token, username: user.username, fullName: user.fullName, authenticatorCounter: cred.counter });
});

app.get('/api/config', (_req, res) => {
  res.json({ mode: 'secure', port: PORT });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`CloudPortal (hardened WebAuthn) running at http://localhost:${PORT}`);
});
