/*
 * CloudPortal (weak WebAuthn) - port 3073
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
const PORT = 3073;

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
  res.json({ username: req.user.username, fullName: req.user.fullName, role: req.user.role, hasPasskey: credentialStore.has(req.user.username) });
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
  const options = await generateRegistrationOptions({
    rpName: 'CloudPortal',
    rpID: 'localhost',
    // ⚠️ VULNERABLE — userID embeds username directly (PII leakage in WebAuthn credential).
    // Discoverable credentials may expose username to any site that triggers the authenticator.
    userID: Buffer.from(username),
    userName: username,
    userDisplayName: fullName,
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      // ⚠️ VULNERABLE — userVerification discouraged; no PIN/biometric required.
      // Physical access to unlocked device is sufficient to register and use a passkey.
      userVerification: 'discouraged',
    },
    timeout: 60000,
    // ⚠️ VULNERABLE — no excludeCredentials; user can register duplicate credentials.
    // Without excludeCredentials, the authenticator may create multiple credentials for the same user.
    // Attacker with session access can register additional passkeys and retain access after password change.
  });

  // ⚠️ VULNERABLE — challenge does not expire; stored indefinitely in registrationChallenges Map.
  // Replay: same challenge can authenticate multiple registration attempts.
  registrationChallenges.set(username, { challenge: options.challenge });
  res.json(options);
});

app.post('/api/register/complete', requireAuth, async (req, res) => {
  const { username } = req.user;
  const stored = registrationChallenges.get(username);
  if (!stored) return res.status(400).json({ error: 'No pending registration' });

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: stored.challenge,
      expectedOrigin: 'http://localhost:3073',
      expectedRPID: 'localhost',
      // ⚠️ VULNERABLE — requireUserVerification:false allows registration without PIN/biometric.
      requireUserVerification: false,
    });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (!verification.verified) return res.status(400).json({ error: 'Registration verification failed' });

  // ⚠️ VULNERABLE — challenge not deleted after successful registration; can be replayed.
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
    // ⚠️ VULNERABLE — userVerification discouraged on authentication; device presence only.
    userVerification: 'discouraged',
    timeout: 60000,
  });

  // ⚠️ VULNERABLE — one global 'auth' challenge slot shared by all users; never expires or rotates.
  authChallenges.set('auth', { challenge: options.challenge });
  res.json(options);
});

app.post('/api/auth/complete', async (req, res) => {
  const stored = authChallenges.get('auth');
  if (!stored) return res.status(400).json({ error: 'No pending authentication' });

  let foundUsername = null;
  let cred = null;
  for (const [username, c] of credentialStore.entries()) {
    if (Buffer.from(c.credentialID).toString('base64url') === req.body.id) {
      foundUsername = username;
      cred = c;
      break;
    }
  }
  if (!cred) return res.status(400).json({ error: 'Credential not found — register a passkey first' });

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: stored.challenge,
      expectedOrigin: 'http://localhost:3073',
      expectedRPID: 'localhost',
      authenticator: {
        credentialID: cred.credentialID,
        credentialPublicKey: cred.credentialPublicKey,
        counter: cred.counter,
        transports: cred.transports,
      },
      // ⚠️ VULNERABLE — requireUserVerification:false; stolen device can authenticate without biometric.
      requireUserVerification: false,
    });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (!verification.verified) return res.status(400).json({ error: 'Authentication failed' });

  // ⚠️ VULNERABLE — authenticator counter NOT updated; cloned credentials undetectable.
  // ⚠️ VULNERABLE — challenge NOT deleted; captured signed response can be replayed while challenge exists.
  const user = USERS.find((u) => u.username === foundUsername);
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token, username: user.username, fullName: user.fullName });
});

app.get('/api/debug/credential', (req, res) => {
  const { username } = req.query;
  const cred = credentialStore.get(username);
  if (!cred) return res.status(404).json({ error: 'No passkey registered for this user' });
  // ⚠️ VULNERABLE — debug endpoint exposes stable credentialID for targeted phishing/tracking.
  res.json({
    username,
    credentialID: Buffer.from(cred.credentialID).toString('base64url'),
    counter: cred.counter,
    transports: cred.transports,
  });
});

app.get('/api/config', (_req, res) => {
  res.json({ mode: 'vulnerable', port: PORT });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`CloudPortal (weak WebAuthn) running at http://localhost:${PORT}`);
});
