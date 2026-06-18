/*
 * SecureVault (weak TOTP) - port 3070
 */
const path = require('path');
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const app = express();
const PORT = 3070;

app.use(cors({ origin: 'http://localhost:3071' }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// ⚠️ DEMO ONLY: plaintext secrets.
const USERS = [
  { username: 'alice', password: 'pass1234', fullName: 'Alice Chen', role: 'user', mfaEnabled: true, totpSecret: 'JBSWY3DPEHPK3PXP' },
  { username: 'bob', password: 'qwerty123', fullName: 'Bob Martinez', role: 'user', mfaEnabled: false, totpSecret: null },
  { username: 'admin', password: 'admin456', fullName: 'Admin User', role: 'admin', mfaEnabled: true, totpSecret: 'JBSWY3DPEHPK3PXP' },
];

const pendingSessions = new Map();
const completedSessions = new Map();

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const session = completedSessions.get(token);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.user = session;
  req.token = token;
  next();
}

// ⚠️ DEMO ONLY: expose current code
app.get('/api/current-totp', (req, res) => {
  const { username } = req.query;
  const user = USERS.find((u) => u.username === username);
  if (!user || !user.mfaEnabled) return res.status(404).json({ error: 'MFA not enabled for this user' });
  const code = speakeasy.totp({ secret: user.totpSecret, encoding: 'base32' });
  const secondsRemaining = 30 - (Math.floor(Date.now() / 1000) % 30);
  res.json({ code, secondsRemaining, note: 'DEMO ONLY — production servers never expose current TOTP codes' });
});

app.get('/api/totp-qr', async (req, res) => {
  const { username } = req.query;
  const user = USERS.find((u) => u.username === username);
  if (!user || !user.mfaEnabled) return res.status(404).json({ error: 'MFA not enabled' });
  const otpauthUrl = `otpauth://totp/SecureVault:${username}?secret=${user.totpSecret}&issuer=SecureVault`;
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
  // ⚠️ DEMO ONLY: returning secret
  res.json({ qrDataUrl, otpauthUrl, secret: user.totpSecret });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find((u) => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  if (!user.mfaEnabled) {
    const token = crypto.randomBytes(32).toString('hex');
    completedSessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
    return res.json({ token, mfaRequired: false });
  }

  const pendingToken = crypto.randomBytes(16).toString('hex');
  pendingSessions.set(pendingToken, { username: user.username, expiresAt: Date.now() + 5 * 60 * 1000 });
  res.json({ mfaRequired: true, pendingToken });
});

app.post('/api/verify-totp', (req, res) => {
  const { pendingToken, code } = req.body;
  const pending = pendingSessions.get(pendingToken);
  if (!pending) return res.status(401).json({ error: 'No pending session — log in again' });
  const user = USERS.find((u) => u.username === pending.username);

  // ⚠️ VULNERABLE — window:10 accepts TOTP codes from ±5 minutes (20 valid codes at once).
  // No replay prevention: same OTP can be submitted multiple times within the window.
  // No rate limiting: attacker can brute-force 1,000,000 six-digit codes; with 20 valid at
  // any moment, success in ~50,000 attempts on average without lockout.
  const valid = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token: String(code || ''),
    window: 10,
  });

  if (!valid) return res.status(401).json({ error: 'Invalid TOTP code' });

  pendingSessions.delete(pendingToken);
  const token = crypto.randomBytes(32).toString('hex');
  completedSessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token });
});

// ⚠️ VULNERABLE — debug endpoint exposes TOTP secret in API response.
// Production servers never return totpSecret; attacker with API access can generate valid codes forever.
app.get('/api/debug/totp-secret', (req, res) => {
  const { username } = req.query;
  const user = USERS.find((u) => u.username === username);
  if (!user || !user.mfaEnabled) return res.status(404).json({ error: 'User not found or MFA disabled' });
  res.json({
    username,
    totpSecret: user.totpSecret,
    otpauthUrl: `otpauth://totp/SecureVault:${username}?secret=${user.totpSecret}&issuer=SecureVault`,
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: req.user.username, fullName: req.user.fullName, role: req.user.role });
});

app.get('/api/vault', requireAuth, (req, res) => {
  res.json([
    { id: 1, site: 'github.com', username: 'alice@dev.io', passwordPreview: '••••••••' },
    { id: 2, site: 'aws.amazon.com', username: 'alice', passwordPreview: '••••••••' },
    { id: 3, site: 'stripe.com', username: 'alice@dev.io', passwordPreview: '••••••••' },
  ]);
});

app.post('/api/logout', requireAuth, (req, res) => {
  completedSessions.delete(req.token);
  res.json({ message: 'Logged out' });
});

app.get('/api/config', (_req, res) => {
  res.json({ mode: 'vulnerable', port: PORT });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`SecureVault (weak TOTP) running at http://localhost:${PORT}`);
});
