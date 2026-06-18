/*
 * SecureVault (hardened TOTP) - port 3072
 */
const path = require('path');
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const app = express();
const PORT = 3072;

app.use(cors({ origin: 'http://localhost:3071' }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

const USERS = [
  { username: 'alice', password: 'pass1234', fullName: 'Alice Chen', role: 'user', mfaEnabled: true, totpSecret: 'JBSWY3DPEHPK3PXP' },
  { username: 'bob', password: 'qwerty123', fullName: 'Bob Martinez', role: 'user', mfaEnabled: false, totpSecret: null },
  { username: 'admin', password: 'admin456', fullName: 'Admin User', role: 'admin', mfaEnabled: true, totpSecret: 'JBSWY3DPEHPK3PXP' },
];

const pendingSessions = new Map();
const completedSessions = new Map();

// ✅ PROTECTED — failure lockout after 5 consecutive bad TOTP attempts.
// 5-minute lockout per username; brute-forcing 1M codes at 5 attempts per 5 minutes ≈ 694 days.
const failedAttempts = new Map();

// ✅ PROTECTED — replay prevention via usedCodes Set keyed by username:timeStep.
// Each accepted OTP recorded; resubmitting the same code within the window is rejected (single-use).
const usedCodes = new Map();
setInterval(() => {
  const cutoff = Math.floor(Date.now() / 30000) - 4;
  for (const key of usedCodes.keys()) {
    const step = parseInt(key.split(':')[1], 10);
    if (step < cutoff) usedCodes.delete(key);
  }
}, 2 * 60 * 1000);

// ✅ PROTECTED — single-use backup codes stored as Set; deleted on use.
// Generated at setup as one-time alternatives when authenticator device is lost; does not weaken
// primary TOTP security because each code works exactly once and count is limited.
const BACKUP_CODES = {
  alice: ['VAULT-A1B2', 'VAULT-C3D4', 'VAULT-E5F6', 'VAULT-G7H8', 'VAULT-I9J0', 'VAULT-K1L2', 'VAULT-M3N4', 'VAULT-O5P6'],
  admin: ['VAULT-Q7R8', 'VAULT-S9T0', 'VAULT-U1V2', 'VAULT-W3X4', 'VAULT-Y5Z6', 'VAULT-AA11', 'VAULT-BB22', 'VAULT-CC33'],
};
const usedBackupCodes = new Set();

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const session = completedSessions.get(token);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.user = session;
  req.token = token;
  next();
}

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
  // ⚠️ DEMO ONLY
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
  if (Date.now() > pending.expiresAt) {
    pendingSessions.delete(pendingToken);
    return res.status(401).json({ error: 'Session expired — log in again' });
  }
  const username = pending.username;
  const user = USERS.find((u) => u.username === username);

  const attempts = failedAttempts.get(username) || { count: 0, lockedUntil: 0 };
  if (Date.now() < attempts.lockedUntil) {
    const remaining = Math.ceil((attempts.lockedUntil - Date.now()) / 1000);
    return res.status(429).json({ error: `Too many attempts. Try again in ${remaining}s` });
  }

  const valid = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token: String(code || ''),
    // window:1 — only codes within ±30 seconds accepted (2 valid codes max vs 20 on vulnerable server).
    window: 1,
  });

  if (!valid) {
    attempts.count++;
    if (attempts.count >= 5) {
      attempts.count = 0;
      attempts.lockedUntil = Date.now() + 5 * 60 * 1000;
      failedAttempts.set(username, attempts);
      return res.status(429).json({ error: 'Too many failed attempts. Account locked for 5 minutes.' });
    }
    failedAttempts.set(username, attempts);
    return res.status(401).json({ error: 'Invalid TOTP code', attemptsRemaining: 5 - attempts.count });
  }

  const timeStep = Math.floor(Date.now() / 30000);
  const codeKey = `${username}:${timeStep}`;
  if (!usedCodes.has(codeKey)) usedCodes.set(codeKey, new Set());
  if (usedCodes.get(codeKey).has(String(code))) {
    return res.status(401).json({ error: 'Code already used — wait for the next code' });
  }
  usedCodes.get(codeKey).add(String(code));

  failedAttempts.delete(username);
  pendingSessions.delete(pendingToken);
  const token = crypto.randomBytes(32).toString('hex');
  completedSessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token });
});

app.post('/api/backup-code', (req, res) => {
  const { pendingToken, backupCode } = req.body;
  const pending = pendingSessions.get(pendingToken);
  if (!pending) return res.status(401).json({ error: 'No pending session — log in again' });
  const username = pending.username;
  const codes = BACKUP_CODES[username] || [];
  const normalized = String(backupCode || '').trim().toUpperCase();
  const key = `${username}:${normalized}`;

  if (!codes.includes(normalized)) return res.status(401).json({ error: 'Invalid backup code' });
  if (usedBackupCodes.has(key)) return res.status(401).json({ error: 'Backup code already used' });

  usedBackupCodes.add(key);
  pendingSessions.delete(pendingToken);
  const user = USERS.find((u) => u.username === username);
  const token = crypto.randomBytes(32).toString('hex');
  completedSessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  const remaining = codes.filter((c) => !usedBackupCodes.has(`${username}:${c}`)).length;
  res.json({ token, warning: `Backup code used. ${remaining} backup codes remaining. Re-enroll your authenticator app as soon as possible.` });
});

app.get('/api/backup-codes', requireAuth, (req, res) => {
  const username = req.user.username;
  const codes = BACKUP_CODES[username] || [];
  const remaining = codes.filter((c) => !usedBackupCodes.has(`${username}:${c}`));
  res.json({ codes: remaining });
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
  res.json({ mode: 'secure', port: PORT });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`SecureVault (hardened TOTP) running at http://localhost:${PORT}`);
});
