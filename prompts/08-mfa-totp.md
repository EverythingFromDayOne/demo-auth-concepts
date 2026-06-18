# Cursor Prompt — 08: MFA & TOTP
# Ports: 3070 (vulnerable) · 3071 (guide) · 3072 (secure)

Build three Node.js Express servers in `auth-concepts/mfa-totp/` that teach TOTP security.

---

## File structure to create

```
mfa-totp/
  vulnerable-server.js  ← port 3070, vulnerable
  guide-server.js       ← port 3071, guide
  secure-server.js      ← port 3072, secure
  public/
    index.html          ← AuthVault TOTP demo SPA (shared)
    style.css
    guide.html
    guide.css
  package.json
```

---

## package.json

```json
{
  "name": "mfa-totp",
  "scripts": {
    "vulnerable": "node vulnerable-server.js",
    "guide": "node guide-server.js",
    "secure": "node secure-server.js",
    "start": "node vulnerable-server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "speakeasy": "^2.0.0",
    "qrcode": "^1.5.3"
  }
}
```

---

## Shared app: AuthVault (TOTP demo)

**Users:** `alice / pass1234`, `bob / qwerty123` (hardcoded in-memory)

**TOTP setup flow:**
1. User logs in with password → server generates TOTP secret (`speakeasy.generateSecret()`) → returns QR code data URL + secret
2. User scans QR code with authenticator app
3. User verifies with first OTP → TOTP enabled
4. Subsequent logins: password + OTP required

**Secret storage:** in-memory Map `userSecrets`: `username → { secret, enabled: bool }`

**Pending sessions:** in-memory Map for users who passed password but not yet TOTP

---

## vulnerable-server.js (port 3070) — vulnerable

Top comment: `* Terminal 1: cd auth-concepts/mfa-totp && npm install && npm run vulnerable`

**Vulnerabilities:**
1. `window: 10` — accepts OTPs up to ±5 minutes old (20 valid codes at any time)
2. No replay prevention — same OTP can be used multiple times within the window
3. No rate limiting — brute-force possible

```js
const verified = speakeasy.totp.verify({
  secret: userSecret.secret,
  encoding: 'base32',
  token: otp,
  window: 10, // ⚠️ ±5 minutes = 20 valid codes at once
});
// ⚠️ No usedCodes check — OTP reusable within window
// ⚠️ No rate limit — unlimited attempts
```

**Routes:**
- `POST /api/setup` → generate secret + QR → return `{ qrDataUrl, secret }`
- `POST /api/verify-setup` → verify first OTP → mark TOTP enabled
- `POST /api/login` → validate password → if TOTP enabled return `{ pendingSession, requiresOtp: true }` else return token
- `POST /api/verify-otp` → verify OTP (window:10, no replay check) → return access token
- `GET /api/me` — requireAuth → return user
- `GET /api/config` → `{ mode: 'vulnerable', port: 3070 }`
- Static + catch-all → `public/index.html`

---

## secure-server.js (port 3072) — secure

Top comment: `* Terminal 3: cd auth-concepts/mfa-totp && npm run secure`

**Fixes:**
1. `window: 1` — only ±30 seconds (2 valid codes max)
2. `usedCodes` Map — each code accepted only once (replay blocked)
3. Rate limiting — 5 failed OTP attempts → 5-minute lockout per user
4. Single-use backup codes — generated at setup, stored hashed, each usable once
5. Pending session expiry — 5-minute window to complete OTP step

```js
const usedCodes = new Map(); // username → Set of used tokens
const lockouts = new Map();  // username → { attempts, lockedUntil }

// In verify-otp:
const lock = lockouts.get(username);
if (lock?.lockedUntil > Date.now()) return res.status(429).json({ error: 'Too many attempts. Try again in 5 minutes.' });

const verified = speakeasy.totp.verify({
  secret, encoding: 'base32', token: otp, window: 1
});

if (!verified) {
  // increment attempt counter, lock after 5
  return res.status(401).json({ error: 'Invalid OTP' });
}

const used = usedCodes.get(username) || new Set();
if (used.has(otp)) return res.status(401).json({ error: 'OTP already used' });
used.add(otp);
usedCodes.set(username, used);
// reset lockout, issue token
```

**Backup codes:** `crypto.randomBytes(4).toString('hex')` × 8, stored in `userBackupCodes` Map as a Set, single-use (delete on use).

Same routes as vulnerable + `POST /api/use-backup-code`. `GET /api/config` → `{ mode: 'secure', port: 3072 }`.

---

## public/index.html — AuthVault TOTP SPA (shared)

On load:
1. `fetch('/api/config')` → set banner:
   - vulnerable: orange — `⚠ WEAK TOTP: window:10 (±5min), no replay prevention, no rate limit`
   - secure: green — `✅ HARDENED TOTP: window:1 (±30s), single-use codes, 5-attempt lockout, backup codes`

**UI flow:**
- Step 1: Password login form
- Step 2: If `requiresOtp: true` → show OTP input field (6-digit) + "Use backup code" option
- Step 3: On success → show dashboard with "MFA enabled" status

**Setup panel:** "Enable TOTP" button → show QR code + manual secret → OTP verification field

---

## guide-server.js (port 3071) — guide

Top comment: `* Terminal 2: cd auth-concepts/mfa-totp && npm run guide`

Thin static server serving `public/guide.html`.

**`public/guide.html`** — dark terminal-green theme:
- Title: "MFA & TOTP"
- Target switcher: "Vulnerable TOTP (3070)" dark slate, "Hardened TOTP (3072)" green `#16a34a`
- Content: HOTP/TOTP algorithm (HMAC-SHA1, time steps), what `window` means (diagram showing overlapping valid codes), replay attack walkthrough, brute-force of 6-digit code, backup codes purpose, comparison table (vulnerable vs secure config).
