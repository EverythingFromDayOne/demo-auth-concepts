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

---

## Inline Comments

Every `// ⚠️` and `// ✅` comment must answer three questions:

1. **What** is wrong (or fixed)
2. **Why** it is exploitable (or why the fix is safe)
3. **How** the attack works mechanically (step by step)

Format:
```js
// ⚠️ VULNERABLE — <one-line summary>
// <explanation: what is wrong, why it matters, how an attacker exploits it>
// <mechanical detail: what the attacker does step by step, what they gain>
const badThing = ...;

// ✅ PROTECTED — <one-line summary>
// <explanation: what the fix does and why it closes the attack vector>
// <mechanical detail: what would need to be true for this to still fail>
const goodThing = ...;
```

**Never shorten an existing comment. Only expand.**
Annotate **vulnerable servers and secure servers only** — never guide servers.

### mfa-totp

**`mfa-totp/vulnerable-server.js`** — root causes to annotate:
- `window: 10`: TOTP generates a new 6-digit code every 30 seconds. `window: 10` means codes from ±5 minutes around the current time are all valid simultaneously — that's 20 valid codes at any moment. An attacker who captures one code (via shoulder surfing, phishing, or a compromised device) can use it for up to 5 minutes after it appeared on the screen.
- No replay prevention: the same OTP can be submitted multiple times within the window. An attacker who intercepts a valid code can use it as many times as they want until the window closes.
- No rate limiting: an attacker can brute-force the 6-digit space (1,000,000 possible codes) with automated requests. With `window: 10`, 20 codes are valid at any time — brute-force succeeds in ~50,000 attempts on average.

**`mfa-totp/secure-server.js`** — fixes to annotate:
- `window: 1`: only codes within ±30 seconds of the current time are accepted — 2 valid codes maximum. The capture-and-replay window shrinks from 10 minutes to 60 seconds.
- `usedCodes` Set: each accepted OTP is recorded. If the same code is submitted again (even within the window), it is rejected. An intercepted code is single-use.
- Rate limiting with lockout: 5 consecutive failures trigger a 5-minute lockout. Brute-forcing 1,000,000 codes at 5 attempts per 5 minutes would take 694 days — effectively impossible.
- Backup codes: generated at setup as one-time-use alternatives. Stored as a Set; deleted on use. Allows recovery when the authenticator device is lost without degrading primary MFA security.

---

## README

Follow this canonical section order for this concept's `README.md`. Use `---` between every section:

```
# [Concept Name] — [App Name]
(one-paragraph description)
---
## Port Reference
---
## How It Works
---
## The Vulnerability
---
## The Fix
---
## How to Run
---
## Demo Walkthrough
---
## Hardened Demo
---
## Vulnerable Lines
---
## Defense Details
---
## Credentials   ← only if needed; always last
```

**Section rename mappings:**

| Old name | Canonical name |
|----------|----------------|
| `## How it works` | `## How It Works` |
| `## Vulnerability (port XXXX)` | `## The Vulnerability` |
| `## Fix (port XXXX)` | `## The Fix` |
| `## Run the demo` / `## Run` | `## How to Run` |
| `## Walkthrough` | `## Demo Walkthrough` |
| `## Hardened Demo` / `## Protected Demo` | `## Hardened Demo` |
| `## Key concepts` | `## Defense Details` |
| `## Demo credentials` / `## Demo API keys` | `## Credentials` |
| `## Ports` | `## Port Reference` |

**Script names to fix:**

| Old | Correct |
|-----|---------|
| `npm run basic` | `npm run vulnerable` |
| `npm run session` (in basic-digest) | `npm run secure` |
| `npm run url` | `npm run vulnerable` |
| `npm run header` | `npm run secure` |
| `npm run weak` | `npm run vulnerable` |
| `npm run strong` | `npm run secure` |
| `npm run hardened` | `npm run secure` |
| `npm run session` (in session/) | `npm run vulnerable` |

### Per-concept README instructions — mfa-totp (AuthVault)

**`## How It Works`** — expand:

```
SETUP (first time):
  POST /api/setup { username }
          ↓
  speakeasy.generateSecret() → base32 secret
  QR code → user scans with authenticator app
  POST /api/verify-setup { code } → TOTP enabled

LOGIN (two-phase):
  Phase 1: POST /api/login { username, password } → { pendingToken, mfaRequired: true }
  Phase 2: POST /api/verify-totp { pendingToken, code }
          ↓
  speakeasy.totp.verify({ secret, token: code, window: N })
          ↓
  Returns: { token }  (full session)
```

**`## The Vulnerability`** — expand TOTP window and replay mechanics:

```
TOTP generates a new 6-digit code every 30 seconds using:
  code = HOTP(HMAC-SHA1(secret, floor(time / 30)))

window:10 means codes from ±5 minutes around now are all accepted simultaneously.
At any given moment, 20 different codes are valid.

REPLAY ATTACK:
  1. Attacker sees alice enter code 482719 (shoulder surf, phishing page, keylogger)
  2. Alice logs in successfully
  3. 2 minutes later, attacker submits 482719 → speakeasy accepts it (still in window)
  4. Attacker is now authenticated as alice

BRUTE FORCE (no rate limit):
  6-digit code = 1,000,000 possibilities
  With window:10 → 20 codes valid at once
  Expected attempts to succeed: ~50,000
  At 100 req/s → crack in ~8 minutes
```

**`## Vulnerable Lines`**:
```js
// ⚠️ VULNERABLE — window:10 accepts codes ±5 minutes old (20 valid codes simultaneously)
// A captured code stays valid for up to 10 minutes after the attack — plenty of time
const valid = speakeasy.totp.verify({
  secret: user.totpSecret,
  encoding: 'base32',
  token: String(code || ''),
  window: 10,   // ← 20 valid codes at once
});

// ⚠️ VULNERABLE — no usedCodes check; same OTP accepted multiple times within window
// ⚠️ VULNERABLE — no rate limiting; unlimited brute-force attempts possible
if (!valid) return res.status(401).json({ error: 'Invalid TOTP code' });
// no replay check, no attempt counter
```

**`## Defense Details`**:
- `### Window tightening` — window:1 allows ±30 seconds (2 valid codes maximum). Accommodates device clock drift without opening a 10-minute replay window.
- `### Replay prevention` — each accepted code is recorded in a per-user Set. Re-submission is rejected even within the valid window. The Set is naturally bounded as codes age out.
- `### Rate limiting with lockout` — 5 consecutive failures trigger a 5-minute lockout. Brute-forcing 1,000,000 codes at 5 attempts per 5 minutes would take 694 days — effectively impossible.
- `### Backup codes` — 8 single-use codes generated at setup. Stored as a Set; each deleted on use. Provides recovery when authenticator device is lost, without bypassing TOTP for normal logins.

**`## Hardened Demo`**:
1. Open `localhost:3070` — login as `alice / pass1234`, use the helper code from `/api/current-totp?username=alice`
2. On `localhost:3070`: submit the same code a second time → **accepted again** (no replay check)
3. Open `localhost:3072` — login, submit the same code twice → second attempt **rejected**: `OTP already used`
4. Submit wrong codes 5 times on `localhost:3072` → `Too many failed attempts. Try again in 5 minutes.`
5. Use a backup code from the setup panel to bypass the lockout on `localhost:3072`
