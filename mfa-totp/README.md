# MFA & TOTP — SecureVault

SecureVault is a password vault demo that uses two-phase login with TOTP-based MFA for sensitive vault access. It shows how time-based one-time passwords add a second factor — and how misconfigured verification windows, missing replay checks, and absent rate limits undermine that protection.

---

## Port Reference

| Port | File | Role |
|------|------|------|
| 3070 | `vulnerable-server.js` | Vulnerable — `window:10`, no replay tracking, no rate limit |
| 3071 | `guide-server.js` | Concept guide — TOTP math and replay demo |
| 3072 | `secure-server.js` | Hardened — `window:1`, replay prevention, lockout, backup codes |

---

## How It Works

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

Protected API:
  GET /api/vault
  Authorization: Bearer <token>
```

---

## The Vulnerability

```
TOTP generates a new 6-digit code every 30 seconds using:
  code = HOTP(HMAC-SHA1(secret, floor(time / 30)))

window:10 means codes from ±5 minutes around now are all accepted simultaneously.
At any given moment, 20 different codes are valid:
  t-5min: code_1  ← still valid
  t-4min: code_2  ← still valid
  ...
  t-now:  code_11 ← valid (current)
  ...
  t+5min: code_20 ← already valid

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

---

## The Fix

The hardened server on port 3072 tightens the verification window to `window:1` (±30 seconds, two valid codes max), records each accepted OTP in a per-user Set so the same code cannot be reused, locks the account after five failed attempts for five minutes, and generates eight single-use backup codes at setup for device-loss recovery without weakening normal TOTP enforcement.

---

## How to Run

```bash
cd auth-concepts/mfa-totp
npm install
npm run vulnerable  # terminal 1 → localhost:3070
npm run guide       # terminal 2 → localhost:3071
npm run secure      # terminal 3 → localhost:3072
```

---

## Demo Walkthrough

1. Open `http://localhost:3071` and review the TOTP math and replay demo.
2. Open `http://localhost:3070`, login as `alice / pass1234`, and enter the helper code from `GET /api/current-totp?username=alice`.
3. Complete login and access the vault — two-phase auth succeeded.
4. Start a new login flow and re-submit the **same** TOTP code — replay is accepted (no used-code tracking).
5. Login as `bob / qwerty123` on port 3070 — bob has no MFA enabled and receives a full session token immediately after password verification.

---

## Hardened Demo

1. Open `localhost:3070` — login as `alice / pass1234`, use the helper code from `/api/current-totp?username=alice`.
2. On `localhost:3070`: submit the same code a second time → **accepted again** (no replay check).
3. Open `localhost:3072` — login, submit the same code twice → second attempt **rejected**: `OTP already used`.
4. Submit wrong codes 5 times on `3072` → `Too many failed attempts. Try again in 5 minutes.`
5. Use a backup code from the setup panel to bypass the lockout on `3072`.

---

## Vulnerable Lines

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
// ⚠️ VULNERABLE — no rate limiting; unlimited attempts possible
if (!valid) return res.status(401).json({ error: 'Invalid TOTP code' });
// no replay check, no attempt counter
```

---

## Defense Details

### Window tightening

`window:1` allows ±30 seconds (two valid codes). This accommodates device clock drift without opening a 10-minute replay window where twenty codes are simultaneously valid.

### Replay prevention

Each accepted code is recorded in a per-user Set. Re-submission is rejected even within the valid window. The Set is naturally garbage-collected as codes age out.

### Rate limiting with lockout

Five failures per user triggers a five-minute lockout. At five attempts per five minutes, cracking 1,000,000 codes would take 694 days.

### Backup codes

Eight single-use codes are generated at setup. Stored as a Set; each is deleted on use. Provides recovery when the authenticator device is lost, without bypassing TOTP for normal logins.

---

## Credentials

| Username | Password | MFA |
|----------|----------|-----|
| alice | pass1234 | TOTP enabled |
| bob | qwerty123 | Disabled (password only) |

Alice TOTP secret (demo): `JBSWY3DPEHPK3PXP`

```
otpauth://totp/SecureVault:alice?secret=JBSWY3DPEHPK3PXP&issuer=SecureVault
```

Demo helper endpoints (never use in production):

- `GET /api/current-totp?username=alice`
- `GET /api/totp-qr?username=alice`
