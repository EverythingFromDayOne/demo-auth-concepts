# JWT & Bearer Token — AuthFlow

AuthFlow is a task management API that demonstrates stateless JWT authentication: login issues a signed token, and every API call verifies the signature without a database lookup.

---

## Port Reference

| Port | File | Role |
|------|------|------|
| 3058 | `jwt-server.js` | Vulnerable — weak secret (`"secret"`), 24h expiry |
| 3059 | `guide-server.js` | Concept guide — decoder + comparison |
| 3060 | `jwt-strong-server.js` | Hardened — 512-bit secret, 15m expiry, algorithm allowlist |

---

## How It Works

```
LOGIN:
  POST /api/login { username, password }
          ↓
  jwt.sign({ sub, username, role, iat }, JWT_SECRET, { expiresIn })
          ↓
  Returns: { token: "eyJhbGci....<signature>" }

SUBSEQUENT REQUESTS:
  Authorization: Bearer eyJhbGci....<signature>
          ↓
  jwt.verify(token, JWT_SECRET)  ← no database lookup
          ↓
  Decoded payload: { sub: 1, username: "alice", role: "user", exp: ... }
```

JWT structure:

```
header.payload.signature
  │       │         │
  │       │         └─ HMAC-SHA256(header + "." + payload, secret)
  │       └─ base64url({ sub, username, role, iat, exp })
  └─ base64url({ alg: "HS256", typ: "JWT" })
```

No database lookup — user identity is in the token itself.

---

## The Vulnerability

`JWT_SECRET = 'secret'` — brute-forceable. See `demo-attacked/jwt-attacks/` for the full attack demo.

```
JWT_SECRET = 'secret'

Attacker captures any JWT (from Network tab, from a log file).
Runs: jwt-cracker <captured-token>  or  hashcat -a 0 -m 16500 token.txt wordlist.txt

Wordlist entry: "secret"
HMAC-SHA256("eyJhbGci...eyJzdWIi", "secret") === captured_signature? → YES

Time to crack "secret": < 1 second.
```

Once the secret is known, the attacker calls `jwt.sign({ sub: 3, username: 'admin', role: 'admin' }, 'secret')` locally.
The forged token passes `jwt.verify()` on the server — the admin endpoint is now open.

---

## The Fix

The hardened server (port 3060) uses a 512-bit random signing key, 15-minute token expiry, and explicit `{ algorithms: ['HS256'] }` in `jwt.verify()`. A stolen token has a short damage window; brute-forcing the secret is infeasible; and algorithm confusion attacks (`alg: none`) are rejected.

---

## How to Run

```bash
cd auth-concepts/jwt-bearer
npm install
npm run vulnerable  # terminal 1 → localhost:3058
npm run guide       # terminal 2 → localhost:3059
npm run secure      # terminal 3 → localhost:3060
```

---

## Demo Walkthrough

1. Login at **localhost:3058** as `alice` / `pass1234` — observe the three-part JWT (header, payload, signature) in the login response.
2. Copy the token and decode the payload (base64url middle segment, or use **localhost:3059** decoder) — see `role: "user"` in plain JSON.
3. Call `/api/admin/users` with the token — rejected because `role` is `user`, not `admin`. The claims in the payload directly control authorization.

---

## Hardened Demo

1. Open `localhost:3058` — login, copy the JWT from the response
2. Go to [jwt.io](https://jwt.io) — decode it; see `role: "user"` in payload
3. Change `role` to `"admin"` in the payload editor, hit **Encode** — the signature changes because jwt.io doesn't know the secret
4. Paste the tampered token into the **Manual Token Test** on the demo — `jwt.verify()` rejects it
5. Open `localhost:3060` — same flow — try `jwt-cracker` against the token; 512-bit key is not crackable

---

## Vulnerable Lines

```js
// ⚠️ VULNERABLE — dictionary word as HMAC-SHA256 key; top entry in every JWT wordlist
const JWT_SECRET = 'secret';

// ⚠️ VULNERABLE — 24-hour expiry; a stolen token grants a full day of access
// No server-side session exists to invalidate — only rotating JWT_SECRET helps,
// which invalidates every active session simultaneously.
const JWT_EXPIRES_IN = '24h';
```

---

## Defense Details

### Secret strength

The hardened server generates a 512-bit (64-byte) random key via `crypto.randomBytes(64)`. Dictionary and wordlist attacks that crack `"secret"` in under a second require testing 2^512 possible keys — computationally infeasible. In production, store the secret in an environment variable or secrets manager, not in source code.

### Short expiry + refresh tokens

A 15-minute access token limits the damage window if a token is stolen from logs, DevTools, or a compromised device. Stateless JWTs cannot be revoked mid-life — the server has no session record to delete. Short expiry is the primary mitigation; refresh tokens (see the access-refresh concept) provide renewal without long-lived bearer tokens.

### Algorithm allowlisting

Passing `{ algorithms: ['HS256'] }` to `jwt.verify()` prevents the `alg: none` attack: an attacker sets `"alg": "none"` in the header, strips the signature, and an unguarded verifier accepts the unsigned payload. Explicit allowlisting rejects any algorithm not on the list.

---

## Credentials

| Username | Password | Role |
|----------|----------|------|
| alice | pass1234 | user |
| bob | qwerty123 | user |
| admin | admin456 | admin |
