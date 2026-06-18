# Access & Refresh Tokens — FlowAPI

FlowAPI is a project management API that demonstrates the access token + refresh token pattern: short-lived JWTs for API calls, long-lived opaque refresh tokens to renew them without re-entering credentials.

---

## Port Reference

| Port | File | Role |
|------|------|------|
| 3061 | `flow-server.js` | Vulnerable — no rotation, refresh never expires |
| 3062 | `guide-server.js` | Concept guide |
| 3063 | `flow-strong-server.js` | Hardened — rotation + reuse detection + revocation |

---

## How It Works

```
LOGIN:
  POST /api/login { username, password }
          ↓
  access_token  = jwt.sign(..., { expiresIn: '15m' })     ← short-lived JWT
  refresh_token = crypto.randomBytes(32).toString('hex')  ← opaque, stored server-side
          ↓
  Response: { access_token }  +  Set-Cookie: ar_refresh=<token>; HttpOnly

API CALL (access token valid):
  GET /api/projects
  Authorization: Bearer <access_token>
          ↓
  jwt.verify() → OK → response

ACCESS TOKEN EXPIRES (after 15 minutes):
  POST /api/refresh  (refresh token sent via HttpOnly cookie)
          ↓
  [VULNERABLE] old refresh token stays valid → new access token issued
  [HARDENED]   old refresh token deleted + new one issued (rotation)
          ↓
  Response: new { access_token }  +  Set-Cookie: new refresh token
```

Token relationship:

```
ACCESS TOKEN                         REFRESH TOKEN
──────────────────────────────────   ──────────────────────────────────
JWT (signed, self-contained)         Opaque random bytes (crypto.randomBytes)
Short-lived: 15 minutes              Long-lived: 7 days (hardened server)
Used on every API call               Used ONLY at /api/refresh
Stateless: no server lookup          Stateful: stored in server Map
If expired → 401 → use refresh       If expired/stolen → full re-login
```

---

## The Vulnerability

Without rotation, a stolen refresh token is permanently valid:

```
1. Attacker captures refresh cookie from alice's browser (via malware, XSS, or compromised device)
2. alice continues using the app normally — her refresh token works fine
3. Attacker also calls POST /api/refresh with stolen token → gets a fresh access token
4. Both alice and attacker have valid sessions. Neither has any signal of compromise.
5. alice logs out → her session ends, but the stolen refresh token is unaffected
6. Attacker continues refreshing indefinitely
```

Refresh token never rotates on port 3061. One stolen token grants indefinite access. After `/api/refresh`, the old refresh token still works — both the victim and the attacker can refresh in parallel with no server-side signal.

---

## The Fix

Refresh token rotates on every `/api/refresh` call on port 3063. The old token is immediately invalid. Reuse of a previously rotated token triggers family revocation — the entire token chain from that login is burned. Password change revokes all refresh tokens for the user, forcing re-authentication everywhere.

---

## How to Run

```bash
cd auth-concepts/access-refresh
npm install
npm run vulnerable  # terminal 1 → localhost:3061
npm run guide       # terminal 2 → localhost:3062
npm run secure      # terminal 3 → localhost:3063
```

---

## Demo Walkthrough

1. Open **localhost:3061** — login as `alice` / `pass1234`, note both tokens
2. Call **POST /api/refresh** — new access token issued, refresh token unchanged
3. Open **localhost:3062** — use the live demo; after refresh, the original refresh token still works
4. Observe that a stolen refresh cookie would grant the same indefinite access — no rotation, no expiry signal

---

## Hardened Demo

1. Open **localhost:3063** — login as `alice` / `pass1234`, note the refresh cookie in DevTools
2. Call **POST /api/refresh** — new access token issued, refresh cookie replaced with a new token
3. Try **POST /api/refresh** again with the **old** cookie value (set it manually in DevTools) — rejected: `Refresh token reuse detected` — entire family revoked
4. The original session is now invalid; re-login required
5. Login again, then **POST /api/change-password** — all sessions revoked immediately

---

## Vulnerable Lines

```js
// ⚠️ VULNERABLE — weak signing secret; brute-forceable (same risk as jwt-bearer)
const ACCESS_SECRET = 'access-secret-weak';

// ⚠️ VULNERABLE — refresh tokens stored in Map but never rotated or expired
// Stolen token grants permanent silent access; no server-side signal of compromise
const refreshTokenStore = new Map(); // { token → { userId, familyId, createdAt } }

// In POST /api/refresh:
// ⚠️ VULNERABLE — old token not deleted; attacker and victim can both refresh indefinitely
const newToken = crypto.randomBytes(32).toString('hex');
refreshTokenStore.set(newToken, { userId: stored.userId });
// stored token is never deleted
```

---

## Defense Details

### Refresh token rotation

Each refresh call consumes the old token and issues a new one. One token = one use. After rotation, the previous token cannot be used again — limiting the window in which a stolen token is useful.

### Token family and reuse detection

Family IDs link tokens from the same login. Reuse of a rotated token means one of the two parties (legitimate user or attacker) used it first. The server cannot tell which, so it revokes the entire family — forcing re-login for both. The compromise surfaces instead of remaining silent.

### Password change revocation

Changing a password should revoke all refresh tokens for that user. It is the standard response to suspected credential compromise — a single action that invalidates every active session without waiting for tokens to expire.

---

## Credentials

| Username | Password | Role |
|----------|----------|------|
| alice | pass1234 | user |
| bob | qwerty123 | user |
| admin | admin456 | admin |
