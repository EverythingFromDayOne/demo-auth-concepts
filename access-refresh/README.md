# Access & Refresh Tokens — FlowAPI Demo

FlowAPI is a project management API that demonstrates the access token + refresh token pattern: short-lived JWTs for API calls, long-lived opaque refresh tokens to renew them.

## Token relationship

```
ACCESS TOKEN                         REFRESH TOKEN
──────────────────────────────────   ──────────────────────────────────
JWT (signed, self-contained)         Opaque random bytes (crypto.randomBytes)
Short-lived: 15 minutes              Long-lived: 7 days (hardened server)
Used on every API call               Used ONLY at /api/refresh
Stateless: no server lookup          Stateful: stored in server Map
If expired → 401 → use refresh       If expired/stolen → full re-login
```

## The attack (port 3061)

Refresh token never rotates. One stolen token → indefinite access. After `/api/refresh`, the old refresh token still works.

## The fix (port 3063)

Refresh token rotates on every `/api/refresh` call. Old token immediately invalid. Reuse of an old token triggers family revocation. Password change revokes all refresh tokens for the user.

## Run the demo

```bash
cd auth-concepts/access-refresh
npm install
npm run vulnerable  # terminal 1 → localhost:3061
npm run guide       # terminal 2 → localhost:3062
npm run strong      # terminal 3 → localhost:3063
```

## Walkthrough

1. Open **localhost:3061** — login as `alice` / `pass1234`, note both tokens
2. Call **POST /api/refresh** — new access token issued, refresh token unchanged
3. Open **localhost:3062** — use live demo; after refresh, original refresh token still works
4. Open **localhost:3063** — login, refresh rotates token; try reusing old token → reuse detected
5. On **3063**, try **POST /api/change-password** — all sessions revoked

## Ports

| Port | Server | Role |
|------|--------|------|
| 3061 | `flow-server.js` | Vulnerable — no rotation, refresh never expires |
| 3062 | `guide-server.js` | Token lifecycle guide + live demo |
| 3063 | `flow-strong-server.js` | Hardened — rotation + reuse detection + revocation |

## Demo credentials

| Username | Password | Role |
|----------|----------|------|
| alice | pass1234 | user |
| bob | qwerty123 | user |
| admin | admin456 | admin |
