# JWT & Bearer Token — AuthFlow Demo

AuthFlow is a task management API that demonstrates stateless JWT authentication: login issues a signed token, and every API call verifies the signature without a database lookup.

## How It Works

```
POST /api/login { username, password }
        ↓
Server: jwt.sign({ sub, username, role, iat, exp }, JWT_SECRET, { algorithm: 'HS256' })
        ↓
Returns: { token: "eyJ...", tokenType: "Bearer" }
        ↓
Client stores token (in memory for this demo)
        ↓
GET /api/tasks
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjEsI...
        ↓
Server: jwt.verify(token, JWT_SECRET) → decoded claims
        ↓
No database lookup — user identity is in the token itself
```

## JWT structure

```
header.payload.signature
  │       │         │
  │       │         └─ HMAC-SHA256(header + "." + payload, secret)
  │       └─ base64url({ sub, username, role, iat, exp })
  └─ base64url({ alg: "HS256", typ: "JWT" })
```

## Vulnerability (port 3058)

`JWT_SECRET = 'secret'` — brute-forceable. See `demo-attacked/jwt-attacks/` for the full attack demo.

## Run the demo

```bash
cd auth-concepts/jwt-bearer
npm install
npm run weak    # terminal 1 → localhost:3058
npm run guide   # terminal 2 → localhost:3059
npm run strong  # terminal 3 → localhost:3060
```

## Walkthrough

1. Login at **localhost:3058** — observe the three-part JWT (header, payload, signature)
2. Open **localhost:3059** — paste the JWT into the decoder, see claims in plain JSON
3. Use the live API test buttons to call `/api/me`, `/api/tasks`, `/api/admin/users`
4. Compare **localhost:3060** — same structure, 64-byte secret, 15-minute expiry, HS256 allowlist

## Ports

| Port | Server | Role |
|------|--------|------|
| 3058 | `jwt-server.js` | Weak secret (`"secret"`), 24h expiry |
| 3059 | `guide-server.js` | Concept guide — decoder + comparison |
| 3060 | `jwt-strong-server.js` | Strong secret, 15m expiry, algorithm whitelist |

## Demo credentials

| Username | Password | Role |
|----------|----------|------|
| alice | pass1234 | user |
| bob | qwerty123 | user |
| admin | admin456 | admin |
