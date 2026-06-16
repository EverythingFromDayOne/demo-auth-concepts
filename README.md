# auth-concepts

Seven authentication mechanisms — how they work, common attack vectors, and secure versions. Each concept runs three servers: **concept demo → guide/explainer → improved version**.

Cursor prompt files only. See `prompts/` — Claude writes `.md` specs, Cursor builds the servers.

---

## Concept Index

| # | Concept | Folder | Ports | Vulnerable Demo | Guide | Secure Version |
|---|---------|--------|-------|-----------------|-------|----------------|
| 1 | Basic & Digest Auth | `basic-digest/` | 3049–3051 | HTTP Basic, base64 credentials | Decoder + comparison | Session token replacement |
| 2 | Session Auth | `session/` | 3052–3054 | Cookie without HttpOnly | Cookie attributes | HttpOnly + SameSite=Strict |
| 3 | API Key Auth | `api-key/` | 3055–3057 | API key in URL param | Exposure vectors | API key in Authorization header |
| 4 | JWT & Bearer | `jwt-bearer/` | 3058–3060 | Weak HS256 secret | JWT structure visualizer | Strong secret + short expiry |
| 5 | Access + Refresh Tokens | `access-refresh/` | 3061–3063 | No token rotation | Token lifecycle | Rotation + revocation |
| 6 | SSO | `sso/` | 3064–3066 | Open redirect_uri | IdP flow diagram | Strict allowlist |
| 7 | OAuth2 & OIDC | `oauth2-oidc/` | 3067–3069 | Missing state param | Auth code flow | state + PKCE |

---

## Port Reference

| Port | Server | Role |
|------|--------|------|
| 3049 | `basic-digest/basic-server.js` | HTTP Basic Auth (WWW-Authenticate) |
| 3050 | `basic-digest/guide-server.js` | Guide: base64 decoder + comparison table |
| 3051 | `basic-digest/session-server.js` | Improved: session token via Authorization: Bearer |
| 3052 | `session/session-server.js` | Session auth — cookie without HttpOnly |
| 3053 | `session/guide-server.js` | Guide: cookie attributes + lifecycle |
| 3054 | `session/session-hardened-server.js` | Hardened: HttpOnly + SameSite=Strict |
| 3055 | `api-key/apikey-url-server.js` | API key in URL query param (key in logs) |
| 3056 | `api-key/guide-server.js` | Guide: 5 exposure vectors + comparison |
| 3057 | `api-key/apikey-header-server.js` | Improved: API key in Authorization header |
| 3058 | `jwt-bearer/jwt-server.js` | JWT with weak secret ("secret"), 24h expiry |
| 3059 | `jwt-bearer/guide-server.js` | Guide: JWT decoder + claims + comparison |
| 3060 | `jwt-bearer/jwt-strong-server.js` | Hardened: 64-byte secret, 15m expiry, HS256 allowlist |
| 3061 | `access-refresh/flow-server.js` | Refresh token — no rotation, never expires |
| 3062 | `access-refresh/guide-server.js` | Guide: token lifecycle + rotation diagram |
| 3063 | `access-refresh/flow-strong-server.js` | Hardened: rotation + reuse detection + revocation |
| 3064 | `sso/sso-server.js` | SSO — unvalidated redirect_uri (open redirect) |
| 3065 | `sso/guide-server.js` | Guide: IdP/SP flow + attack + allowlist |
| 3066 | `sso/sso-strong-server.js` | Hardened: exact redirect_uri allowlist |
| 3067 | `oauth2-oidc/oauth-server.js` | OAuth2/OIDC — missing state parameter (CSRF) |
| 3068 | `oauth2-oidc/guide-server.js` | Guide: auth code flow + PKCE + OIDC claims |
| 3069 | `oauth2-oidc/oauth-strong-server.js` | Hardened: state + PKCE (code_challenge/verifier) |

---

## Attack / Concept Flows

### 1. Basic & Digest Auth

```
Client                          Server (port 3049)
  │                                    │
  ├── GET /protected ─────────────────→│
  │                                    │ 401 WWW-Authenticate: Basic realm="..."
  │←── 401 ────────────────────────────┤
  │
  │   Browser shows native dialog
  │   User enters: alice / pass1234
  │
  ├── GET /protected ─────────────────→│
  │   Authorization: Basic YWxpY2U6c3Vuc2hpbmU5OQ==
  │   (base64 of "alice:pass1234" — not encrypted!)
  │                                    │ atob("YWxpY2U6c3Vuc2hpbmU5OQ==") → "alice:pass1234"
  │←── 200 + content ──────────────────┤

Vulnerability: credentials sent on EVERY request in base64 (not encryption!)
Fix: replace with session token or JWT — credentials sent once, token used thereafter
```

### 2. Session Auth

```
POST /api/login { username, password }
        ↓
sessions.set("a3f9b2c1...", { username: "alice" })
        ↓
Port 3052: Set-Cookie: nk_session=a3f9b2c1...; Path=/; SameSite=Lax
           → document.cookie = "nk_session=a3f9b2c1..."  ← XSS can steal this!

Port 3054: Set-Cookie: nk_session=a3f9b2c1...; Path=/; HttpOnly; SameSite=Strict
           → document.cookie = ""  ← JS cannot see the token
```

### 3. API Key Auth

```
Port 3055 (URL param — VULNERABLE):
  GET /api/weather?api_key=sk_live_alice_a3f9b2c1...
  → Appears in: server logs, browser history, Referer header, CDN logs

Port 3057 (Header — SECURE):
  GET /api/weather
  Authorization: Bearer sk_live_alice_a3f9b2c1...
  → Clean URLs, key not in logs
```

### 4. JWT & Bearer

```
POST /api/login → jwt.sign({ sub, username, role }, secret, { expiresIn: '15m' })
                → Returns: eyJhbGciOiJIUzI1NiJ9.<payload>.<signature>

Three parts (dot-separated, base64url encoded):
  Header:    { "alg": "HS256", "typ": "JWT" }
  Payload:   { "sub": 1, "username": "alice", "role": "user", "exp": ... }
  Signature: HMAC-SHA256(header + "." + payload, secret)

GET /api/tasks
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
  → Server: jwt.verify(token, secret) → decoded claims (no DB lookup)

Vulnerability (port 3058): secret = "secret" — brute-forceable
Fix (port 3060): secret = crypto.randomBytes(64), expiresIn = '15m', algorithms: ['HS256']
```

### 5. Access + Refresh Tokens

```
Login → { accessToken (15 min JWT), refreshToken (7 days opaque) }

Normal flow:
  GET /api/resource + Authorization: Bearer <accessToken>
  → 200 (if access token valid)
  → 401 (if expired) → POST /api/refresh + refreshToken → new accessToken

Port 3061 (VULNERABLE — no rotation):
  refreshToken "abc" used → new accessToken → "abc" still valid forever
  Stolen "abc" → attacker gets access tokens indefinitely

Port 3063 (HARDENED — rotation):
  refreshToken "abc" used → new accessToken + new refreshToken "xyz" → "abc" deleted
  Stolen "abc" used → reuse detected → ENTIRE family revoked → force re-login
```

### 6. SSO (Single Sign-On)

```
User → WorkHub (SP) → redirect to CorpID (IdP)
Port 3064 (VULNERABLE — open redirect):
  /auth/authorize?client_id=workhub&redirect_uri=http://ATTACKER.COM/steal&state=x
  → User logs in → assertion token sent to attacker.com
  → Attacker uses token: /callback?token=<stolen> → logged in as victim

Port 3066 (HARDENED — allowlist):
  redirect_uri must exactly match registered URI for client_id
  Unregistered URI → 400 Bad Request before login form shown
```

### 7. OAuth2 & OIDC

```
Authorization Code Flow:
  1. ConnectApp → /auth/authorize?...&state=abc123&code_challenge=SHA256(verifier)
  2. User logs in + approves scopes
  3. GrantID → /callback?code=xyz789&state=abc123
  4. ConnectApp verifies state === 'abc123' (CSRF check)
  5. POST /auth/token { code, code_verifier } → { access_token, id_token }

Port 3067 (VULNERABLE — no state):
  CSRF: trick victim into loading /callback?code=ATTACKER_CODE
  → Victim's ConnectApp linked to attacker's GitBucket account

Port 3069 (HARDENED — state + PKCE):
  state = crypto.randomBytes(16) → verified in callback
  code_verifier secret → code_challenge = SHA256(verifier) sent with /authorize
  Even stolen code → can't exchange without code_verifier
```

---

## Usage

Each folder is independent. Run three terminals per concept:

```bash
# Example: JWT & Bearer (ports 3058-3060)
cd auth-concepts/jwt-bearer
npm install
npm run weak    # localhost:3058 — weak secret demo
npm run guide   # localhost:3059 — concept guide
npm run strong  # localhost:3060 — hardened version
```

## Prerequisites

Node.js 18+. Each folder has its own `package.json`. Run `npm install` in each before starting.

## Relation to demo-attacked/

`demo-attacked/` (ports 3001–3048) covers web security attack techniques (XSS, SQLi, CSRF, IDOR, etc.).  
`auth-concepts/` (ports 3049–3069) covers authentication MECHANISMS — how different auth approaches work and their tradeoffs.
