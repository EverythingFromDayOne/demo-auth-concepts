# Cursor Prompt — 05: Access + Refresh Tokens
# Ports: 3061 (vulnerable) · 3062 (guide) · 3063 (secure)

Build three Node.js Express servers in `auth-concepts/access-refresh/` that teach refresh token rotation.

---

## File structure to create

```
access-refresh/
  flow-server.js        ← port 3061, vulnerable
  guide-server.js       ← port 3062, guide
  flow-strong-server.js ← port 3063, secure
  public/
    index.html          ← dashboard SPA (shared)
    style.css
    guide.html
    guide.css
  package.json
```

---

## package.json

```json
{
  "name": "access-refresh",
  "scripts": {
    "vulnerable": "node flow-server.js",
    "guide": "node guide-server.js",
    "secure": "node flow-strong-server.js",
    "start": "node flow-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5", "jsonwebtoken": "^9.0.0" }
}
```

---

## Token design (both servers)

- **Access token:** JWT, short-lived (15 min). Payload: `{ sub, username, type: 'access' }`.
- **Refresh token:** opaque `crypto.randomBytes(32).toString('hex')`, stored in server-side Map.
- **Login returns:** `{ accessToken, refreshToken, expiresIn: 900 }`.

---

## flow-server.js (port 3061) — vulnerable

Top comment: `* Terminal 1: cd auth-concepts/access-refresh && npm install && npm run vulnerable`

**Vulnerability:** refresh tokens are never rotated. A stolen refresh token grants indefinite access.

**In-memory store:** `const refreshTokens = new Map(); // token → { username, createdAt }`

**Routes:**
- `POST /api/login` → issue accessToken + refreshToken, store in Map
- `POST /api/refresh` → if token in Map → issue new accessToken, **old refresh token kept valid** → return `{ accessToken }`
- `GET /api/resource` — requireAccess → return `{ data: '...', user: req.user }`
- `POST /api/logout` → delete refresh token from Map
- `GET /api/config` → `{ mode: 'vulnerable', port: 3061 }`
- Static + catch-all → `public/index.html`

---

## flow-strong-server.js (port 3063) — secure

Top comment: `* Terminal 3: cd auth-concepts/access-refresh && npm run secure`

**Fix:** refresh token rotation + reuse detection. Every use of a refresh token issues a new one and invalidates the old one. Reuse of an invalidated token revokes the entire family.

**Token family tracking:**
```js
// familyId groups tokens from same login session
// usedTokens Set tracks consumed tokens (for reuse detection)
const tokenFamilies = new Map(); // familyId → Set of valid tokens
const usedTokens = new Set();
```

**`POST /api/refresh` logic:**
1. If token in `usedTokens` → REUSE DETECTED → revoke entire family → 401
2. If token valid → mark old token as used → issue new accessToken + new refreshToken in same family → return both

**Routes:** same as vulnerable + rotation logic. `GET /api/config` → `{ mode: 'secure', port: 3063 }`.

---

## public/index.html — Token Flow Dashboard SPA (shared)

On load:
1. `fetch('/api/config')` → set banner:
   - vulnerable: orange — `⚠ NO ROTATION: refresh tokens never expire. A stolen token grants indefinite access.`
   - secure: green — `✅ TOKEN ROTATION: each refresh issues a new token. Reuse detection revokes the entire session family.`

**UI panels:**
- Login button → show accessToken (decoded) + refreshToken (truncated)
- Token status: access token expiry countdown, refresh token status
- "Use Resource" button → `GET /api/resource` with accessToken
- "Refresh Tokens" button → `POST /api/refresh` → update displayed tokens
- "Simulate Stolen Token" button (vulnerable mode): allow pasting an old refresh token and show it still works
- Token timeline visualization showing rotation vs no-rotation

---

## guide-server.js (port 3062) — guide

Top comment: `* Terminal 2: cd auth-concepts/access-refresh && npm run guide`

Thin static server serving `public/guide.html`.

**`public/guide.html`** — dark terminal-green theme:
- Title: "Access + Refresh Tokens"
- Target switcher: "Vulnerable Flow (3061)" dark slate, "Hardened Flow (3063)" green `#16a34a`
- Content: token lifecycle diagram (login → access → refresh → new access), why access tokens expire, what refresh token rotation prevents, reuse detection flow, family revocation on reuse, comparison table.

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

### access-refresh

**`access-refresh/flow-server.js`** — root causes to annotate:
- Weak signing secrets (`'access-secret-weak'`): same brute-force risk as jwt-bearer.
- No refresh token rotation: each call to `/api/refresh` issues a new access token but keeps the old refresh token valid. If a refresh token is stolen, the attacker can silently refresh indefinitely — the legitimate user and the attacker both have valid sessions simultaneously, with no signal that anything is wrong.
- No refresh token expiry: a stolen refresh token grants permanent access unless the user explicitly logs out or the secret rotates.
- No token family tracking: token theft is invisible. There is no mechanism to detect that two parties are using the same refresh token.

**`access-refresh/flow-strong-server.js`** — fixes to annotate:
- Refresh token rotation: every `/api/refresh` call invalidates the old refresh token and issues a new one. A stolen token can only be used once — the moment the attacker uses it, the legitimate user's next refresh fails, alerting them (or the system) to the compromise.
- Token family revocation: each login creates a "family" (linked list of refresh tokens). If an already-used token is presented, the entire family is revoked — all sessions for that login event are destroyed. This detects token theft even when the attacker refreshes before the legitimate user does.
- Refresh token expiry (7 days): long-lived but bounded. Silent refresh within the window; re-login required after.

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

### Per-concept README instructions — access-refresh (FlowAPI)

**`## How It Works`** — expand with token lifecycle:

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

**`## The Vulnerability`** — expand with token theft scenario:

Without rotation, a stolen refresh token is permanently valid:

```
1. Attacker captures refresh cookie from alice's browser (via malware, XSS, or compromised device)
2. alice continues using the app normally — her refresh token works fine
3. Attacker also calls POST /api/refresh with stolen token → gets a fresh access token
4. Both alice and attacker have valid sessions. Neither has any signal of compromise.
5. alice logs out → her session ends, but the stolen refresh token is unaffected
6. Attacker continues refreshing indefinitely
```

**`## Vulnerable Lines`**:
```js
// ⚠️ VULNERABLE — weak signing secret; brute-forceable (same risk as jwt-bearer)
const ACCESS_SECRET = 'access-secret-weak';

// ⚠️ VULNERABLE — refresh tokens stored in Map but never rotated or expired
// Stolen token grants permanent silent access; no server-side signal of compromise
const refreshTokenStore = new Map();

// In POST /api/refresh:
// ⚠️ VULNERABLE — old token not deleted; attacker and victim can both refresh indefinitely
const newToken = crypto.randomBytes(32).toString('hex');
refreshTokenStore.set(newToken, { userId: stored.userId });
// stored token is never deleted
```

**`## Defense Details`**:
- `### Refresh token rotation` — each refresh call consumes the old token and issues a new one. One token = one use. A stolen token can only be used once before the legitimate user's next refresh exposes the compromise.
- `### Token family and reuse detection` — family IDs link tokens from the same login event. Reuse of a rotated token revokes the entire family — forcing re-login for both parties. The compromise surfaces even if the attacker refreshes first.
- `### Password change revocation` — changing a password should revoke all refresh tokens: standard response to suspected credential compromise.

**`## Hardened Demo`**:
1. Open `localhost:3063` — login as `alice / pass1234`, note the refresh cookie in DevTools
2. Call `POST /api/refresh` — new access token issued, refresh cookie replaced with a new token
3. Try `POST /api/refresh` again with the **old** cookie value (set it manually in DevTools) — rejected: `Refresh token reuse detected` — entire family revoked
4. The original session is now invalid; re-login required
5. Login again, then `POST /api/change-password` — all sessions revoked immediately
