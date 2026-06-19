# Cursor Prompt — 04: JWT & Bearer
# Ports: 3058 (vulnerable) · 3059 (guide) · 3060 (secure)

Build three Node.js Express servers in `auth-concepts/jwt-bearer/` that teach JWT security.

---

## File structure to create

```
jwt-bearer/
  jwt-server.js         ← port 3058, vulnerable
  guide-server.js       ← port 3059, guide
  jwt-strong-server.js  ← port 3060, secure
  public/
    index.html          ← TaskFlow playground SPA (shared)
    style.css
    guide.html
    guide.css
  package.json
```

---

## package.json

```json
{
  "name": "jwt-bearer",
  "scripts": {
    "vulnerable": "node jwt-server.js",
    "guide": "node guide-server.js",
    "secure": "node jwt-strong-server.js",
    "start": "node jwt-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5", "jsonwebtoken": "^9.0.0" }
}
```

---

## Shared app: TaskFlow (task management API)

**Users:** `alice / pass1234`, `bob / qwerty123`

**Tasks data:** 3 sample tasks per user (id, title, status: open/done, dueDate)

---

## jwt-server.js (port 3058) — vulnerable

Top comment: `* Terminal 1: cd auth-concepts/jwt-bearer && npm install && npm run vulnerable`

**Vulnerability:** JWT signed with weak hardcoded secret `"secret"` and 24-hour expiry — brute-forceable offline.

```js
const SECRET = 'secret'; // ⚠️ Weak, hardcoded, brute-forceable
jwt.sign({ sub: user.id, username: user.username, role: 'user' }, SECRET, { expiresIn: '24h' })
```

**JWT verification:** `jwt.verify(token, SECRET)` — no algorithm restriction (accepts `{ algorithms: ['HS256', 'none'] }` — or omit algorithms entirely, leaving `alg:none` attack possible).

**Routes:**
- `POST /api/login` → validate creds → return `{ token: <jwt> }`
- `GET /api/tasks` — `Authorization: Bearer <token>` → requireJWT → return tasks
- `GET /api/me` — requireJWT → return user info
- `GET /api/config` → `{ mode: 'vulnerable', port: 3058 }`
- Static + catch-all → `public/index.html`

---

## jwt-strong-server.js (port 3060) — secure

Top comment: `* Terminal 3: cd auth-concepts/jwt-bearer && npm run secure`

**Fix:** 64-byte random secret generated at startup, 15-minute expiry, strict algorithm allowlist.

```js
const SECRET = require('crypto').randomBytes(64).toString('hex'); // ✅ Strong, ephemeral
jwt.sign({ sub: user.id, username: user.username, role: 'user' }, SECRET, { expiresIn: '15m', algorithm: 'HS256' })
jwt.verify(token, SECRET, { algorithms: ['HS256'] }) // ✅ No alg:none
```

**Routes:** same as vulnerable. `GET /api/config` → `{ mode: 'secure', port: 3060 }`.

---

## public/index.html — TaskFlow playground SPA (shared)

On load:
1. `fetch('/api/config')` → set banner:
   - vulnerable: orange — `⚠ WEAK JWT: signed with "secret" (brute-forceable) and 24h expiry. Paste token at jwt.io to inspect.`
   - secure: green — `✅ STRONG JWT: 64-byte random secret, 15min expiry, HS256 algorithm enforced.`

**UI panels:**
- Login form (username + password) → `POST /api/login` → store token in `sessionStorage`
- Token display: show raw JWT, decoded header + payload (base64 decode in JS)
- Task list: `GET /api/tasks` with stored token → display tasks
- Manual token test: paste any JWT → `GET /api/me` with it → show response

---

## guide-server.js (port 3059) — guide

Top comment: `* Terminal 2: cd auth-concepts/jwt-bearer && npm run guide`

Thin static server serving `public/guide.html`.

**`public/guide.html`** — dark terminal-green theme:
- Title: "JWT & Bearer Auth"
- Target switcher: "Vulnerable JWT (3058)" dark slate, "Hardened JWT (3060)" green `#16a34a`
- Content: JWT structure (header.payload.signature), interactive decoder (paste JWT → see decoded parts), algorithm confusion attack (`alg:none`), weak secret brute-force demo, comparison table (weak vs strong config), best practices (short expiry, strong secret, algorithm pinning, rotate on logout).

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

### jwt-bearer

See the format examples above — they cover jwt-bearer fully. Apply the same depth to any additional `// ⚠️` or `// ✅` lines found in the files.

**`jwt-bearer/jwt-server.js`** — root causes to annotate:
- `JWT_SECRET = 'secret'`: well-known weak HMAC-SHA256 key. An attacker who captures any signed token can run it offline through jwt-cracker, hashcat, or a dictionary attack — no server contact needed, no rate-limit possible. Once the secret is recovered, they can forge any payload (role:'admin', any userId). The server cannot distinguish a forged token from a legitimate one.
- `expiresIn: '24h'`: a stolen token grants access for a full day. No server-side session to invalidate — the only recourse is rotating JWT_SECRET, which invalidates every active session simultaneously.

**`jwt-bearer/jwt-strong-server.js`** — fixes to annotate:
- 512-bit random key generated from CSPRNG at startup. Brute-forcing at 1 billion attempts/second would take longer than the age of the universe. In production, load from JWT_SECRET env var so the key persists across restarts without being hardcoded.
- 15-minute expiry limits the damage window for a stolen token. Pair with refresh token rotation for seamless re-authentication.
- `{ algorithms: ['HS256'] }` in verify() prevents the alg:none attack where a token with no signature passes an unguarded verifier.

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

### Per-concept README instructions — jwt-bearer (TaskFlow)

**`## How It Works`** — expand flow with JWT internals:

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

**`## The Vulnerability`** — expand brute-force mechanics:

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

**`## Vulnerable Lines`**:
```js
// ⚠️ VULNERABLE — dictionary word as HMAC-SHA256 key; top entry in every JWT wordlist
const JWT_SECRET = 'secret';

// ⚠️ VULNERABLE — 24-hour expiry; a stolen token grants a full day of access
// No server-side session exists to invalidate — only rotating JWT_SECRET helps,
// which invalidates every active session simultaneously.
const JWT_EXPIRES_IN = '24h';
```

**`## Defense Details`**:
- `### Secret strength` — 512-bit random key from CSPRNG. Wordlist attacks are infeasible; brute-forcing at 1 billion attempts/second would take longer than the age of the universe.
- `### Short expiry + refresh tokens` — 15-minute access token limits the damage window for a stolen token. Stateless JWTs cannot be revoked mid-life; short expiry is the mitigation. Pair with refresh token rotation (see access-refresh concept).
- `### Algorithm allowlisting` — `{ algorithms: ['HS256'] }` in verify() prevents the `alg:none` attack where a token with no signature passes an unguarded verifier.

**`## Hardened Demo`**:
1. Open `localhost:3058` — login, copy the JWT from the response
2. Go to jwt.io — decode it; see `role: "user"` in payload
3. Change `role` to `"admin"` in the payload editor — the signature changes because jwt.io doesn't know the secret
4. Paste the tampered token into the **Manual Token Test** on the demo — `jwt.verify()` rejects it
5. Open `localhost:3060` — try `jwt-cracker` against the token; 512-bit key is not crackable
