# Cursor Prompt — 10: Magic Links & Passwordless
# Ports: 3076 (vulnerable) · 3077 (guide) · 3078 (secure)

Build three Node.js Express servers in `auth-concepts/magic-links/` that teach magic link token security.

---

## File structure to create

```
magic-links/
  vulnerable-server.js  ← port 3076, vulnerable
  guide-server.js       ← port 3077, guide
  secure-server.js      ← port 3078, secure
  public/
    index.html          ← Inkwell login + dashboard SPA (shared)
    style.css
    guide.html
    guide.css
  package.json
```

---

## package.json

```json
{
  "name": "magic-links",
  "scripts": {
    "vulnerable": "node vulnerable-server.js",
    "guide": "node guide-server.js",
    "secure": "node secure-server.js",
    "start": "node vulnerable-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## Shared app: Inkwell (blogging platform)

**User profiles (in-memory):**
```js
const USER_PROFILES = {
  'alice@example.com': { name: 'Alice Chen', plan: 'pro', posts: [
    { title: 'Getting started with Node.js', status: 'published', views: 1420 },
    { title: 'Understanding JWT auth', status: 'draft', views: 0 },
  ]},
  'bob@example.com': { name: 'Bob Martinez', plan: 'free', posts: [
    { title: 'My first blog post', status: 'published', views: 89 },
  ]},
  'demo@example.com': { name: 'Demo User', plan: 'free', posts: [] },
};
```

**Magic link flow:**
1. User enters email → `POST /api/request-link` → server generates token → "email" shown in response (simulated, no real email)
2. `GET /auth/verify?token=<token>` → validate token → set session cookie → redirect to dashboard
3. Dashboard loads → `GET /api/profile` → render user data

**Token store:** in-memory Map `magicLinks`: `token → { email, expiresAt?, used? }`

**Session store:** in-memory Map `sessions`: `sessionId → { email, createdAt }`

---

## vulnerable-server.js (port 3076) — vulnerable

Top comment: `* Terminal 1: cd auth-concepts/magic-links && npm install && npm run vulnerable`

**Vulnerabilities:**
1. `Math.random()` for token generation — predictable, only ~15 bits of entropy
2. No expiry — token valid indefinitely
3. No single-use — same link can be used multiple times
4. No rate limiting — attacker can request unlimited links
5. Session cookie set without `HttpOnly` or `SameSite`

```js
// ⚠️ Predictable token
const token = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
magicLinks.set(token, { email }); // ⚠️ No expiry, no single-use flag

// ⚠️ Cookie without HttpOnly
res.setHeader('Set-Cookie', `inkwell_session=${sid}; Path=/; SameSite=Lax`);
```

**Routes:**
- `POST /api/request-link` → generate weak token → store → return `{ token, magicLink: '/auth/verify?token='+token }` (simulates email)
- `GET /auth/verify` → find token (no expiry check) → set session → redirect `/dashboard` — token NOT deleted
- `GET /api/me` — requireSession → return `{ email }`
- `GET /api/profile` — requireSession → return `{ email, name, plan, posts }` from USER_PROFILES
- `POST /api/logout` — requireSession → delete session → clear cookie
- `GET /api/config` → `{ mode: 'vulnerable', port: 3076 }`
- `app.use(express.static(path.join(__dirname, 'public')))`
- Catch-all → `res.sendFile('public/index.html')`

---

## secure-server.js (port 3078) — secure

Top comment: `* Terminal 3: cd auth-concepts/magic-links && npm run secure`

**Fixes:**
1. `crypto.randomBytes(32).toString('hex')` — 256 bits of entropy
2. 15-minute expiry
3. Token deleted on use — single-use
4. Rate limiting — max 3 link requests per hour per email
5. Cleanup interval — remove expired tokens every 5 minutes
6. Session cookie with `HttpOnly; SameSite=Lax`

```js
// ✅ Cryptographically random token
const token = require('crypto').randomBytes(32).toString('hex');
const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes
magicLinks.set(token, { email, expiresAt });

// Rate limiting store
const rateLimits = new Map(); // email → { count, windowStart }

// In /api/request-link:
const rl = rateLimits.get(email) || { count: 0, windowStart: Date.now() };
if (Date.now() - rl.windowStart > 3600000) { rl.count = 0; rl.windowStart = Date.now(); }
if (rl.count >= 3) return res.status(429).json({ error: 'Too many requests. Wait 1 hour.' });
rl.count++;
rateLimits.set(email, rl);

// In /auth/verify:
const link = magicLinks.get(token);
if (!link || link.expiresAt < Date.now()) return res.status(400).send('Link expired or invalid');
magicLinks.delete(token); // ✅ Single-use
// Set session with HttpOnly
res.setHeader('Set-Cookie', `inkwell_session=${sid}; Path=/; HttpOnly; SameSite=Lax`);

// Cleanup interval
setInterval(() => {
  for (const [tok, data] of magicLinks) {
    if (data.expiresAt < Date.now()) magicLinks.delete(tok);
  }
}, 5 * 60 * 1000);
```

Same routes as vulnerable + `GET /api/profile`. `GET /api/config` → `{ mode: 'secure', port: 3078 }`.

---

## public/index.html — Inkwell SPA (shared by both servers)

On load:
1. `fetch('/api/config')` → set banner:
   - vulnerable: orange — `⚠ WEAK MAGIC LINK: Math.random() token, no expiry, no single-use, no rate limit`
   - secure: green — `✅ SECURE MAGIC LINK: crypto.randomBytes(32), 15min expiry, single-use, rate-limited`
2. `fetch('/api/me', { credentials: 'same-origin' })` → if 401 show login form; if 200 fetch `/api/profile` and show dashboard

**Login form:**
- Email input → `POST /api/request-link`
- On success: show the magic link inline (simulating email delivery), with "Click to verify" button that navigates to `/auth/verify?token=<token>`

**Dashboard:**
- Header: Inkwell logo, user name + plan, Sign Out button
- Posts table: title, status (badge), views

**Sign Out:** `POST /api/logout` → reload

---

## guide-server.js (port 3077) — guide

Top comment: `* Terminal 2: cd auth-concepts/magic-links && npm run guide`

Thin static server serving `public/guide.html`.

**`public/guide.html`** — dark terminal-green theme:
- Title: "Magic Links & Passwordless"
- Target switcher: "Vulnerable Magic Links (3076)" dark slate, "Hardened Magic Links (3078)" green `#16a34a`
- Content: magic link flow diagram (request → email → click → verify → session), entropy comparison (Math.random ~15 bits vs crypto.randomBytes(32) 256 bits), token lifecycle (expiry, single-use), rate limiting purpose, comparison table.

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

### magic-links

**`magic-links/vulnerable-server.js`** — root causes to annotate:
- `Math.random()` for token generation: `Math.random()` is a pseudo-random number generator seeded from a predictable source. It produces roughly 15 bits of effective entropy when used as shown (`Math.random().toString(36).slice(2)`). Two calls concatenated give ~30 bits — about 1 billion possible tokens. An attacker who can make ~500 million requests, or who can seed the PRNG from observable timing, can predict valid tokens without ever receiving the magic link email.
- No expiry: tokens never expire. An old magic link in a forwarded email, archived inbox, or email provider's server-side scan is a permanently valid authentication credential.
- No single-use enforcement: the token is not deleted after use (`magicTokens.delete(token)` is never called). The same link can be clicked unlimited times by anyone who has it — including the email provider's link-scanner, which clicks links on delivery.
- No rate limiting: an attacker can call `POST /api/request-link` in a tight loop to flood the target's inbox and increase the chance of predicting a token.

**`magic-links/secure-server.js`** — fixes to annotate:
- `crypto.randomBytes(32).toString('hex')`: 256 bits of entropy from the OS CSPRNG. The token space is 2^256 — computationally infeasible to brute-force or predict regardless of how many tokens are observed.
- 15-minute expiry: `expiresAt = Date.now() + 15 * 60 * 1000`. A link in a forwarded or scanned email is useless after 15 minutes. Checked on every verification attempt.
- Single-use: `magicTokens.delete(token)` is called immediately before the session is created. The link cannot be replayed. Email scanner clicks consume the token harmlessly — 15-minute expiry limits the damage window.
- Rate limiting: max 3 link requests per email per hour. Prevents inbox flooding and reduces the surface for token-prediction attacks.

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

### Per-concept README instructions — magic-links (Inkwell)

**`## How It Works`** — keep existing, add token lifecycle diagram:

```
TOKEN LIFECYCLE (hardened):

  POST /api/request-link { email }
          ↓
  [VULNERABLE] token = Math.random().toString(36)... (~30 bits)
  [HARDENED]   token = crypto.randomBytes(32).toString('hex') (256 bits)
          ↓
  magicTokens.set(token, { email, expiresAt: now + 15min })
          ↓
  "Email sent" (console.log in demo) — token shown in response for demo purposes

  GET /auth/verify?token=<token>
          ↓
  Look up token → check expiry
          ↓
  [VULNERABLE] token NOT deleted — reusable forever
  [HARDENED]   magicTokens.delete(token) — single use, before session creation
          ↓
  sessions.set(sid, { email, createdAt })
  Set-Cookie: inkwell_session=<sid>; Path=/; HttpOnly; SameSite=Lax
  302 /dashboard
```

**`## The Vulnerability`** — deepen Math.random() entropy analysis:

```js
// Math.random() uses a PRNG seeded from timing and OS entropy sources.
// Output space for Math.random().toString(36).slice(2): ~15 bits per call
// Two calls concatenated: ~30 bits effective entropy
// ~1,073,741,824 possible tokens

// Compare:
// crypto.randomBytes(32).toString('hex'): 256 bits
// 2^256 ≈ 10^77 possible tokens — not brute-forceable
```

An attacker who observes the server startup time can narrow the seed space.
Tools exist specifically to predict V8's Math.random() output given a starting seed.

Without expiry: tokens issued a year ago in a forwarded email are still valid.
Without single-use: email providers that scan links for malware detection consume the token,
potentially before the intended user clicks it.

**`## Vulnerable Lines`**:
```js
// ⚠️ VULNERABLE — Math.random() PRNG; ~30 bits of entropy; offline predictable
function generateToken() {
  return Math.random().toString(36).slice(2) +
         Math.random().toString(36).slice(2);
}

// ⚠️ VULNERABLE — no expiresAt; token valid indefinitely
magicTokens.set(token, { email: email, createdAt: Date.now() });

// ⚠️ VULNERABLE — token NOT deleted after use; same link works unlimited times
// Email scanners auto-click links on delivery — scanner consumes first session,
// user's click creates a second. Both sessions are valid.
const stored = magicTokens.get(token);
sessions.set(sid, { email: stored.email, createdAt: Date.now() });
// magicTokens.delete(token) ← MISSING

// ⚠️ VULNERABLE — no rate limiting; attacker can flood inbox to exhaust token space
app.post('/api/request-link', function (req, res) {
  const token = generateToken();
  // no rate check
```

**`## Defense Details`**:
- `### Entropy requirement` — 256 bits from CSPRNG. V8's PRNG output is deterministic given the seed; 30-bit space makes brute-force over a network feasible. `crypto.randomBytes(32)` draws from the OS CSPRNG, producing 2^256 possible tokens.
- `### Token expiry` — 15 minutes matches typical user behaviour (open email, click link). Shorter reduces risk but increases friction if the user is distracted.
- `### Delete before session` — token deleted before session is written. If the write fails, no valid session exists. Prevents race-condition replay where two requests arrive simultaneously with the same token.
- `### Same response for all outcomes` — `{ message: "If that email is registered, a link was sent" }` whether the email exists or not. Prevents email enumeration attacks.
- `### Rate limiting` — 3 links per email per hour. Prevents inbox flooding and reduces token-prediction attack surface.

**`## Hardened Demo`**:
1. Open `localhost:3076` — send link to `alice@example.com`, click **Open Link**
2. Click **Open Again (replay)** — second session created — link is not consumed
3. Open `localhost:3078` — send link, click once — authenticated
4. Try the same token again — `invalid_token` — single-use enforced
5. Send a link 4 times to the same email on `localhost:3078` — 4th attempt: rate limited (no demo link in response)
6. Inspect the two token values side-by-side in the demo banner — length and entropy comparison
