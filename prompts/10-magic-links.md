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
