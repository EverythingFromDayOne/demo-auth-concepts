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
