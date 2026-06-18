# Cursor Prompt: auth-concepts HTML extraction refactor

Refactor all 10 concepts in `auth-concepts/` to extract inline HTML strings from server files into a `public/` static folder per concept. Replace `res.send(HTML_STRING)` with `express.static` + `res.sendFile`. Add `GET /api/config` to each app server so client-side HTML can self-configure the demo banner.

---

## Rules that apply to every concept

1. Create `<concept>/public/` folder.
2. Extract the main app HTML to `public/index.html`, inline `<style>` to `public/style.css` (linked via `<link rel="stylesheet" href="/style.css">`).
3. Extract guide HTML to `public/guide.html`, guide styles to `public/guide.css`.
4. In every app server (vulnerable + secure), add before all routes:
   ```js
   const path = require('path');
   app.use(express.static(path.join(__dirname, 'public')));
   ```
5. Replace `res.send(LOGIN_HTML)`, `res.send(DASHBOARD_HTML)`, `res.send(PORTAL_HTML)`, `res.send(HTML)`, etc. with:
   ```js
   res.sendFile(path.join(__dirname, 'public', 'index.html'));
   ```
   Add a SPA catch-all AFTER all API routes:
   ```js
   app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
   ```
6. Add this endpoint to every app server (not guide servers):
   ```js
   app.get('/api/config', (_req, res) => {
     res.json({ mode: 'vulnerable', port: PORT }); // or 'secure'
   });
   ```
7. In `public/index.html`, fetch `/api/config` on load to set the demo banner:
   ```js
   fetch('/api/config').then(r => r.json()).then(cfg => {
     const banner = document.getElementById('demo-banner');
     if (cfg.mode === 'vulnerable') {
       banner.style.cssText = 'background:#fffbeb;border-bottom:2px solid #f59e0b;color:#92400e;padding:0.65rem 1.5rem;font-size:0.85rem';
       banner.textContent = '⚠ VULNERABLE: [concept-specific text]';
     } else {
       banner.style.cssText = 'background:#f0fdf4;border-bottom:2px solid #22c55e;color:#166534;padding:0.65rem 1.5rem;font-size:0.85rem';
       banner.textContent = '✅ SECURE: [concept-specific text]';
     }
   });
   ```
   Add `<div id="demo-banner"></div>` at the top of `<body>`.
8. Guide servers become thin static servers:
   ```js
   const path = require('path');
   const express = require('express');
   const app = express();
   app.use(express.static(path.join(__dirname, 'public')));
   app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'guide.html')));
   app.listen(PORT, () => console.log(`Guide at http://localhost:${PORT}`));
   ```
9. For concepts with login + dashboard as two HTML blocks in one server (session, basic-digest/session-server, access-refresh, magic-links): combine into a single `public/index.html` SPA. On page load, call `GET /api/me` — if 401, show the login form div; if 200, show the dashboard div. Only one div is visible at a time via `display:none`.
10. Delete all `const LOGIN_HTML`, `const DASHBOARD_HTML`, `const PORTAL_HTML`, `const HTML`, `const GUIDE_HTML`, `function DASHBOARD_HTML(...)` variable declarations from server files after extracting.

---

## Concept 1: basic-digest/ (ports 3049–3051)

**Files:**
- `basic-server.js` (3049) — vulnerable: HTTP Basic Auth
- `guide-server.js` (3050) — guide
- `session-server.js` (3051) — secure: session token replacement

**Create:**
```
basic-digest/public/
  index.html       ← SimpleDesk dashboard (for basic-server.js)
  style.css        ← extracted from basic-server.js inline styles
  session.html     ← login + dashboard SPA (for session-server.js)
  session.css      ← styles from session-server.js
  guide.html       ← guide content
  guide.css        ← guide styles
```

**Modify `basic-server.js`:**
- Add `express.static` pointing to `public/`
- `GET /` currently calls `basicAuth` middleware then `res.send(DASHBOARD_HTML(req.user))`. Change to: `app.get('/', basicAuth, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')))` — Basic Auth still protects this route.
- In `public/index.html`, remove the SSR injection `${user.fullName} (${user.username})` at the user display element. Replace with `<span id="user-display">Loading…</span>`. The existing `fetch('/api/me')` already updates this element — no change needed to that fetch.
- Add `GET /api/config` returning `{ mode: 'vulnerable', port: 3049 }`.
- **Note:** `DASHBOARD_HTML(user)` currently injects `user.fullName`/`user.username` at render time, BUT the page immediately overwrites this via `fetch('/api/me')` in the inline script. The SSR injection is redundant — safe to remove.

**Modify `session-server.js` (3051):**
- Add `express.static` pointing to `public/` (serves `session.html` etc.)
- Serve `session.html` for `/login`, `/dashboard`, and catch-all.
- Add `GET /api/config` returning `{ mode: 'secure', port: 3051 }`.
- `session.html` uses `/api/config` to set banner, `/api/me` to decide login vs dashboard view.

**Modify `guide-server.js` (3050):** Make thin static server as per Rule 8.

---

## Concept 2: session/ (ports 3052–3054)

**Files:**
- `session-server.js` (3052) — vulnerable
- `guide-server.js` (3053) — guide
- `session-hardened-server.js` (3054) — secure

**Create:**
```
session/public/
  index.html    ← login + dashboard SPA (shared between 3052 and 3054)
  style.css
  guide.html
  guide.css
```

**Modify `session-server.js` and `session-hardened-server.js`:**
- Both servers serve the same `public/index.html`. The only differences are API behavior (cookie flags) and `/api/config` response.
- `session-server.js`: `GET /api/config` returns `{ mode: 'vulnerable', port: 3052 }`.
- `session-hardened-server.js`: `GET /api/config` returns `{ mode: 'secure', port: 3054 }`.
- `public/index.html` fetches `/api/config` → sets banner text/color.
- `public/index.html` fetches `/api/me` on load → if 401 show login form, if 200 show dashboard.
- Remove `/login` and `/dashboard` route handlers that serve HTML; replace with SPA catch-all.

**Modify `guide-server.js` (3053):** Thin static server.

---

## Concept 3: api-key/ (ports 3055–3057)

**Files:**
- `apikey-url-server.js` (3055) — vulnerable
- `guide-server.js` (3056) — guide
- `apikey-header-server.js` (3057) — secure

**Create:**
```
api-key/public/
  index.html    ← DataPulse portal (shared between 3055 and 3057)
  style.css
  guide.html
  guide.css
```

**Modify `apikey-url-server.js`:**
- Add `express.static`, replace `res.send(PORTAL_HTML)` with `res.sendFile`.
- Add `GET /api/config` returning `{ mode: 'vulnerable', port: 3055 }`.

**Modify `apikey-header-server.js`:**
- Same. `GET /api/config` returns `{ mode: 'secure', port: 3057 }`.

Both serve the same `public/index.html`. The only difference is how `/api/weather` validates the key (URL param vs Authorization header) — `index.html` adapts based on `cfg.mode` to show the correct request format in its UI.

**Modify `guide-server.js` (3056):** Thin static server.

---

## Concept 4: jwt-bearer/ (ports 3058–3060)

**Files:**
- `jwt-server.js` (3058) — vulnerable
- `guide-server.js` (3059) — guide
- `jwt-strong-server.js` (3060) — secure

**Create:**
```
jwt-bearer/public/
  index.html    ← TaskFlow playground (shared between 3058 and 3060)
  style.css
  guide.html
  guide.css
```

**Modify `jwt-server.js`:**
- Add `express.static`, replace `res.send(PLAYGROUND_HTML)` with SPA catch-all.
- Add `GET /api/config` returning `{ mode: 'vulnerable', port: 3058 }`.

**Modify `jwt-strong-server.js`:**
- Same. `GET /api/config` returns `{ mode: 'secure', port: 3060 }`.

**Modify `guide-server.js` (3059):** Thin static server.

---

## Concept 5: access-refresh/ (ports 3061–3063)

**Files:**
- `flow-server.js` (3061) — vulnerable
- `guide-server.js` (3062) — guide
- `flow-strong-server.js` (3063) — secure

**Create:**
```
access-refresh/public/
  index.html    ← dashboard SPA (shared between 3061 and 3063)
  style.css
  guide.html
  guide.css
```

**Modify `flow-server.js`:**
- Add `express.static`, replace `res.send(DASHBOARD_HTML)` with SPA catch-all.
- Add `GET /api/config` returning `{ mode: 'vulnerable', port: 3061 }`.

**Modify `flow-strong-server.js`:**
- Same. `GET /api/config` returns `{ mode: 'secure', port: 3063 }`.

**Modify `guide-server.js` (3062):** Thin static server.

---

## Concept 6: sso/ (ports 3064–3066)

**Files:**
- `sso-server.js` (3064) — vulnerable
- `guide-server.js` (3065) — guide
- `sso-strong-server.js` (3066) — secure

**⚠ KEEP `res.send` for `IDP_LOGIN_HTML` — genuine SSR required.**

The IdP login page injects `clientName` (looked up server-side from client registry by `client_id`), plus `redirect_uri`, `state`, `client_id` into hidden `<input type="hidden">` form fields. These values come from the incoming OAuth query string and must be embedded in the form for the POST to work. The `clientName` lookup requires server-side data — cannot be client-side.

**Partial refactor only:**
- Extract WorkHub SP pages (home, dashboard) to `public/index.html` + `public/style.css`. Add `express.static`. Serve these statically.
- Keep `IDP_LOGIN_HTML(opts)` and `DASHBOARD_HTML(session)` as `res.send` — they remain SSR.
- Add `GET /api/config` returning `{ mode: 'vulnerable', port: 3064 }` (or `secure`/3066).
- WorkHub `public/index.html` fetches `/api/config` to set its banner.

**Create:**
```
sso/public/
  index.html    ← WorkHub SP home/dashboard (static)
  style.css
  guide.html
  guide.css
```

**Modify `guide-server.js` (3065):** Thin static server.

---

## Concept 7: oauth2-oidc/ (ports 3067–3069)

**Files:**
- `oauth-server.js` (3067) — vulnerable
- `guide-server.js` (3068) — guide
- `oauth-strong-server.js` (3069) — secure

**⚠ KEEP `res.send` for `AUTHORIZE_HTML` — genuine SSR required.**

The `/auth/authorize` consent page injects `client_id`, `redirect_uri`, `state`, `scope` (and in the secure version: `code_challenge`, `code_challenge_method`) into hidden `<input type="hidden">` form fields. These arrive as OAuth query params and must be round-tripped through the form POST. Cannot be client-side without an additional `GET /api/authorize-info` round-trip which would change the OAuth protocol flow.

**What to refactor:**
- `HOME_HTML()` takes no arguments (effectively static) → extract to `public/index.html`.
- `DASHBOARD_HTML(data)` injects `access_token`, `id_token`, user claims. Add `GET /api/me` returning `{ username, email, accessToken, idToken }` and render client-side.
- Keep `AUTHORIZE_HTML(opts)` and its route as `res.send`.

**Create:**
```
oauth2-oidc/public/
  index.html    ← ConnectApp home + dashboard SPA (client-side rendered)
  style.css
  guide.html
  guide.css
```

**Modify `oauth-server.js` and `oauth-strong-server.js`:**
- Add `express.static`.
- `GET /` → `res.sendFile('public/index.html')`.
- `GET /dashboard` → `res.sendFile('public/index.html')` (SPA handles showing dashboard view after `/api/me`).
- `GET /auth/authorize` → **KEEP `res.send(AUTHORIZE_HTML(opts))`** with comment: `// SSR required: OAuth params injected into hidden form fields`
- Add `GET /api/me` returning `{ username, email, scope, accessToken }` (read from server session).
- Add `GET /api/config` returning `{ mode: 'vulnerable'|'secure', port }`.

**Modify `guide-server.js` (3068):** Thin static server.

---

## Concept 8: mfa-totp/ (ports 3070–3072)

**Files:**
- `vulnerable-server.js` (3070) — vulnerable
- `guide-server.js` (3071) — guide
- `secure-server.js` (3072) — secure

**Create:**
```
mfa-totp/public/
  index.html    ← single-page TOTP demo (shared between 3070 and 3072)
  style.css
  guide.html
  guide.css
```

**Modify `vulnerable-server.js`:**
- `const HTML = \`...\`` is a single static string (no runtime injection).
- Add `express.static`. Replace `app.get('/', (_req, res) => res.send(HTML))` with `res.sendFile`.
- Add `GET /api/config` returning `{ mode: 'vulnerable', port: 3070 }`.

**Modify `secure-server.js`:**
- Same. `GET /api/config` returns `{ mode: 'secure', port: 3072 }`.

**Modify `guide-server.js` (3071):** Thin static server.

---

## Concept 9: passkeys-webauthn/ (ports 3073–3075)

**Files:**
- `vulnerable-server.js` (3073) — vulnerable
- `guide-server.js` (3074) — guide
- `secure-server.js` (3075) — secure

**Create:**
```
passkeys-webauthn/public/
  index.html    ← single-page WebAuthn demo (shared between 3073 and 3075)
  style.css
  guide.html
  guide.css
```

**Modify `vulnerable-server.js`:**
- `const HTML = \`...\`` is a single static string.
- Add `express.static`. Replace `res.send(HTML)` with `res.sendFile`.
- Add `GET /api/config` returning `{ mode: 'vulnerable', port: 3073 }`.

**Modify `secure-server.js`:**
- Same. `GET /api/config` returns `{ mode: 'secure', port: 3075 }`.

**Modify `guide-server.js` (3074):** Thin static server.

---

## Concept 10: magic-links/ (ports 3076–3078)

**Files:**
- `vulnerable-server.js` (3076) — vulnerable
- `guide-server.js` (3077) — guide
- `secure-server.js` (3078) — secure

**Both app servers have `DASHBOARD_HTML(email, profile)` that injects `profile.name`, `email`, `profile.plan`, and `postsHtml` (a server-rendered HTML table). Refactor by adding a `GET /api/profile` endpoint and rendering client-side.**

**Add to both `vulnerable-server.js` and `secure-server.js`:**
```js
app.get('/api/profile', requireSession, (req, res) => {
  const email = req.session.email;
  const profile = USER_PROFILES[email] || { name: email, plan: 'free', posts: [] };
  res.json({ email, name: profile.name, plan: profile.plan, posts: profile.posts });
});
```

**Create:**
```
magic-links/public/
  index.html    ← Inkwell login + dashboard SPA (shared between 3076 and 3078)
  style.css
  guide.html
  guide.css
```

**`public/index.html` pattern:**
1. On load: `fetch('/api/config')` → set banner color/text.
2. `fetch('/api/me')` — if 401 show login form, if 200 fetch `/api/profile` and render dashboard.
3. Render posts table from `profile.posts` in client-side JS (replacing the server-rendered `postsHtml`).

**Modify `vulnerable-server.js`:**
- Add `express.static`. Add `GET /api/profile`. Replace `res.send(LOGIN_HTML)` and `res.send(DASHBOARD_HTML(...))` with SPA catch-all.
- Add `GET /api/config` returning `{ mode: 'vulnerable', port: 3076 }`.

**Modify `secure-server.js`:**
- Same. `GET /api/config` returns `{ mode: 'secure', port: 3078 }`.

**Modify `guide-server.js` (3077):** Thin static server.

---

## Summary: which servers keep `res.send`

| Server | Keep SSR? | Reason |
|--------|-----------|--------|
| `sso/sso-server.js` | ✅ Yes — `IDP_LOGIN_HTML` only | `clientName` server-side lookup + OAuth params in hidden form fields |
| `sso/sso-strong-server.js` | ✅ Yes — `IDP_LOGIN_HTML` only | Same |
| `oauth2-oidc/oauth-server.js` | ✅ Yes — `AUTHORIZE_HTML` only | `client_id`/`state`/`scope` injected into hidden form fields for OAuth POST |
| `oauth2-oidc/oauth-strong-server.js` | ✅ Yes — `AUTHORIZE_HTML` only | Same + `code_challenge`/`code_challenge_method` |
| All others | ❌ No | All HTML is static or can be driven by client-side `fetch()` calls |

Do not touch `package.json` files. Do not add `nodemon`. Do not change API endpoint paths or auth logic — only the HTML delivery mechanism changes.
