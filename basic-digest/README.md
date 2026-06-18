# Basic & Digest Auth — SimpleDesk Demo

SimpleDesk is an internal IT helpdesk for submitting and tracking support tickets. This demo shows why HTTP Basic Auth is risky (credentials in every request) and how session tokens improve the model.

---

## Port Reference

| Port | File | Role |
|------|------|------|
| 3049 | `basic-server.js` | Vulnerable — credentials base64-encoded on every request |
| 3050 | `guide-server.js` | Concept guide — decoder, intercept demo, comparison table |
| 3051 | `session-server.js` | Hardened — session token via `Authorization: Bearer` |

---

## How It Works

```
GET /api/tickets  (no Authorization header)
        ↓
Server: 401 Unauthorized
        WWW-Authenticate: Basic realm="SimpleDesk"
        ↓
Browser shows native credential dialog (no JavaScript involved)
        ↓
User enters alice / pass1234
        ↓
Browser encodes "alice:pass1234" → base64 → Authorization: Basic YWxpY2U6cGFzczEyMzQ=
        ↓
Server decodes base64, verifies password → 200 OK
        ↓
Browser caches credential for http://localhost:3049 — attaches header on every subsequent request
```

### How the browser dialog appears (no JavaScript involved)

There is no HTML form and no client-side code that creates the login dialog. The browser shows it automatically based on the HTTP response from the server:

```
Server sends:
  HTTP/1.1 401 Unauthorized
  WWW-Authenticate: Basic realm="SimpleDesk"

Browser built-in logic:
  "I received 401 + WWW-Authenticate: Basic → show native credential dialog"
```

Both conditions are required. `401` alone shows no dialog (browser renders the JSON error body). `WWW-Authenticate: Basic` alone without `401` is ignored entirely. The `realm` string (`"SimpleDesk"`) appears as the subtitle in the dialog but does not affect whether it triggers.

The only server code responsible:

```js
res.setHeader('WWW-Authenticate', 'Basic realm="SimpleDesk"');
return res.status(401).json({ error: 'Authentication required' });
```

No JavaScript framework, no HTML, no event listeners — this is defined by the HTTP/1.1 specification (RFC 7617) as browser behaviour.

### How the Authorization header is set (also no JavaScript)

When the user clicks "Sign in" in the dialog, the **browser** (not any code you wrote):

1. Takes the username and password from the dialog
2. Concatenates: `"alice" + ":" + "pass1234"` → `"alice:pass1234"`
3. Base64-encodes: `btoa("alice:pass1234")` → `"YWxpY2U6cGFzczEyMzQ="`
4. Prepends scheme: `"Basic YWxpY2U6cGFzczEyMzQ="`
5. Attaches as `Authorization` header and **retries the original request**
6. Caches the credential for the origin (`http://localhost:3049`) and **sends the same header on every subsequent request** — automatically, silently, forever

The server-side decode:

```js
const base64 = authHeader.slice(6);                              // strip "Basic "
const decoded = Buffer.from(base64, 'base64').toString('utf8'); // → "alice:pass1234"
const colonIndex = decoded.indexOf(':');
const username = decoded.substring(0, colonIndex);
const password = decoded.substring(colonIndex + 1);
```

#### Why `Buffer.from()` and not `atob()`?

`atob()` is a **browser/Web API**. In Node.js it did not exist until v16 (added in 2021 only as a web-compatibility shim). `Buffer` is Node.js's native binary data primitive — available since Node 0.1.0 and always the idiomatic server-side choice.

There are two additional concrete reasons `Buffer` is better even when `atob` is technically available:

- **Encoding**: `atob()` decodes to Latin-1 (ISO-8859-1). If a password contains accented or Unicode characters, `atob()` produces wrong bytes. `Buffer.from(...).toString('utf8')` always uses UTF-8.
- **Error tolerance**: `atob()` throws a `DOMException` on any whitespace or padding mismatch. `Buffer.from()` is lenient.

Rule of thumb:
```
Client-side JS (browser) → atob() / btoa()
Server-side JS (Node.js) → Buffer.from(b64, 'base64') / .toString('base64')
```

---

## The Vulnerability

`atob("YWxpY2U6cGFzczEyMzQ=")` → `"alice:pass1234"` — one line in any browser console. The password travels with every request and is visible in:

- Proxy logs and load balancer access logs
- Any packet capture on the network (without TLS)
- Browser history if credentials are embedded in a URL
- `Authorization` header visible in DevTools → Network → any request

### Credential caching — how Basic Auth persists across tabs

The browser caches Basic Auth credentials **per origin** (scheme + host + port). Once authenticated at `http://localhost:3049`, the credential is stored in the browser's internal HTTP credential store — completely below the JavaScript layer, inaccessible to any Web API.

Consequences:
- Open a new tab → navigate to `localhost:3049` → the header is already attached, no dialog
- The credential persists until the tab/window is closed, the browser is restarted, or browser data is cleared
- **JavaScript cannot read or clear it.** `localStorage`, `sessionStorage`, `document.cookie` are all irrelevant — none of them touch this store

### Logout — why it is impossible (and the tricks people try)

There is no `POST /api/logout` on port 3049 intentionally. Basic Auth has no session to destroy. The server cannot revoke a credential it did not issue — as long as the password is `pass1234`, the base64 header will always be valid.

#### The URL credential trick

```
http://logout:logout@localhost:3049/
```

RFC 3986 URL structure:
```
scheme :// [userinfo @] host [:port] / path
http://   logout:logout @ localhost : 3049 /
          ─────────────   ─────────   ────
            userinfo         host     port
```

The `@` separates userinfo from host. The **origin is still `http://localhost:3049`** — same cache slot. The browser sends `Authorization: Basic bG9nb3V0OmxvZ291dA==` (logout:logout), the server returns `401`, and the browser marks the cached credential for that origin as rejected/invalid.

This is why `http://logout.localhost:3049/` (no `@`) does **not** work — `logout.localhost` is parsed as a different hostname, making the origin `http://logout.localhost:3049`, a completely separate credential cache with no connection to `http://localhost:3049`.

#### Why correct credentials in a URL have no effect

```
http://admin:admin456@localhost:3049/
```

The server returns `200 OK` (credentials are correct). The browser confirms the cached credential and the page renders normally. No visible change — because nothing was wrong to begin with. The credential cache only gets invalidated by a `401` response, not by a `200`.

#### Why keeping the logout URL open in another tab blocks login

Both tabs share **one** credential cache entry for `http://localhost:3049`. If Tab A has `http://logout:logout@localhost:3049/` open and active, it keeps sending bad credentials → keeps receiving `401` → keeps reasserting `{logout:logout}` as the cached credential. Even if a dialog appears in Tab B and the user enters the correct password, Tab A's next request overwrites the cache back to the bad credential. The only fix: close Tab A.

### What happens when you refresh a tab loaded via a credential URL

If a tab's current URL contains credentials (e.g. `http://admin:admin456@localhost:3049/`), pressing F5 replays that exact URL. The HTML may be served from the browser's HTTP cache (`304 Not Modified`) so the page shell appears — but then Chrome's security model kicks in:

**Chrome blocks all `fetch()` calls from pages loaded at a URL with embedded credentials.**

```
Page URL: http://admin:admin456@localhost:3049/
                   ─────────────
                   credentials present

fetch('/api/me')
  → Chrome resolves relative path to absolute URL
  → http://admin:admin456@localhost:3049/api/me
  → Security check: "URL has username/password?" → YES
  → TypeError: Request cannot be constructed from a URL that includes credentials
```

Every API call (`/api/me`, `/api/tickets`) throws synchronously. The page renders from cache but "Loading tickets..." hangs forever. This is Chrome's way of preventing credentials from leaking into subrequests — another reason why embedding credentials in page URLs is harmful even when the server accepts them.

---

## The Fix

Port 3051 runs the same SimpleDesk app but replaces Basic Auth with a login form and session tokens. Credentials are sent once at login; all subsequent requests use an opaque random `Authorization: Bearer` token. The server stores sessions in a Map and supports `POST /api/logout`, which immediately invalidates the token — something impossible with stateless Basic Auth.

---

## How to Run

```bash
cd auth-concepts/basic-digest
npm install
npm run vulnerable  # terminal 1 → localhost:3049 (Basic Auth)
npm run guide       # terminal 2 → localhost:3050 (concept guide)
npm run secure      # terminal 3 → localhost:3051 (Session Auth)
```

---

## Demo Walkthrough

1. Open `http://localhost:3049` — the browser shows a native credential dialog (no HTML login form). Enter `alice / pass1234`.
2. Open DevTools → Network → click any API request — observe `Authorization: Basic YWxpY2U6cGFzczEyMzQ=` on every request.
3. In the browser console, run `atob("YWxpY2U6cGFzczEyMzQ=")` — returns `"alice:pass1234"`. The password is trivially recoverable from any captured header.
4. Open a new tab and navigate to `localhost:3049` — no dialog appears; the browser silently attaches the cached credential.
5. Try to log out — there is no `POST /api/logout` endpoint. Basic Auth has no session to destroy.
6. Navigate to `http://logout:logout@localhost:3049/` — the server returns `401`, invalidating the cached credential for that origin.
7. Optionally open `http://localhost:3050` (concept guide) to use the decoder and intercept demo interactively.

---

## Hardened Demo

1. Open `localhost:3051` — login with `alice / pass1234`
2. Open DevTools → Network → any request — `Authorization` header shows `Bearer a3f9...`, not base64 credentials
3. `POST /api/logout` → server calls `sessions.delete(token)` — the token is immediately invalid
4. Attempt the old `atob()` trick in the console — there is no `Authorization: Basic` header to decode

---

## Vulnerable Lines

```js
// ⚠️ VULNERABLE — HTTP Basic Auth sends base64(username:password) on every request.
// atob("YWxpY2U6cGFzczEyMzQ=") === "alice:pass1234" — one line in any browser console.
function basicAuth(req, res, next) {
  // ... Authorization: Basic <base64> checked on every single request
  res.setHeader('WWW-Authenticate', 'Basic realm="SimpleDesk"');
  return res.status(401).json({ error: 'Authentication required' });
}
```

---

## Defense Details

### Why session tokens fix the problem

Port 3051 runs the same SimpleDesk app but replaces Basic Auth with a login form + session token. Credentials are sent **once** at login; all subsequent requests use an opaque random token.

```
POST /api/login { username, password }
→ server verifies → issues 64-char random token
→ client stores token in localStorage

GET /api/tickets
Authorization: Bearer a3f9b2c1...   ← opaque token, not your password

POST /api/logout
→ server deletes the session entry → token immediately invalid
```

Key differences from Basic Auth:

| Property | Basic Auth (3049) | Session Auth (3051) |
|----------|-------------------|---------------------|
| Password over wire | Every request | Login only |
| Server stores | Nothing (stateless) | Session Map |
| Logout possible | No | Yes — `sessions.delete(token)` |
| MFA support | No | Yes (add step after login) |
| Credential exposure | Every network request | Login request only |

### Digest Auth — the fix that wasn't

Digest Auth was designed to fix Basic Auth's plaintext credential problem:

```
Basic:   Authorization: Basic YWxpY2U6cGFzczEyMzQ=   ← base64, trivially reversible
Digest:  Authorization: Digest response="d7a8f3c9..."  ← HMAC-MD5 hash, password never sent
```

The server sends a `nonce` (random value) in the 401 challenge. The client computes `MD5(username:realm:password)` combined with the nonce and sends only the hash. The password never crosses the wire.

**Why it's still obsolete:**

- MD5 is offline-crackable. If a nonce is captured from a network trace, the hash can be brute-forced
- Modern password storage uses bcrypt/Argon2 — incompatible with Digest (which needs to compute the same hash the server expects)
- Still no logout (same stateless problem as Basic)
- Still no MFA support
- Not used in any modern system

### When Basic Auth is acceptable in the real world

Basic Auth is not used for user-facing web applications. It survives in:

- **Machine-to-machine API calls** — `curl`, Postman, CI scripts, SDKs. The caller controls when credentials are sent; no "session" or "logout" concept is needed
- **Internal developer tools over HTTPS** — TLS provides encryption, the small team understands the trade-offs
- **Local development** — convenience over security, never exposed publicly

For any app where a human needs to click "Sign out", the answer is always session tokens or JWT. That is the entire point of port 3051.

---

## Credentials

| Username | Password |
|----------|----------|
| alice | pass1234 |
| bob | qwerty123 |
| admin | admin456 |
