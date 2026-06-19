# Cursor Prompt — 03: API Key Auth
# Ports: 3055 (vulnerable) · 3056 (guide) · 3057 (secure)

Build three Node.js Express servers in `auth-concepts/api-key/` that teach API key placement security.

---

## File structure to create

```
api-key/
  apikey-url-server.js    ← port 3055, vulnerable
  guide-server.js         ← port 3056, guide
  apikey-header-server.js ← port 3057, secure
  public/
    index.html            ← DataPulse portal SPA (shared)
    style.css
    guide.html
    guide.css
  package.json
```

---

## package.json

```json
{
  "name": "api-key",
  "scripts": {
    "vulnerable": "node apikey-url-server.js",
    "guide": "node guide-server.js",
    "secure": "node apikey-header-server.js",
    "start": "node apikey-url-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## Shared app: DataPulse (weather/analytics API portal)

**API keys (in-memory):**
- `sk_live_alice_a3f9b2c1` → user alice
- `sk_live_bob_d4e5f6a7` → user bob
- `sk_test_demo_x9y8z7w6` → demo user

**Weather data returned:** `{ city:'San Francisco', temp:18, condition:'Partly cloudy', humidity:72, updatedAt:'2026-06-17T10:00:00Z' }`

---

## apikey-url-server.js (port 3055) — vulnerable

Top comment: `* Terminal 1: cd auth-concepts/api-key && npm install && npm run vulnerable`

**Vulnerability:** API key passed as URL query param `?api_key=<key>` — appears in server logs, browser history, Referer header, proxy logs, CDN logs.

**Routes:**
- `GET /api/weather?api_key=<key>` — validate key from `req.query.api_key` → return weather data or 401
- `GET /api/config` → `{ mode: 'vulnerable', port: 3055 }`
- `app.use(express.static(...))`
- Catch-all → `res.sendFile('public/index.html')`

---

## apikey-header-server.js (port 3057) — secure

Top comment: `* Terminal 3: cd auth-concepts/api-key && npm run secure`

**Fix:** API key passed as `Authorization: Bearer <key>` header — never appears in URLs, logs, or Referer.

**Routes:**
- `GET /api/weather` — validate key from `req.headers.authorization` (strip `Bearer `) → return weather data or 401
- `GET /api/config` → `{ mode: 'secure', port: 3057 }`
- Same static + catch-all as vulnerable server

---

## public/index.html — DataPulse SPA (shared by both servers)

On load:
1. `fetch('/api/config')` → set banner + adapt UI:
   - vulnerable (mode=`vulnerable`): orange banner — `⚠ API KEY IN URL: key appears in server logs, browser history, and Referer headers`; request input shows `GET /api/weather?api_key=YOUR_KEY`
   - secure (mode=`secure`): green banner — `✅ API KEY IN HEADER: Authorization: Bearer YOUR_KEY — clean URLs, key never in logs`; request input shows `GET /api/weather` with header field

**UI:** API key input field, "Fetch Weather" button, response display area showing JSON or error. Show the actual request format (URL vs header) based on mode.

When button clicked:
- vulnerable mode: fetch `/api/weather?api_key=${keyInput.value}`
- secure mode: fetch `/api/weather` with `Authorization: Bearer ${keyInput.value}`

---

## guide-server.js (port 3056) — guide

Top comment: `* Terminal 2: cd auth-concepts/api-key && npm run guide`

Thin static server serving `public/guide.html`.

**`public/guide.html`** — dark terminal-green theme:
- Title: "API Key Auth"
- Target switcher: "Vulnerable API Key (3055)" dark slate, "Hardened API Key (3057)" green `#16a34a`
- Content: 5 exposure vectors for URL-based keys (server logs, browser history, Referer header, CDN/proxy logs, shoulder surfing), comparison table (URL param vs Authorization header vs custom header), key rotation best practices, scoping keys to minimal permissions.

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

### api-key

**`api-key/apikey-url-server.js`** — root causes to annotate:
- API key in URL query parameter: `GET /api/weather?api_key=sk_test_...`. URLs are logged by every reverse proxy, load balancer, CDN, and web server access log. The key appears in server logs, browser history, and the HTTP `Referer` header if the page links to another site. A compromised log file exposes every key that ever made a request. Sharing a URL for debugging silently shares the credential. The header server is identical in scoping and rate-limiting — only the key transport differs.

**`api-key/apikey-header-server.js`** — fixes to annotate:
- API key in `Authorization: Bearer` header. By convention and configuration, reverse proxies strip or exclude `Authorization` headers from access logs. The key never appears in URLs, browser history, or `Referer` headers. DevTools Network tab shows it, but only to someone with local access to the browser.
- Per-key metadata (name, permissions, created date) enables auditing, rotation, and least-privilege scoping.

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

### Per-concept README instructions — api-key (DataPulse)

**`## How It Works`** — expand:

```
VULNERABLE (port 3055):
  GET /api/weather?api_key=sk_live_alice_a3f9...   ← key in URL
          ↓
  Nginx access log: GET /api/weather?api_key=sk_live_alice_a3f9... 200
  CDN log: same line
  Referer header on next navigation: /api/weather?api_key=sk_live_alice_a3f9...

SECURE (port 3057):
  GET /api/weather
  Authorization: Bearer sk_live_alice_a3f9...   ← key in header
          ↓
  Nginx access log: GET /api/weather 200
  (Authorization header stripped from logs by convention)
```

**`## The Vulnerability`** — expand with concrete log exposure and Referer leak:

The URL query parameter appears verbatim in: web server access logs (`/var/log/nginx/access.log`),
CDN and load balancer logs (AWS ALB, Cloudflare), browser history (every API call a developer
made in the browser is saved), HTTP `Referer` header (if the page links anywhere, the full URL
including the key is sent as the Referer on the next request), and curl command history on
developer machines.

A single leaked log file or compromised developer laptop exposes every API key that ever made a
request. There is no way to audit which keys appeared in logs without reading every log line.

**`## The Fix`** — expand:

`Authorization: Bearer <key>` keeps the credential out of the URL entirely.
Reverse proxies configured with standard access log formats omit the `Authorization` header.
Keys never appear in browser history because headers are not part of the URL.

Additionally, the hardened server attaches per-key metadata (owner, scopes, created date),
enabling key auditing, rotation, and least-privilege — a key with scope `weather` cannot call
the analytics endpoint even if stolen.

**`## Vulnerable Lines`**:
```js
// ⚠️ VULNERABLE — API key extracted from URL query parameter
// The full URL (including the key) is written to every access log on every hop between
// client and server: browser → proxy → CDN → load balancer → app server.
const apiKey = req.query.api_key;
```

**`## Defense Details`**:
- `### Why headers are safer than query params` — headers are not cached, not in browser history, not in Referer. Logging infrastructure treats Authorization specially — standard formats omit it.
- `### Key scoping and rotation` — per-key metadata enables auditing, rotation, and least-privilege enforcement. A rotated key can be issued without downtime.
- `### What this doesn't fix` — Authorization header still appears in DevTools Network tab (requires local access to the browser). Defense is about reducing attack surface, not eliminating it entirely.

**`## Hardened Demo`**:
1. Open `localhost:3055` — click any weather request, then click **Refresh Logs** — see the full key in the log
2. Click the "Rotate Key" button — old key rejected on next request
3. Open `localhost:3057` — make the same request — logs show `GET /api/weather 200`, key absent
4. Try calling `/api/analytics` with the `demo` key — rejected (scope: weather only)
