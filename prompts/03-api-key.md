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
