# API Key Authentication — DataPipe

DataPipe is a weather and analytics data API. This demo shows why passing API keys as URL query parameters is dangerous, and how the `Authorization: Bearer` header fixes the exposure.

---

## Port Reference

| Port | File | Role |
|------|------|------|
| 3055 | `apikey-url-server.js` | Vulnerable — `?api_key=sk_...` in URL |
| 3056 | `guide-server.js` | Concept guide — exposure vectors + live demo |
| 3057 | `apikey-header-server.js` | Secure — `Authorization: Bearer sk_...` |

---

## How It Works

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

---

## The Vulnerability

Server access log (port 3055):

```
GET /api/weather?api_key=sk_live_alice_a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5 HTTP/1.1
```

Anyone with access to the server logs, CDN logs, or proxy logs sees the API key.

The URL query parameter appears verbatim in:

- Web server access logs (`/var/log/nginx/access.log`)
- CDN and load balancer logs (AWS ALB, Cloudflare)
- Browser history — every API call a developer made in the browser is saved
- HTTP `Referer` header — if the page links anywhere, the full URL including the key is sent as the Referer on the next request
- Curl command history on developer machines

A single leaked log file or compromised developer laptop exposes every API key that ever made a request.
There is no way to audit which keys appeared in logs without reading every log line.

---

## The Fix

`Authorization: Bearer <key>` keeps the credential out of the URL entirely.
Reverse proxies configured with standard access log formats omit the `Authorization` header.
Keys never appear in browser history because headers are not part of the URL.

Additionally, the hardened server attaches per-key metadata (owner, scopes, created date),
enabling key auditing, rotation, and least-privilege — a key with scope `weather` cannot call
the analytics endpoint even if stolen.

---

## How to Run

```bash
cd auth-concepts/api-key
npm install
npm run vulnerable  # terminal 1 → localhost:3055
npm run guide       # terminal 2 → localhost:3056
npm run secure      # terminal 3 → localhost:3057
```

---

## Demo Walkthrough

1. Open **localhost:3055** — enter the demo key, click a weather request.
2. Click **Refresh Logs** — see the full key in the access log:

   ```
   GET /api/weather?api_key=sk_live_alice_a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5 HTTP/1.1
   ```

3. Anyone with access to server logs, CDN logs, or proxy logs would see the same line — the key is permanently recorded.

---

## Hardened Demo

1. Open `localhost:3055` — click any weather request, then click **Refresh Logs** — see the full key in the log
2. Click the **Rotate Key** button — old key rejected on next request
3. Open `localhost:3057` — make the same request — logs show `GET /api/weather 200`, key absent
4. Try calling `/api/analytics` with the `demo` key — rejected (scope: weather only)

---

## Vulnerable Lines

```js
// ⚠️ VULNERABLE — API key extracted from URL query parameter
// The full URL (including the key) is written to every access log on every hop between
// client and server: browser → proxy → CDN → load balancer → app server.
const apiKey = req.query.api_key;
```

---

## Defense Details

### Why headers are safer than query params

The HTTP spec treats headers and query strings differently for caching, logging, and navigation. Query parameters appear in URLs, browser history, and Referer headers. Headers are not cached by browsers, not stored in history, and not forwarded in Referer. Logging infrastructure conventionally omits or redacts the `Authorization` header in access logs.

### Key scoping and rotation

The hardened server stores per-key metadata: owner, plan, scopes, rate limit, and creation date. Scopes enforce least-privilege at the API layer — a weather-only key cannot reach analytics even if exfiltrated. Rotation invalidates a compromised key without changing the owner's identity; audit trails tie each key to an owner for incident response.

### What this doesn't fix

The `Authorization` header still appears in DevTools Network tab (requires local access to the machine). TLS termination logs at a proxy would still see the header in plaintext before re-encryption. Defense is about reducing attack surface — moving keys out of URLs eliminates the most common accidental leak vectors — not eliminating all exposure.

---

## Credentials

| Key | Owner | Scopes |
|-----|-------|--------|
| `sk_test_demo_c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0` | demo | weather |
| `sk_live_bob_b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9` | bob | weather |
| `sk_live_alice_a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5` | alice | weather, analytics |
