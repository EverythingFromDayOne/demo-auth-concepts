# Session Authentication — NoteKeep Demo

NoteKeep is a personal notes app that demonstrates session-based authentication: login creates a server-side session, the browser stores a cookie, and every request sends that cookie for validation.

## How It Works

```
POST /api/login { username, password }
        ↓
Server validates credentials → creates session:
  sessions.set("a3f9b2c1...", { username: "alice" })
        ↓
Set-Cookie: nk_session=a3f9b2c1...; Path=/; HttpOnly; SameSite=Strict
        ↓
Every subsequent request: browser sends Cookie: nk_session=a3f9b2c1...
        ↓
Server: sessions.get("a3f9b2c1...") → { username: "alice" } → authorized
        ↓
POST /api/logout → sessions.delete("a3f9b2c1...") → token invalidated
```

## Cookie vulnerability (port 3052)

`Set-Cookie: nk_session=a3f9b2c1...; Path=/; SameSite=Lax` — missing `HttpOnly`.

`document.cookie` returns `"nk_session=a3f9b2c1..."` — any XSS payload can read and exfiltrate it.

## The fix (port 3054)

`Set-Cookie: nk_session=a3f9b2c1...; Path=/; HttpOnly; SameSite=Strict`

`document.cookie` returns `""` — browser sends the cookie automatically but JS cannot see it.

## Run the demo

```bash
cd auth-concepts/session
npm install
npm run vulnerable  # terminal 1 → localhost:3052
npm run guide       # terminal 2 → localhost:3053
npm run secure      # terminal 3 → localhost:3054
```

## Walkthrough

1. Open **localhost:3052** — sign in as `alice` / `pass1234`.
2. On the dashboard, note the amber box showing `document.cookie` with your `nk_session` token visible.
3. Open DevTools console and run `document.cookie` — the full session token is readable.
4. Open **localhost:3054** — same login. Dashboard shows `(HttpOnly — not visible to JavaScript)`.
5. Run `document.cookie` in the console — returns empty string; session still works via automatic cookie sending.
6. Open **localhost:3053** — compare cookie attributes and click the visibility demo buttons.

## Ports

| Port | Server | Role |
|------|--------|------|
| 3052 | `session-server.js` | Vulnerable — cookie without HttpOnly |
| 3053 | `guide-server.js` | Concept guide — lifecycle + cookie attributes |
| 3054 | `session-hardened-server.js` | Hardened — HttpOnly + SameSite=Strict |

## Demo credentials

| Username | Password |
|----------|----------|
| alice | pass1234 |
| bob | qwerty123 |
