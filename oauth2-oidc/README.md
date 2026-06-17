# OAuth2 & OIDC — ConnectApp Demo

ConnectApp is a third-party todo app that connects to GitBucket via GrantID (OAuth2 + OIDC authorization server).

## Authorization code flow

```
1. User clicks "Connect with GitBucket" on ConnectApp
2. ConnectApp redirects to GrantID /auth/authorize (with state + PKCE on hardened server)
3. User logs in at GrantID and approves scopes
4. GrantID redirects to ConnectApp /callback?code=...&state=...
5. ConnectApp verifies state, exchanges code (+ code_verifier) for tokens
6. ConnectApp uses access_token to call GitBucket API
7. id_token proves who the user is (OIDC)
```

## Vulnerability (port 3067)

No `state` parameter. CSRF attack: trick victim into loading `/callback?code=ATTACKER_CODE` — victim's ConnectApp account links to attacker's GitBucket identity.

## Fix (port 3069)

`state` is cryptographically random and verified in callback. PKCE: `code_challenge` sent with authorize, `code_verifier` sent with token exchange.

## Run the demo

```bash
cd auth-concepts/oauth2-oidc
npm install
npm run vulnerable  # terminal 1 → localhost:3067
npm run guide       # terminal 2 → localhost:3068
npm run strong      # terminal 3 → localhost:3069
```

## Walkthrough

1. Open **localhost:3068** — read flow diagrams, try PKCE generator and id_token decoder.
2. Open **localhost:3067** — click **Connect with GitBucket**, login as `alice@example.com` / `pass1234`, approve scopes.
3. Dashboard shows GitBucket repos, access token preview, and decoded OIDC claims.
4. Open **localhost:3069** — same flow; notice `state` and PKCE in the authorize URL.
5. Try loading `/callback?code=fake&state=wrong` on **3069** — rejected as CSRF.

## Demo credentials

| Email | Password |
|-------|----------|
| alice@example.com | pass1234 |
| bob@example.com | qwerty123 |

## Ports

| Port | Server | Role |
|------|--------|------|
| 3067 | `oauth-server.js` | Vulnerable — no state |
| 3068 | `guide-server.js` | OAuth2 & OIDC Lab |
| 3069 | `oauth-strong-server.js` | Hardened — state + PKCE |
