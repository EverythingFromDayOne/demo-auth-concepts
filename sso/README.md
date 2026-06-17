# SSO — WorkHub + CorpID Demo

Single Sign-On lets users access multiple applications through one central login. WorkHub is the Service Provider (SP); CorpID is the Identity Provider (IdP).

## SSO flow

```
User → WorkHub (SP) → redirect to CorpID (IdP) → login → assertion token
     ← redirect back to WorkHub /callback?token=... → WorkHub creates session
```

## Vulnerability (port 3064)

The IdP accepts any `redirect_uri`. Attack: craft a login URL with `redirect_uri=http://attacker.com/steal` — after the victim logs in, the assertion token is sent to the attacker's server instead of WorkHub.

```
http://localhost:3064/idp/login?client_id=workhub-client-id&redirect_uri=http://attacker.com/steal&state=x
```

## Fix (port 3066)

`redirect_uri` must be an exact match in the registered allowlist for the `client_id`. Rejection happens at both `/idp/login` (before the form) and `/idp/authenticate` (on POST). State parameter is validated on callback.

## Run the demo

```bash
cd auth-concepts/sso
npm install
npm run vulnerable  # terminal 1 → localhost:3064
npm run guide       # terminal 2 → localhost:3065
npm run strong      # terminal 3 → localhost:3066
```

## Walkthrough

1. Open **localhost:3064** — redirected to CorpID, login as `alice@corp.com` / `pass1234`
2. Land on WorkHub dashboard with SSO badge — name and email embedded via SSR
3. Click **Sign Out** — SP session cleared; visit again and notice instant re-login (IdP session still active)
4. Paste the attack URL from the amber banner — see `redirect_uri` pointing at attacker.com
5. Open **localhost:3065** — read flow diagrams; test allowlist against :3066
6. Open **localhost:3066** — try the same attack URL → 400 Bad Request

## Ports

| Port | Server | Role |
|------|--------|------|
| 3064 | `sso-server.js` | Vulnerable — unvalidated redirect_uri |
| 3065 | `guide-server.js` | SSO Lab — flow + attack + live tester |
| 3066 | `sso-strong-server.js` | Hardened — exact allowlist + state validation |

## Demo credentials

| Email | Password | Role |
|-------|----------|------|
| alice@corp.com | pass1234 | employee |
| bob@corp.com | qwerty123 | employee |
| admin@corp.com | admin456 | admin |
