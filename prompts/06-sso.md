# Cursor Prompt — 06: SSO (Single Sign-On)
# Ports: 3064 (vulnerable) · 3065 (guide) · 3066 (secure)

Build three Node.js Express servers in `auth-concepts/sso/` that teach SSO redirect_uri validation.

---

## File structure to create

```
sso/
  sso-server.js         ← port 3064, vulnerable
  guide-server.js       ← port 3065, guide
  sso-strong-server.js  ← port 3066, secure
  public/
    index.html          ← WorkHub SP home + dashboard SPA (static, shared)
    style.css
    guide.html
    guide.css
  package.json
```

---

## package.json

```json
{
  "name": "sso",
  "scripts": {
    "vulnerable": "node sso-server.js",
    "guide": "node guide-server.js",
    "secure": "node sso-strong-server.js",
    "start": "node sso-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## Architecture

Each server simulates both the **Service Provider (SP)** (WorkHub, a project management app) and the **Identity Provider (IdP)** (CorpID) in one Express app using route prefixes:

- `/` and `/dashboard` and `/api/*` → WorkHub SP
- `/auth/authorize`, `/auth/login`, `/auth/callback` → CorpID IdP

**Registered clients (in-memory):**
```js
const CLIENTS = {
  'workhub-client-id': {
    name: 'WorkHub',
    allowedRedirectUris: ['http://localhost:PORT/callback'] // PORT = 3064 or 3066
  }
}
```

**IdP users:** `alice / pass1234`, `bob / qwerty123`

**Assertion tokens:** opaque `crypto.randomBytes(16).toString('hex')` stored in `assertions` Map.

---

## ⚠ SSR REQUIRED FOR IDP LOGIN PAGE — DO NOT CONVERT TO STATIC

The IdP login page (`/auth/authorize`) MUST use `res.send(IDP_LOGIN_HTML(opts))` because:
1. `clientName` requires server-side lookup: `CLIENTS[clientId].name`
2. `redirect_uri`, `state`, `client_id` must be injected into `<input type="hidden">` form fields for the login form POST

```js
// Keep as SSR — hidden fields carry OAuth state through the form POST
app.get('/auth/authorize', (req, res) => {
  const { client_id, redirect_uri, state } = req.query;
  const client = CLIENTS[client_id];
  res.send(IDP_LOGIN_HTML({
    clientName: client?.name || 'Unknown App',
    clientId: client_id,
    redirectUri: redirect_uri,
    state,
  }));
});
```

The SP home (`/`) and SP dashboard (`/dashboard`) ARE served statically from `public/`.

---

## sso-server.js (port 3064) — vulnerable

Top comment: `* Terminal 1: cd auth-concepts/sso && npm install && npm run vulnerable`

**Vulnerability:** `redirect_uri` is NOT validated against the registered allowlist. Any URI is accepted → open redirect attack: attacker crafts `/auth/authorize?redirect_uri=http://attacker.com/steal` → victim logs in → assertion token sent to attacker.

**`POST /auth/login`:** validate credentials → generate assertion token → redirect to `redirect_uri?token=<assertion>` **without checking if redirect_uri is allowed**.

**SP callback `GET /callback`:** receive `token` from query → exchange with IdP (`assertions` Map) → set session → redirect to `/dashboard`.

**Routes:**
- `GET /` → serve `public/index.html` (WorkHub home)
- `GET /dashboard` → requireSPSession → serve `public/index.html` (or redirect to `/auth/authorize` if not logged in)
- `GET /auth/authorize` → **SSR** → IDP_LOGIN_HTML with hidden fields
- `POST /auth/login` → validate + redirect (no URI check)
- `GET /callback` → exchange token → set session
- `GET /api/me` → return session user
- `POST /api/logout` → clear session
- `GET /api/config` → `{ mode: 'vulnerable', port: 3064 }`
- `app.use(express.static(path.join(__dirname, 'public')))`

---

## sso-strong-server.js (port 3066) — secure

Top comment: `* Terminal 3: cd auth-concepts/sso && npm run secure`

**Fix:** `redirect_uri` validated against exact allowlist before login form is shown AND before redirect is issued.

```js
// Check on authorize:
if (!client || !client.allowedRedirectUris.includes(redirect_uri)) {
  return res.status(400).send('Invalid redirect_uri');
}

// Check again on login POST:
if (!client.allowedRedirectUris.includes(redirect_uri)) {
  return res.status(400).json({ error: 'redirect_uri not allowed' });
}
```

Same routes as vulnerable. `GET /api/config` → `{ mode: 'secure', port: 3066 }`.

---

## public/index.html — WorkHub SPA

On load:
1. `fetch('/api/config')` → set banner:
   - vulnerable: orange — `⚠ OPEN REDIRECT: redirect_uri is not validated — any URI accepted as callback target`
   - secure: green — `✅ STRICT ALLOWLIST: redirect_uri validated against registered URIs before login`
2. `fetch('/api/me')` → if 401 show "Login with CorpID" button → redirect to `/auth/authorize?client_id=workhub-client-id&redirect_uri=http://localhost:PORT/callback&state=<random>`; if 200 show dashboard with user info

---

## IDP_LOGIN_HTML(opts) — SSR template (inline in server file)

Dark IdP theme (navy: `#1e1e2e` bg, `#cdd6f4` text):
- CorpID logo
- "Signing in to: **{clientName}**" 
- Vulnerability banner (orange) for vulnerable server, secure banner for strong server
- Username + password form
- Hidden inputs: `redirect_uri`, `state`, `client_id`
- Error display

---

## guide-server.js (port 3065) — guide

Top comment: `* Terminal 2: cd auth-concepts/sso && npm run guide`

Thin static server serving `public/guide.html`.

**`public/guide.html`** — dark terminal-green theme:
- Title: "SSO — Single Sign-On"
- Target switcher: "Vulnerable SSO (3064)" dark slate, "Hardened SSO (3066)" green `#16a34a`
- Content: IdP/SP flow diagram, what the assertion token is, open redirect attack walkthrough step-by-step, strict allowlist fix, real-world examples (OAuth2 redirect_uri registration).

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

### sso

**`sso/sso-server.js`** — root causes to annotate:
- `redirect_uri` not validated against allowlist: the IdP (CorpID) accepts any URL as the callback target. An attacker crafts a phishing URL: `/auth/authorize?client_id=workhub-client-id&redirect_uri=http://attacker.com/steal`. The victim sees a legitimate CorpID login page, enters their credentials, and the IdP redirects the assertion token to the attacker's server. The attacker now has a valid token to log into WorkHub as the victim. The victim has no indication anything went wrong.
- Weak IdP signing secret: if the assertion JWT can be forged (same brute-force path as jwt-bearer), the attacker bypasses login entirely.

**`sso/sso-strong-server.js`** — fixes to annotate:
- `redirect_uri` validated twice: at `/auth/authorize` before showing the login form, and again at `POST /auth/login` before issuing the redirect. Both checks use exact string equality against the registered allowlist — no prefix matching, no wildcard. If the URI is not in the list, the request is rejected before credentials are ever entered.
- Strong IdP secret: same argument as jwt-bearer fix.

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

### Per-concept README instructions — sso (WorkHub + CorpID)

**`## How It Works`** — expand the flow:

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

**Note:** The `/auth/authorize` authorization page must use `res.send()` for SSR (hidden form fields). Do not convert to JSON — the OAuth flow requires a rendered HTML form.

**`## The Vulnerability`** — open redirect attack step by step:

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

The victim saw a real login page, entered real credentials, and was "successfully" logged in.
Nothing on screen indicated the token was diverted.

**`## Vulnerable Lines`**:
```js
// ⚠️ VULNERABLE — no redirect_uri allowlist; any URL accepted as callback target
const REGISTERED_SPS = {
  workhub: { name: 'WorkHub', clientId: 'workhub-client-id' },
  // allowedRedirectUris is absent — no validation performed
};

// In POST /idp/authenticate:
// ⚠️ VULNERABLE — redirectUri comes from request body and used directly without allowlist check
res.redirect(`${redirectUri}?token=${assertionToken}&state=${state}`);
```

**`## Defense Details`**:
- `### Exact allowlist matching` — prefix matching (`startsWith`) is insufficient: `http://localhost:3066.attacker.com/` starts with `http://localhost:3066`. Exact string equality only.
- `### Double validation` — check at `/idp/login` (before rendering the form) AND at `POST /idp/authenticate` (before issuing the redirect). The first check prevents the login page from being used as a phishing scaffold. The second check is the security guarantee — both are required.
- `### State parameter` — allowlist protects where the token goes; state protects who initiates the flow. Both defenses are independent.

**`## Hardened Demo`**:
1. Open `localhost:3066` — copy the attack URL from the amber banner on `localhost:3064`
2. Change `localhost:3064` to `localhost:3066` in the URL — attempt the attack on the hardened server
3. Response: `400 Bad Request — redirect_uri not in allowlist` — form never renders
4. Login normally at `localhost:3066` — observe `state` parameter in the authorize URL
5. Try `/callback?token=fake&state=wrong` — state mismatch rejected
