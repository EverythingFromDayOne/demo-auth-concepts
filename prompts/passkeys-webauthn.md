# Cursor Prompt: Passkeys / WebAuthn Demo — CloudPortal (Ports 3073–3075)

## Global UI Standard — applies to every server in this lab

| Server type | Theme |
|-------------|-------|
| Attacker server / Attack guide | Clone `DASHBOARD_HTML` from `demo-attacked/reverse-tabnabbing/attacker-server.js` — `#0a0a0a` bg, `#00ff41` text, `'Courier New'` font. Copy `<style>` verbatim. |
| Internal / target server | Muted corporate — `#1a1a2e` bg, `#e2e8f0` text |
| Victim servers | Realistic product UI matching their brand |

**Attacker/guide pages — non-negotiable rules:**
- Copy the `<style>` block from `DASHBOARD_HTML` in `demo-attacked/reverse-tabnabbing/attacker-server.js` **verbatim**. Never recreate or paraphrase it.
- Body layout: `padding: 2rem` on body. No `max-width` wrapper div. No centering.
- Panels: use `.flow-box` and `.credentials-panel` classes. Full-width. Only `<p>` text may use `max-width`.
- Navigation: **fixed bottom-left `target-switcher` only.**
- **After** the verbatim `<style>` block, always add this override: `.flow-box { max-width: 900px; }`

---

## Code Comment Standard — use throughout all three files

```
// ⚠️ VULNERABILITY: <what is wrong and why it matters>
// ✅ PROTECTED: <what was changed and why it is now safe>
```

No lorem ipsum anywhere. All copy must be realistic product language.

---

## Files to create

```
auth-concepts/passkeys-webauthn/
├── vulnerable-server.js    # CloudPortal — Weak WebAuthn          — port 3073
├── guide-server.js         # Passkeys & WebAuthn Lab              — port 3074
├── secure-server.js        # CloudPortal — Hardened WebAuthn      — port 3075
├── package.json
└── README.md
```

---

## Context

**Concept:** Passkeys / WebAuthn (FIDO2 — Web Authentication API)
**App name:** CloudPortal — a cloud infrastructure management console
**Tagline:** "Manage your cloud resources"
**Folder:** `auth-concepts/passkeys-webauthn/`

CloudPortal replaces passwords with passkeys. A passkey is a FIDO2 WebAuthn credential: a key pair where the private key never leaves the user's device and the server only stores the public key. Authentication is a cryptographic challenge-response — the server sends a random challenge, the device signs it with the private key (after the user touches a sensor or scans biometrics), and the server verifies the signature with the stored public key.

**Why it matters:** Passkeys are phishing-resistant by design — credentials are bound to the RP origin so a phishing site cannot reuse them. But weak implementations can still be exploited: skipping user verification (biometric/PIN) means device presence alone suffices, no counter check means cloned credentials go undetected, and reusing challenges allows replay attacks. The secure implementation requires user verification, tracks the authenticator counter, and invalidates each challenge after a single use.

---

## Port Layout

| Port | Role | App |
|------|------|-----|
| 3073 | Concept: Weak WebAuthn | CloudPortal (UV discouraged, no counter update, challenge reusable) |
| 3074 | Concept guide | Passkeys & WebAuthn Lab (FIDO2 flow, raw API demo, attack explainers) |
| 3075 | Improved: Hardened WebAuthn | CloudPortal (UV required, counter check, single-use challenge) |

---

## Shared across all three servers

### Users

```js
// Users start with passwords only.
// Each user registers a passkey from the dashboard — credentials are device-generated,
// so they cannot be pre-seeded like passwords or TOTP secrets.

const USERS = [
  { username: 'alice', password: 'pass1234',  fullName: 'Alice Chen',   role: 'user' },
  { username: 'bob',   password: 'qwerty123', fullName: 'Bob Martinez', role: 'user' },
  { username: 'admin', password: 'admin456',  fullName: 'Admin User',   role: 'admin' },
];
```

### In-memory stores

```js
const crypto = require('crypto');

// Password-authenticated sessions (Map<token, { username, fullName, role }>)
const sessions = new Map();

// Registered WebAuthn credentials (Map<username, { credentialID: Buffer, credentialPublicKey: Buffer, counter: number, transports: string[] }>)
// One passkey per user for demo simplicity. Production: allow multiple passkeys per user.
const credentialStore = new Map();

// Pending WebAuthn challenges
// Registration: Map<username, { challenge: string (base64url), expiresAt: number }>
const registrationChallenges = new Map();
// Authentication: Map<challengeKey, { challenge: string (base64url), expiresAt: number }>
// On vulnerable server: a single shared key 'auth' (race-condition-prone and reusable).
// On secure server: per-request random key, returned to client, single-use.
const authChallenges = new Map();
```

### requireAuth middleware (password session)

```js
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const session = sessions.get(token);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.user = session;
  req.token = token;
  next();
}
```

### Password login (identical on both servers — starting point before passkey registration)

```js
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token, hasPasskey: credentialStore.has(user.username) });
});

app.post('/api/logout', requireAuth, (req, res) => {
  sessions.delete(req.token);
  res.json({ message: 'Logged out' });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    username: req.user.username,
    fullName: req.user.fullName,
    role: req.user.role,
    hasPasskey: credentialStore.has(req.user.username),
  });
});

app.get('/api/resources', requireAuth, (req, res) => {
  res.json([
    { id: 'vm-001',  name: 'prod-api-01',   type: 'Compute Instance', region: 'us-east-1',  status: 'running' },
    { id: 'db-002',  name: 'primary-db',    type: 'Database',         region: 'us-east-1',  status: 'running' },
    { id: 's3-003',  name: 'assets-bucket', type: 'Object Storage',   region: 'us-west-2',  status: 'active' },
  ]);
});
```

### Client-side base64url helpers (inline in every HTML page)

These are **browser-side** functions. Include them in the `<script>` block of every page that calls WebAuthn.

```js
// WebAuthn API requires ArrayBuffer; the server sends/receives base64url strings.
// These helpers convert between them.

function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Prepare PublicKeyCredentialCreationOptions from server JSON for navigator.credentials.create()
function prepareRegistrationOptions(serverOptions) {
  return {
    ...serverOptions,
    challenge: base64urlToBuffer(serverOptions.challenge),
    user: {
      ...serverOptions.user,
      id: base64urlToBuffer(serverOptions.user.id),
    },
    excludeCredentials: (serverOptions.excludeCredentials || []).map(c => ({
      ...c,
      id: base64urlToBuffer(c.id),
    })),
  };
}

// Prepare PublicKeyCredentialRequestOptions from server JSON for navigator.credentials.get()
function prepareAuthOptions(serverOptions) {
  return {
    ...serverOptions,
    challenge: base64urlToBuffer(serverOptions.challenge),
    allowCredentials: (serverOptions.allowCredentials || []).map(c => ({
      ...c,
      id: base64urlToBuffer(c.id),
    })),
  };
}

// Serialize a PublicKeyCredential (from create) for sending to /api/register/complete
function serializeRegistrationCredential(credential) {
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON:    bufferToBase64url(credential.response.clientDataJSON),
      attestationObject: bufferToBase64url(credential.response.attestationObject),
    },
  };
}

// Serialize a PublicKeyCredential (from get) for sending to /api/auth/complete
function serializeAuthCredential(credential) {
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON:    bufferToBase64url(credential.response.clientDataJSON),
      authenticatorData: bufferToBase64url(credential.response.authenticatorData),
      signature:         bufferToBase64url(credential.response.signature),
      userHandle: credential.response.userHandle
        ? bufferToBase64url(credential.response.userHandle)
        : null,
    },
  };
}
```

---

## Port 3073 — Weak WebAuthn CloudPortal

### File: `passkeys-webauthn/vulnerable-server.js`

**Dependencies:** `express ^4.18.2`, `cors ^2.8.5`, `@simplewebauthn/server ^9.0.0`

```js
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
```

Enable CORS:
```js
const cors = require('cors');
app.use(cors({ origin: 'http://localhost:3074' }));
app.use(express.json());
```

### Registration — begin (vulnerable)

```js
app.get('/api/register/begin', requireAuth, async (req, res) => {
  const { username, fullName } = req.user;

  const options = await generateRegistrationOptions({
    rpName: 'CloudPortal',
    rpID: 'localhost',
    userID: Buffer.from(username),       // ⚠️ using username as userID leaks PII in credential metadata
    userName: username,
    userDisplayName: fullName,
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform', // prefer Touch ID / Windows Hello
      residentKey: 'preferred',
      // ⚠️ VULNERABILITY 1: userVerification 'discouraged' means device touch only.
      // The authenticator will NOT prompt for biometric or PIN.
      // Anyone with physical access to an unlocked device can authenticate.
      userVerification: 'discouraged',
    },
    timeout: 60000,
    // ⚠️ VULNERABILITY 2: No excludeCredentials.
    // The same authenticator can register multiple times for the same user,
    // cluttering the credential store with duplicates.
  });

  // ⚠️ VULNERABILITY 3: Challenge never expires — valid until the server restarts.
  // A captured challenge can be used minutes or hours later.
  registrationChallenges.set(username, { challenge: options.challenge });
  //                                     ^^ no expiresAt

  res.json(options);
});
```

### Registration — complete (vulnerable)

```js
app.post('/api/register/complete', requireAuth, async (req, res) => {
  const { username } = req.user;
  const stored = registrationChallenges.get(username);
  if (!stored) return res.status(400).json({ error: 'No pending registration' });

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: stored.challenge,
      expectedOrigin: 'http://localhost:3073',
      expectedRPID: 'localhost',
      // ⚠️ VULNERABILITY 1 (mirror): must match registration option
      requireUserVerification: false,
    });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const { verified, registrationInfo } = verification;
  if (!verified) return res.status(400).json({ error: 'Registration verification failed' });

  // ⚠️ VULNERABILITY 3 (mirror): challenge NOT deleted after use — reusable
  // Production: registrationChallenges.delete(username);

  const { credentialID, credentialPublicKey, counter } = registrationInfo;
  credentialStore.set(username, {
    credentialID,       // Uint8Array
    credentialPublicKey,// Uint8Array
    counter,            // number (ignored on authentication — see below)
    transports: req.body.response.transports || [],
  });

  res.json({ verified: true, credentialID: Buffer.from(credentialID).toString('base64url') });
});
```

### Authentication — begin (vulnerable)

```js
app.post('/api/auth/begin', async (req, res) => {
  // Discoverable credential flow: client sends no username; the authenticator
  // presents which passkeys are available for this RP.

  const options = await generateAuthenticationOptions({
    rpID: 'localhost',
    // ⚠️ VULNERABILITY 1 (auth mirror): UV discouraged — no biometric prompt
    userVerification: 'discouraged',
    timeout: 60000,
    // No allowCredentials → discoverable / resident key flow
  });

  // ⚠️ VULNERABILITY 4: Single global challenge key — race condition if two
  // users authenticate simultaneously. Also: never invalidated after use.
  authChallenges.set('auth', { challenge: options.challenge });

  res.json(options);
});
```

### Authentication — complete (vulnerable)

```js
app.post('/api/auth/complete', async (req, res) => {
  const stored = authChallenges.get('auth');
  if (!stored) return res.status(400).json({ error: 'No pending authentication' });

  // Find which user this credential belongs to
  let foundUsername = null;
  let cred = null;
  for (const [username, c] of credentialStore.entries()) {
    if (Buffer.from(c.credentialID).toString('base64url') === req.body.id) {
      foundUsername = username;
      cred = c;
      break;
    }
  }
  if (!cred) return res.status(400).json({ error: 'Credential not found — register a passkey first' });

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: stored.challenge,
      expectedOrigin: 'http://localhost:3073',
      expectedRPID: 'localhost',
      authenticator: {
        credentialID:        cred.credentialID,
        credentialPublicKey: cred.credentialPublicKey,
        counter:             cred.counter,
        transports:          cred.transports,
      },
      requireUserVerification: false, // ⚠️ VULNERABILITY 1
    });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const { verified, authenticationInfo } = verification;
  if (!verified) return res.status(400).json({ error: 'Authentication failed' });

  // ⚠️ VULNERABILITY 5: Counter NOT updated after authentication.
  // The stored counter stays at the initial registration value forever.
  // If an attacker clones the credential (copies private key + counter value),
  // both the real credential and the clone produce valid signatures — the server
  // can never detect the clone because it never checks whether the counter advanced.
  // Production: cred.counter = authenticationInfo.newCounter;

  // ⚠️ VULNERABILITY 4 (mirror): challenge NOT deleted — same challenge reusable
  // Production: authChallenges.delete('auth');

  const user = USERS.find(u => u.username === foundUsername);
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token, username: user.username, fullName: user.fullName });
});
```

### Information disclosure endpoint

```js
// ⚠️ VULNERABILITY 6: Credential details exposed — credentialID is a stable
// identifier tied to the user's device. Exposing it lets an attacker enumerate
// registered devices. In phishing scenarios, knowing the credentialID can help
// craft targeted allowCredentials lists.
app.get('/api/debug/credential', (req, res) => {
  const { username } = req.query;
  const cred = credentialStore.get(username);
  if (!cred) return res.status(404).json({ error: 'No passkey registered for this user' });
  res.json({
    username,
    credentialID: Buffer.from(cred.credentialID).toString('base64url'), // ⚠️ never expose
    counter: cred.counter,
    transports: cred.transports,
  });
});
```

### UI — CloudPortal (static HTML + client JS)

**Colors:** `#f8fafc` background, `#0f172a` header bar, `#eff6ff` sidebar, `#3b82f6` accent (blue).

**App flow — three states:**

**State 1 — Login page** (shown when not authenticated):
- Two sections separated by an `<hr>`:
  - **"Sign in with Passkey"** — a single blue button with a fingerprint icon 🔑. Calls the passkey auth flow.
  - **"Sign in with password"** — username + password fields + "Continue" button.
- Amber banner: `⚠️ WEAK WEBAUTHN: User verification is discouraged. No biometric will be prompted.`

**State 2 — Dashboard** (after password login, no passkey registered yet):
- Header: "CloudPortal" + user name + Logout button.
- Resources table from `GET /api/resources`.
- Amber "Passkey Setup" panel:
  ```
  🔑 Secure your account with a Passkey
  Register your device's biometric sensor as a sign-in method.
  No password needed for future logins.
  [Register Passkey]
  ```
  Button calls the registration flow.

**State 3 — Dashboard** (after password login, passkey already registered):
- Green "Passkey Active" banner: `✅ Passkey registered. You can sign in with your device next time.`
- Resources table.
- Logout button.

**Passkey registration JS:**

```js
document.getElementById('btn-register-passkey').addEventListener('click', async function() {
  try {
    // Step 1: Get options from server
    var optRes = await fetch('/api/register/begin', {
      headers: { 'Authorization': 'Bearer ' + localStorage.getItem('cpToken') },
    });
    var serverOptions = await optRes.json();
    if (!optRes.ok) return showResult('passkey-result', 'failure', '✗ ' + serverOptions.error);

    // Step 2: Ask the browser to create a credential (triggers OS biometric prompt)
    var credential;
    try {
      credential = await navigator.credentials.create({ publicKey: prepareRegistrationOptions(serverOptions) });
    } catch (e) {
      if (e.name === 'NotAllowedError') {
        return showResult('passkey-result', 'failure', '✗ Registration cancelled or timed out');
      }
      return showResult('passkey-result', 'failure', '✗ ' + e.message);
    }

    // Step 3: Send attestation to server
    var verRes = await fetch('/api/register/complete', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + localStorage.getItem('cpToken'),
      },
      body: JSON.stringify(serializeRegistrationCredential(credential)),
    });
    var verData = await verRes.json();
    if (!verRes.ok) return showResult('passkey-result', 'failure', '✗ ' + verData.error);

    showResult('passkey-result', 'success', '✅ Passkey registered! Use it next time you log in.');
    // Reload dashboard to show updated state
    setTimeout(() => loadDashboard(), 1200);
  } catch (e) {
    showResult('passkey-result', 'failure', '✗ ' + e.message);
  }
});
```

**Passkey authentication JS (on login page):**

```js
document.getElementById('btn-passkey-login').addEventListener('click', async function() {
  try {
    // Step 1: Get auth challenge from server
    var optRes = await fetch('/api/auth/begin', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
    var serverOptions = await optRes.json();
    if (!optRes.ok) return showResult('auth-result', 'failure', '✗ ' + serverOptions.error);

    // Step 2: Ask the browser to select a passkey and sign the challenge
    var assertion;
    try {
      assertion = await navigator.credentials.get({ publicKey: prepareAuthOptions(serverOptions) });
    } catch (e) {
      if (e.name === 'NotAllowedError') {
        return showResult('auth-result', 'failure', '✗ Authentication cancelled or timed out');
      }
      return showResult('auth-result', 'failure', '✗ ' + e.message);
    }

    // Step 3: Send assertion to server for verification
    var authRes = await fetch('/api/auth/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(serializeAuthCredential(assertion)),
    });
    var authData = await authRes.json();
    if (!authRes.ok) return showResult('auth-result', 'failure', '✗ ' + authData.error);

    localStorage.setItem('cpToken', authData.token);
    loadDashboard();
  } catch (e) {
    showResult('auth-result', 'failure', '✗ ' + e.message);
  }
});
```

**Login input CSS:**
```css
.login-input {
  width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #cbd5e1;
  border-radius: 6px; font-size: 0.95rem; color: #0f172a;
  background: #fff; outline: none; box-sizing: border-box; font-family: inherit;
}
.login-input:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.15); }
.passkey-btn {
  width: 100%; padding: 0.75rem; background: #3b82f6; color: #fff;
  border: none; border-radius: 8px; font-size: 1rem; font-weight: 600;
  cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 0.5rem;
}
.passkey-btn:hover { background: #2563eb; }
```

**WebAuthn unavailability guard:**
```js
// Check if WebAuthn is available before showing passkey buttons
if (!window.PublicKeyCredential) {
  document.getElementById('btn-passkey-login').disabled = true;
  document.getElementById('btn-passkey-login').title = 'WebAuthn not supported in this browser';
  showResult('auth-result', 'info', 'ℹ️ WebAuthn not available — use password login below');
}
```

---

## Port 3074 — Concept Guide

### File: `passkeys-webauthn/guide-server.js`

Open `demo-attacked/reverse-tabnabbing/attacker-server.js`. Find the `DASHBOARD_HTML` constant. Copy its entire `<style>` block **verbatim**. Paste it into this guide's HTML template.

### Page structure

**Title:** `🔑 Passkeys & WebAuthn — How It Works`

**Section 1 — The Problem With Passwords** (`.flow-box`)

Heading: `Why Passwords Keep Failing`

```
Passwords can be:
  ✗ Phished       — user tricked into typing on a fake site
  ✗ Breached       — database dump exposes millions at once
  ✗ Reused         — same password on 50 sites
  ✗ Stolen in transit — MITM or unencrypted connection

Passkeys fix all four:
  ✓ Phishing-resistant — credential is bound to the exact origin (domain + protocol)
  ✓ Not breachable     — server only stores the PUBLIC key; private key never leaves the device
  ✓ Not reusable       — each site gets a different key pair
  ✓ Nothing to intercept — only a signature travels; it's useless without the private key
```

Show in `<pre>` with `color:#00ff41`.

**Section 2 — How WebAuthn Works** (`.flow-box`)

Heading: `Registration Flow (one-time setup)`

ASCII flow:
```
  User                  Browser / OS                 Server (3073)
    │                        │                             │
    │   click "Add Passkey"  │                             │
    │───────────────────────→│                             │
    │                        │── GET /api/register/begin ─→│
    │                        │                             │ generate random challenge
    │                        │←── { challenge, rpID, ... } ┤
    │                        │                             │
    │                        │ generate key pair           │
    │   touch sensor / Face ID                             │
    │←──────────────────────→│ (private key stays on device)
    │                        │                             │
    │                        │── POST /api/register/complete ─→│
    │                        │   { credentialID,           │ verify attestation
    │                        │     attestationObject }     │ store { credentialID, publicKey, counter }
    │                        │                             │
    │                        │←── { verified: true } ──────┤
```

Show in `<pre>`.

Heading: `Authentication Flow (every sign-in)`

ASCII flow:
```
  User                  Browser / OS                 Server (3073)
    │                        │                             │
    │  click "Sign in with   │                             │
    │  Passkey"              │                             │
    │───────────────────────→│                             │
    │                        │── POST /api/auth/begin ────→│
    │                        │                             │ generate fresh challenge
    │                        │←── { challenge, rpID }──────┤
    │                        │                             │
    │                        │ find matching credential    │
    │   touch sensor / Face ID                             │
    │←──────────────────────→│ sign challenge with private key
    │                        │                             │
    │                        │── POST /api/auth/complete ─→│
    │                        │   { signature,              │ verify signature with stored publicKey
    │                        │     authenticatorData }     │ check counter increased
    │                        │←── { token } ───────────────┤
```

Show in `<pre>`.

**Section 3 — Key Concepts** (`.flow-box`)

Heading: `Terms You Need to Know`

```
RP (Relying Party):
  The server / website. Identified by rpID (e.g., "localhost" or "example.com").
  Credentials are bound to rpID — a phishing site on evil.com cannot use a
  credential registered for example.com.

Challenge:
  A random byte string generated fresh by the server for each registration/authentication.
  The client signs it with the private key. Without a fresh unique challenge, an attacker
  could replay a captured signature.

User Presence (UP):
  The authenticator confirmed a human is present (e.g., tapped a button on YubiKey).
  Minimum requirement for userVerification: 'discouraged'.

User Verification (UV):
  The authenticator verified the specific user's identity (Touch ID, Face ID, Windows Hello PIN).
  Required when userVerification: 'required'.
  UP ≠ UV: UP means "someone is there", UV means "the right person is there".

Counter:
  Each authentication increments a counter stored on the authenticator.
  The server should verify the counter is HIGHER than the last recorded value.
  If the counter goes backward or stays the same → possible cloned credential.

Credential ID:
  A handle generated by the authenticator to identify this specific key pair.
  Sent to the server during authentication so it can look up the right public key.
  Not secret — but stable, so treat it like a username.
```

Show in `<pre>`.

**Section 4 — Raw WebAuthn API Demo** (`.flow-box`)

Heading: `🔬 What the Browser API Looks Like`

```html
<pre style="color:#00ff41;font-size:0.78rem;white-space:pre-wrap">
// Registration — what navigator.credentials.create() receives:
navigator.credentials.create({
  publicKey: {
    challenge: ArrayBuffer,           // random bytes from server (decoded from base64url)
    rp: { name: "CloudPortal", id: "localhost" },
    user: {
      id: ArrayBuffer,               // user identifier (not PII)
      name: "alice",
      displayName: "Alice Chen",
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7  },  // ES256 (ECDSA P-256)
      { type: "public-key", alg: -257 }, // RS256 (RSA)
    ],
    authenticatorSelection: {
      userVerification: "required",  // "discouraged" skips biometric
    },
    timeout: 60000,
  }
})
// → returns PublicKeyCredential { id, rawId, response: { attestationObject, clientDataJSON } }

// Authentication — what navigator.credentials.get() receives:
navigator.credentials.get({
  publicKey: {
    challenge: ArrayBuffer,          // fresh random bytes from server
    rpId: "localhost",
    userVerification: "required",
    timeout: 60000,
    // allowCredentials: [] → empty = discoverable credential (passkey) flow
  }
})
// → returns PublicKeyCredential { id, rawId, response: { authenticatorData, signature, clientDataJSON } }
</pre>
```

Live check — whether this browser supports WebAuthn:

```html
<div class="flow-box" style="margin-top:0.5rem">
  <button class="demo-btn" id="btn-check-webauthn">Check WebAuthn support</button>
  <pre class="decoded-box" id="webauthn-check" style="min-height:60px;margin-top:0.5rem">Click to check</pre>
</div>
```

```js
document.getElementById('btn-check-webauthn').addEventListener('click', async function() {
  var out = document.getElementById('webauthn-check');
  if (!window.PublicKeyCredential) {
    out.textContent = '✗ PublicKeyCredential API not available in this browser\nTry Chrome, Edge, Safari, or Firefox 119+';
    return;
  }
  var platformAvail = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  out.textContent =
    '✓ WebAuthn (navigator.credentials) — available\n' +
    (platformAvail
      ? '✓ Platform authenticator (Touch ID / Face ID / Windows Hello) — available\n  You can register and use a passkey on this device.'
      : '✗ Platform authenticator — not available on this device\n  Cross-platform authenticator (hardware key) may still work.\n  On macOS: requires Touch ID-capable machine with Chrome/Safari.\n  On Windows: requires Windows Hello configured.');
});
```

**Section 5 — Attack: User Presence ≠ User Verification** (`.flow-box`)

Heading: `⚠️ Attack: No Biometric Required (Port 3073)`

```
Port 3073 registers and authenticates with userVerification: 'discouraged'.

Result: the OS will NOT prompt for Touch ID, Face ID, or PIN.
The authenticator only checks that a human is present (button tap or no prompt at all).

Scenario:
  1. Alice registers a passkey on port 3073 — no Touch ID prompt
  2. Alice leaves her laptop unlocked and steps away
  3. Mallory walks up, clicks "Sign in with Passkey" on :3073
  4. No biometric prompt — authentication succeeds with device presence only
  5. Mallory is now logged in as alice

Port 3075 uses userVerification: 'required':
  → OS always prompts for Touch ID / Face ID / Windows Hello PIN
  → Even with the unlocked device, the attacker cannot authenticate without biometrics
```

Show in `<pre>`.

**Section 6 — Attack: Credential Cloning / Counter Bypass** (`.flow-box`)

Heading: `⚠️ Attack: Cloned Credential Goes Undetected (Port 3073)`

```
The authenticator counter:
  - Stored on the physical authenticator
  - Starts at 0 on registration
  - Increments by 1 each authentication
  - Sent to the server inside authenticatorData

What the server SHOULD do:
  if (newCounter <= storedCounter) {
    // Counter did not advance → credential may be cloned
    alert("Possible credential clone — revoke and re-register");
  }
  storedCounter = newCounter; // update for next auth

What port 3073 does:
  // ⚠️ counter never updated — always compares against registration value
  // Clone the private key + initial counter → both copies authenticate forever

Note: platform authenticators (Apple, Google, Windows) often return counter = 0
for all authentications because they use a different clone-detection model (TPM binding).
Counter checking is most meaningful for hardware keys (YubiKey, etc.).
The real defense against cloning is hardware attestation at registration time.
```

**Section 7 — Comparison Table** (`.flow-box`)

Heading: `Password vs TOTP vs Passkey`

```html
<table style="width:100%;border-collapse:collapse;font-size:0.82rem;margin-top:0.5rem">
  <tr style="color:#64748b;border-bottom:1px solid #1a3a1a">
    <th style="text-align:left;padding:0.5rem">Property</th>
    <th>Password</th>
    <th>Password + TOTP</th>
    <th>Passkey (WebAuthn)</th>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Phishing-resistant</td>
    <td style="text-align:center;color:#fca5a5">No</td>
    <td style="text-align:center;color:#fbbf24">Partial (TOTP can be phished)</td>
    <td style="text-align:center;color:#4ade80">Yes — bound to origin</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Server breach exposure</td>
    <td style="text-align:center;color:#fca5a5">Password hash stolen</td>
    <td style="text-align:center;color:#fbbf24">TOTP secret stolen</td>
    <td style="text-align:center;color:#4ade80">Public key only (useless alone)</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Replay attack</td>
    <td style="text-align:center;color:#fca5a5">Yes (reuse stolen password)</td>
    <td style="text-align:center;color:#fbbf24">30-second window</td>
    <td style="text-align:center;color:#4ade80">No — challenge is single-use</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">User friction</td>
    <td style="text-align:center;color:#94a3b8">Type password</td>
    <td style="text-align:center;color:#94a3b8">Type password + 6 digits</td>
    <td style="text-align:center;color:#4ade80">Touch sensor / Face ID</td>
  </tr>
  <tr>
    <td style="padding:0.5rem;color:#94a3b8">Device loss risk</td>
    <td style="text-align:center;color:#4ade80">Not device-dependent</td>
    <td style="text-align:center;color:#fbbf24">Need backup codes</td>
    <td style="text-align:center;color:#fbbf24">Need account recovery</td>
  </tr>
</table>
```

**Navigation:** Fixed bottom-left `target-switcher`:
- `Weak WebAuthn (3073)` → `window.open('http://localhost:3073')`
- `Hardened WebAuthn (3075)` → `window.open('http://localhost:3075')`

**Helper CSS (append after verbatim style block):**
```css
.flow-box { max-width: 900px; }

input.field {
  background: #111; border: 1px solid #1a3a1a; color: #00ff41;
  font-family: 'Courier New', Courier, monospace; font-size: 0.82rem;
  padding: 0.4rem 0.6rem; border-radius: 4px;
}
.result-banner { padding: 0.6rem 1rem; border-radius: 4px; font-size: 0.82rem; margin-top: 0.75rem; display: none; }
.result-banner.success { background: #052e16; border: 1px solid #16a34a; color: #4ade80; }
.result-banner.failure { background: #450a0a; border: 1px solid #dc2626; color: #fca5a5; }
.result-banner.info    { background: #0c1a2e; border: 1px solid #1e40af; color: #93c5fd; }
pre.decoded-box {
  background: #0a0a0a; border: 1px solid #1a3a1a; border-radius: 4px;
  padding: 0.75rem; font-size: 0.78rem; color: #cbd5e1;
  white-space: pre-wrap; word-break: break-all; margin-top: 0.5rem;
}
```

```js
function showResult(id, type, msg) {
  var el = document.getElementById(id);
  el.className = 'result-banner ' + type;
  el.textContent = msg;
  el.style.display = 'block';
}
```

---

## Port 3075 — Hardened WebAuthn CloudPortal

### File: `passkeys-webauthn/secure-server.js`

**Dependencies:** `express ^4.18.2`, `cors ^2.8.5`, `@simplewebauthn/server ^9.0.0`

Same imports as port 3073. All four functions from `@simplewebauthn/server`.

### Registration — begin (hardened)

```js
app.get('/api/register/begin', requireAuth, async (req, res) => {
  const { username, fullName } = req.user;

  // ✅ PROTECTED: excludeCredentials prevents re-registering the same authenticator.
  // Avoids duplicate credentials accumulating in the store.
  const existingCred = credentialStore.get(username);
  const excludeCredentials = existingCred
    ? [{ id: existingCred.credentialID, type: 'public-key', transports: existingCred.transports }]
    : [];

  const options = await generateRegistrationOptions({
    rpName: 'CloudPortal',
    rpID: 'localhost',
    userID: Buffer.from(crypto.randomUUID()), // ✅ PROTECTED: opaque UUID, not the username
    userName: username,
    userDisplayName: fullName,
    attestationType: 'none',
    excludeCredentials,
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      // ✅ PROTECTED: userVerification 'required' — Touch ID / Face ID / PIN always prompted.
      // A stolen or borrowed unlocked device cannot authenticate without the user's biometric.
      userVerification: 'required',
    },
    timeout: 60000,
  });

  // ✅ PROTECTED: Challenge stored with expiry — expired challenges are rejected.
  registrationChallenges.set(username, {
    challenge: options.challenge,
    expiresAt: Date.now() + 5 * 60 * 1000, // 5-minute expiry
  });

  res.json(options);
});
```

### Registration — complete (hardened)

```js
app.post('/api/register/complete', requireAuth, async (req, res) => {
  const { username } = req.user;
  const stored = registrationChallenges.get(username);
  if (!stored) return res.status(400).json({ error: 'No pending registration' });

  // ✅ PROTECTED: Reject expired challenges
  if (Date.now() > stored.expiresAt) {
    registrationChallenges.delete(username);
    return res.status(400).json({ error: 'Registration challenge expired — start again' });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: stored.challenge,
      expectedOrigin: 'http://localhost:3075',
      expectedRPID: 'localhost',
      // ✅ PROTECTED: Must match registration option
      requireUserVerification: true,
    });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const { verified, registrationInfo } = verification;
  if (!verified) return res.status(400).json({ error: 'Registration verification failed' });

  // ✅ PROTECTED: Delete challenge after use — one-time use only
  registrationChallenges.delete(username);

  const { credentialID, credentialPublicKey, counter } = registrationInfo;
  credentialStore.set(username, {
    credentialID,
    credentialPublicKey,
    counter,
    transports: req.body.response.transports || [],
  });

  res.json({ verified: true, credentialID: Buffer.from(credentialID).toString('base64url') });
});
```

### Authentication — begin (hardened)

```js
app.post('/api/auth/begin', async (req, res) => {
  const options = await generateAuthenticationOptions({
    rpID: 'localhost',
    // ✅ PROTECTED: UV required — biometric always prompted
    userVerification: 'required',
    timeout: 60000,
  });

  // ✅ PROTECTED: Per-request challenge key — no global race condition.
  // Return the key to the client; it must be presented back in /api/auth/complete.
  const challengeKey = crypto.randomBytes(16).toString('hex');
  authChallenges.set(challengeKey, {
    challenge: options.challenge,
    expiresAt: Date.now() + 5 * 60 * 1000, // 5-minute expiry
  });

  res.json({ ...options, challengeKey });
});
```

### Authentication — complete (hardened)

```js
app.post('/api/auth/complete', async (req, res) => {
  const { challengeKey, ...assertionBody } = req.body;

  // ✅ PROTECTED: Per-request key lookup — no shared global slot
  const stored = authChallenges.get(challengeKey);
  if (!stored) return res.status(400).json({ error: 'No pending authentication' });

  // ✅ PROTECTED: Reject expired challenges
  if (Date.now() > stored.expiresAt) {
    authChallenges.delete(challengeKey);
    return res.status(400).json({ error: 'Authentication challenge expired — try again' });
  }

  // ✅ PROTECTED: Delete challenge immediately — single use, prevents replay
  authChallenges.delete(challengeKey);

  // Find credential
  let foundUsername = null;
  let cred = null;
  for (const [username, c] of credentialStore.entries()) {
    if (Buffer.from(c.credentialID).toString('base64url') === assertionBody.id) {
      foundUsername = username;
      cred = c;
      break;
    }
  }
  if (!cred) return res.status(400).json({ error: 'Credential not found — register a passkey first' });

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: assertionBody,
      expectedChallenge: stored.challenge,
      expectedOrigin: 'http://localhost:3075',
      expectedRPID: 'localhost',
      authenticator: {
        credentialID:        cred.credentialID,
        credentialPublicKey: cred.credentialPublicKey,
        counter:             cred.counter,
        transports:          cred.transports,
      },
      // ✅ PROTECTED: requireUserVerification must match registration intent
      requireUserVerification: true,
    });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const { verified, authenticationInfo } = verification;
  if (!verified) return res.status(400).json({ error: 'Authentication failed' });

  // ✅ PROTECTED: Update counter after each authentication.
  // If the new counter is not higher than the stored one, verifyAuthenticationResponse
  // will already throw — this line persists the new value for the NEXT authentication.
  const previousCounter = cred.counter;
  cred.counter = authenticationInfo.newCounter;

  // ✅ PROTECTED: Log counter anomaly (informational — platform authenticators may return 0)
  if (authenticationInfo.newCounter > 0 && authenticationInfo.newCounter <= previousCounter) {
    console.warn(`[SECURITY] Counter anomaly for user ${foundUsername}: `
      + `stored=${previousCounter}, received=${authenticationInfo.newCounter}. `
      + `Possible cloned credential.`);
    // Production: revoke credential, notify user
  }

  const user = USERS.find(u => u.username === foundUsername);
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token, username: user.username, fullName: user.fullName });
});
```

### UI differences from port 3073

Same CloudPortal design and flow as port 3073 with these changes:

1. **Green banner instead of amber:**
   ```
   ✅ HARDENED WEBAUTHN: User verification required. Your biometric is always prompted.
   Challenge is single-use and expires in 5 minutes.
   ```

2. **Auth begin passes `challengeKey`:** The server returns `{ ...options, challengeKey }`. The client must store `challengeKey` from the begin response and include it in the complete request:
   ```js
   var challengeKey = serverOptions.challengeKey; // store this
   // ... after navigator.credentials.get() ...
   body: JSON.stringify({ challengeKey, ...serializeAuthCredential(assertion) })
   ```

3. **Counter displayed on dashboard** (after passkey auth): Show `Authenticator counter: N` in the passkey info panel so users can watch it increment on each sign-in.

---

## Shared `package.json` at `passkeys-webauthn/`

```json
{
  "name": "passkeys-webauthn-demo",
  "version": "1.0.0",
  "scripts": {
    "vulnerable": "node vulnerable-server.js",
    "guide":      "node guide-server.js",
    "secure":     "node secure-server.js"
  },
  "dependencies": {
    "express":               "^4.18.2",
    "cors":                  "^2.8.5",
    "@simplewebauthn/server": "^9.0.0"
  }
}
```

---

## README at `passkeys-webauthn/README.md`

### How It Works

```
Registration (one-time):
  GET  /api/register/begin   → { challenge, rpID, user, ... }    (requires password session)
  Browser: navigator.credentials.create({ publicKey: options })
         → user touches sensor → key pair generated on device
  POST /api/register/complete { credentialID, attestationObject }
         → server verifies + stores { credentialID, publicKey, counter }

Authentication (every sign-in):
  POST /api/auth/begin       → { challenge, rpID }
  Browser: navigator.credentials.get({ publicKey: options })
         → user selects passkey + touches sensor → assertion signed
  POST /api/auth/complete    { signature, authenticatorData }
         → server verifies signature with stored publicKey → issues session token

Weak   (3073): UV discouraged, no counter update, challenge reusable, no expiry
Hardened (3075): UV required, counter updated, challenge single-use + 5-min expiry
```

### Prerequisites

WebAuthn requires a **secure context**: HTTPS or localhost. Running on `localhost:307x` satisfies this requirement — no HTTPS setup needed for development.

You also need a platform authenticator:
- macOS: Touch ID (Safari, Chrome, or Edge — not Firefox on macOS for platform auth)
- Windows: Windows Hello (PIN, fingerprint, or face)
- iOS/Android: FaceID, TouchID, or screen lock

### Run the demo

```bash
cd auth-concepts/passkeys-webauthn
npm install
npm run vulnerable  # terminal 1 → localhost:3073
npm run guide       # terminal 2 → localhost:3074
npm run secure      # terminal 3 → localhost:3075
```

### Walkthrough

1. Open **localhost:3074** — read the registration/authentication flows.
2. Open **localhost:3073** — log in as alice / pass1234. Click "Register Passkey". Note: no biometric prompt (UV discouraged).
3. Log out. Click "Sign in with Passkey". No biometric prompt — just device presence.
4. Open **localhost:3075** — repeat the same flow. Note: your OS now prompts for Touch ID / Windows Hello PIN.
5. On :3073, open DevTools → Network. Note the auth challenge in `/api/auth/begin`. Make a second call with the same challenge — it succeeds (replay). On :3075, the challenge is deleted after first use.

### Key Concepts

**Private key never leaves the device:** The `navigator.credentials.create()` call generates a key pair inside the device's secure enclave (TPM, Secure Enclave, etc.). The private key is never accessible to JavaScript — only to the OS authenticator.

**Credentials are origin-bound:** A passkey created for `localhost:3073` cannot be used on `localhost:3075` or any other origin. This is enforced by the browser — the signature includes a hash of the `clientData` containing the origin. A phishing site on a different domain simply cannot produce a valid signature for your real domain.

**`userVerification: 'required'` is the meaningful security upgrade:** UV means the authenticator verified the user's identity (biometric or PIN), not just that someone tapped a button. Without UV, physical device access = authentication.

**Counter checking matters for hardware keys:** Platform authenticators (Apple, Google, Microsoft) often return counter = 0 for all authentications, using TPM binding instead. Counter checking is critical for hardware security keys (YubiKey, etc.) where cloning is physically possible.

---

## Key technical notes for Cursor

1. **`@simplewebauthn/server` v9 takes base64url strings for challenges.** `generateRegistrationOptions()` returns `{ challenge: string (base64url), ... }`. Store this string directly. Pass it as `expectedChallenge` in `verifyRegistrationResponse()`. Do not convert to Buffer on the server — the library expects strings.

2. **Client-side conversions are mandatory.** `navigator.credentials.create()` and `navigator.credentials.get()` require `challenge` to be an `ArrayBuffer`, not a string. Use `base64urlToBuffer()` before calling the browser API. Conversely, the credential returned by the browser contains `ArrayBuffer` fields — use `bufferToBase64url()` before JSON serialization and sending to the server.

3. **`credentialID` and `credentialPublicKey` are `Uint8Array`** (returned from `verifyRegistrationResponse`). Store them as-is. Pass them directly to `verifyAuthenticationResponse` as `authenticator.credentialID` and `authenticator.credentialPublicKey`. Do not convert to string for storage — keep them as `Uint8Array` in the in-memory Map.

4. **`userID` in registration should be opaque.** Use `Buffer.from(crypto.randomUUID())` rather than `Buffer.from(username)`. The userID appears in the credential metadata on the device and can be read by some authenticators — embedding the username leaks PII.

5. **`localhost` is a valid secure context.** WebAuthn works on `http://localhost` without HTTPS — browsers treat localhost as a secure origin. The `rpID` should be `'localhost'` and `expectedOrigin` should be `'http://localhost:3073'` (or 3075). Mismatching these causes `verifyRegistrationResponse` to throw.

6. **WebAuthn unavailability is common.** `window.PublicKeyCredential` is `undefined` in HTTP iframes, some older browsers, and certain OS configurations. Always check for it and show a graceful fallback to password login. `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()` is an additional async check for whether the device has a biometric sensor registered.

7. **`NotAllowedError` from `navigator.credentials.*`.** This is thrown when the user cancels the biometric prompt, the operation times out, or the RP is not a secure context. Catch it separately and show a clear "cancelled or timed out" message rather than a generic error.

8. **The `challengeKey` pattern (port 3075).** The secure server generates a per-request key alongside the challenge, returns it in the begin response, and requires it in the complete request. The client stores it between the two requests (e.g., in a `var challengeKey` variable). This solves the race condition where two simultaneous logins would overwrite each other's challenge in the global Map.

9. **`excludeCredentials` on registration requires the stored `credentialID` as a `Buffer` or `Uint8Array`.** Pass it directly from `credentialStore.get(username).credentialID` — it is already the right type from the previous `verifyRegistrationResponse` call.

10. **Platform authenticator counter behavior.** Apple's Secure Enclave and Android's StrongBox often return `counter: 0` for all assertions (they use device-binding instead). `verifyAuthenticationResponse` from `@simplewebauthn/server` does NOT fail when `newCounter === 0 && counter === 0` — it only rejects if `newCounter < counter` for non-zero values. The counter anomaly log in the secure server is therefore advisory for hardware key scenarios.
