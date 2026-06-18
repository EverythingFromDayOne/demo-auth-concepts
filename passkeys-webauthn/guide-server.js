/*
 * Passkeys & WebAuthn Lab - port 3074
 */
const path = require('path');
const express = require('express');

const app = express();
const PORT = 3074;

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'guide.html'));
});

app.listen(PORT, () => console.log(`Passkeys & WebAuthn Lab running at http://localhost:${PORT}`));
