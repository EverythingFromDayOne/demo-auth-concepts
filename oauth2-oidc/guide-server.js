/*
 * Terminal 2: cd auth-concepts/oauth2-oidc && npm run guide
 * OAuth2 & OIDC Lab (port 3068)
 */

const path = require('path');
const express = require('express');

const app = express();
const PORT = 3068;

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'guide.html'));
});

app.listen(PORT, function () {
  console.log('OAuth2 & OIDC Lab running at http://localhost:' + PORT);
});
