/*
 * Terminal 2: cd auth-concepts/sso && npm run guide
 * SSO Lab — concept guide (port 3065)
 */

const path = require('path');
const express = require('express');

const app = express();
const PORT = 3065;

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'guide.html'));
});

app.listen(PORT, function () {
  console.log('SSO Lab running at http://localhost:' + PORT);
});
