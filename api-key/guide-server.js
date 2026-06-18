/*
 * Terminal 2: cd auth-concepts/api-key && npm run guide
 * API Key Auth Lab — concept guide (port 3056)
 */

const path = require('path');
const express = require('express');

const app = express();
const PORT = 3056;

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'guide.html'));
});

app.listen(PORT, function () {
  console.log('API Key Auth Lab running at http://localhost:' + PORT);
});
