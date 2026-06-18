/*
 * Terminal 2: cd auth-concepts/basic-digest && npm run guide
 * Basic & Digest Auth Lab — concept guide (port 3050)
 */

const path = require('path');
const express = require('express');

const app = express();
const PORT = 3050;

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'guide.html'));
});

app.listen(PORT, function () {
  console.log('Basic & Digest Auth Lab running at http://localhost:' + PORT);
});
