/*
 * Terminal 2: cd auth-concepts/jwt-bearer && npm run guide
 * JWT & Bearer Lab — concept guide (port 3059)
 */

const path = require('path');
const express = require('express');

const app = express();
const PORT = 3059;

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'guide.html'));
});

app.listen(PORT, function () {
  console.log('JWT & Bearer Lab running at http://localhost:' + PORT);
});
