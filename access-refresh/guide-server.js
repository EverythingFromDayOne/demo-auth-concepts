/*
 * Terminal 2: cd auth-concepts/access-refresh && npm run guide
 * Token Lifecycle Lab — concept guide (port 3062)
 */

const path = require('path');
const express = require('express');

const app = express();
const PORT = 3062;

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'guide.html'));
});

app.listen(PORT, function () {
  console.log('Token Lifecycle Lab running at http://localhost:' + PORT);
});
