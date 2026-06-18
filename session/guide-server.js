/*
 * Terminal 2: cd auth-concepts/session && npm run guide
 * Session Auth Lab — concept guide (port 3053)
 */

const path = require('path');
const express = require('express');

const app = express();
const PORT = 3053;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/demo-cookie', function (req, res) {
  res.json({
    port3052: 'Set-Cookie: nk_session=<token>; Path=/; SameSite=Lax',
    port3054: 'Set-Cookie: nk_session=<token>; Path=/; HttpOnly; SameSite=Strict',
    difference: 'HttpOnly prevents JavaScript from reading the cookie via document.cookie',
  });
});

app.get('/', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'guide.html'));
});

app.listen(PORT, function () {
  console.log('Session Auth Lab running at http://localhost:' + PORT);
});
