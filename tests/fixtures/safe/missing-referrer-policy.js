// SAFE: Express server with Referrer-Policy via helmet
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet());
app.get('/api/users', (req, res) => {
  res.json(users);
});

app.listen(3000);
