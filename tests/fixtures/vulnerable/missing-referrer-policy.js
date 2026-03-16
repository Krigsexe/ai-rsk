// VULNERABLE: Express server without Referrer-Policy header
const express = require('express');
const app = express();

app.use(cors());
app.get('/api/users', (req, res) => {
  res.json(users);
});

app.listen(3000);
