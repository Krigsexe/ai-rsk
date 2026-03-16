// VULNERABLE: Express server without Permissions-Policy header
const express = require('express');
const app = express();

app.use(cors());
app.get('/api/data', (req, res) => {
  res.json(data);
});

app.listen(3000);
