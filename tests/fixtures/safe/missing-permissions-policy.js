// SAFE: Express server with Permissions-Policy header set manually
const express = require('express');
const app = express();

app.use((req, res, next) => {
  res.setHeader('Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
  );
  next();
});

app.get('/api/data', (req, res) => {
  res.json(data);
});

app.listen(3000);
