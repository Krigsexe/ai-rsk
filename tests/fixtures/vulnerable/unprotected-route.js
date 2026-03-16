// Vulnerable: delete route with no auth middleware
const express = require('express');
const app = express();

app.delete('/users/:id', (req, res) => {
  db.deleteUser(req.params.id);
  res.json({ deleted: true });
});

router.post('/admin/settings', (req, res) => {
  updateSettings(req.body);
  res.json({ ok: true });
});

app.put('/account/billing', (req, res) => {
  updateBilling(req.body);
  res.json({ ok: true });
});
