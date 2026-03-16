// Safe: all sensitive routes have auth middleware
const express = require('express');
const app = express();
const { authMiddleware } = require('./middleware/auth');

app.delete('/users/:id', authMiddleware, (req, res) => {
  db.deleteUser(req.params.id);
  res.json({ deleted: true });
});

router.post('/admin/settings', isAuthenticated, (req, res) => {
  updateSettings(req.body);
  res.json({ ok: true });
});

// Global auth on router
router.use(requireAuth);
router.put('/account/billing', (req, res) => {
  updateBilling(req.body);
  res.json({ ok: true });
});
