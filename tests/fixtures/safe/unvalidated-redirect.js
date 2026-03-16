// SAFE: Validated redirect with allowlist
const ALLOWED_REDIRECTS = ['/dashboard', '/settings', '/profile'];
app.get('/callback', (req, res) => {
  const target = req.query.returnUrl;
  if (ALLOWED_REDIRECTS.includes(target)) {
    res.redirect(target);
  } else {
    res.redirect('/dashboard');
  }
});
