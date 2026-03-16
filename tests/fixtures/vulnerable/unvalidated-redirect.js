// VULNERABLE: Open redirect with user-controlled URL
app.get('/callback', (req, res) => {
  res.redirect(req.query.returnUrl);
});
app.get('/goto', (req, res) => {
  const redirectUrl = req.body.url;
  res.redirect(redirectUrl);
});
