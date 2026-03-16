// Safe: path.basename strips directory traversal
const fs = require('fs');
const path = require('path');

app.get('/download', (req, res) => {
  const safeName = path.basename(req.query.file);
  fs.readFile(path.join('/uploads', safeName), (err, data) => {
    res.send(data);
  });
});

// Safe: whitelist approach
const allowedFiles = ['report.pdf', 'invoice.pdf'];
app.get('/docs/:name', (req, res) => {
  if (!allowedFiles.includes(req.params.name)) {
    return res.status(403).json({ error: 'Not allowed' });
  }
  fs.readFile(path.join('/docs', req.params.name), (err, data) => {
    res.send(data);
  });
});
