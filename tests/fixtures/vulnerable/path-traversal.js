// Vulnerable: user-controlled path in fs operations
const fs = require('fs');
const path = require('path');

app.get('/download', (req, res) => {
  fs.readFile(path.join('/uploads', req.query.file), (err, data) => {
    res.send(data);
  });
});

app.delete('/files/:name', (req, res) => {
  fs.unlinkSync('/data/' + req.params.name);
  res.json({ deleted: true });
});
