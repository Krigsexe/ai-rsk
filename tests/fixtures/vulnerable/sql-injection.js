// Vulnerable: SQL injection via string concatenation
const userId = req.params.id;
db.query("SELECT * FROM users WHERE id = " + userId);
db.query(`SELECT * FROM users WHERE email = ${req.body.email}`);
db.query("DELETE FROM posts WHERE author = '" + username + "'");
