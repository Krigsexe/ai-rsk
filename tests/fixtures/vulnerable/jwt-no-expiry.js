// Vulnerable: JWT signed without expiration
const jwt = require('jsonwebtoken');
const token = jwt.sign({ userId: user.id, role: 'admin' }, process.env.SECRET);
