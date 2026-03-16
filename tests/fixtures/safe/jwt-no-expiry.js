// Safe: JWT with expiration
const jwt = require('jsonwebtoken');
const token = jwt.sign({ userId: user.id }, process.env.SECRET, { expiresIn: '15m' });
const refresh = jwt.sign({ userId: user.id }, process.env.REFRESH_SECRET, { expiresIn: '7d' });
