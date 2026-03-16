// Safe: crypto.randomBytes for tokens
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
const sessionId = crypto.randomUUID();
const otp = crypto.randomInt(100000, 999999);

// Safe: Math.random() for non-security purposes (UI, animation, shuffle)
const randomColor = Math.random() * 360;
const shuffleIndex = Math.floor(Math.random() * array.length);
