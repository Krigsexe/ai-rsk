// Vulnerable: Math.random() for security tokens
const token = Math.random().toString(36).substring(2);
const sessionId = 'sess_' + Math.random().toString(36);
const otp = Math.floor(Math.random() * 1000000);
const resetToken = Math.random().toString(16).slice(2);
