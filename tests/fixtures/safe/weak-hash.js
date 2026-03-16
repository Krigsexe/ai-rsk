// Safe: bcrypt with proper cost factor
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);
const salt = await bcrypt.genSalt(12);

// Safe: argon2
const argon2 = require('argon2');
const argonHash = await argon2.hash(password);

// Safe: SHA256 for non-password use (file checksums)
const crypto = require('crypto');
const fileChecksum = crypto.createHash('sha256').update(fileBuffer).digest('hex');
