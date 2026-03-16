// Vulnerable: bcrypt cost too low
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 4);
const hashSync = bcrypt.hashSync(password, 6);
const salt = await bcrypt.genSalt(3);

// Vulnerable: MD5 for password
const crypto = require('crypto');
const md5Hash = crypto.createHash('md5').update(password).digest('hex');

// Vulnerable: SHA1 for password
const sha1Hash = crypto.createHash('sha1').update(password).digest('hex');
