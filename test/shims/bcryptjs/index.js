'use strict';
const crypto = require('crypto');
exports.hashSync = (pw) => { const salt = crypto.randomBytes(8).toString('hex'); return 'shim$' + salt + '$' + crypto.scryptSync(String(pw), salt, 32).toString('hex'); };
exports.compareSync = (pw, h) => { const [, salt, hash] = String(h).split('$'); if (!salt || !hash) return false; const a = Buffer.from(crypto.scryptSync(String(pw), salt, 32).toString('hex')), b = Buffer.from(hash); return a.length === b.length && crypto.timingSafeEqual(a, b); };
