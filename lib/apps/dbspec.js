'use strict';
// Database details typed into an installer wizard: database name, database user, password (+ WordPress table prefix).
// Empty = the installer picks safe random values (the 1.0.3 behaviour).
const c = require('../core');
const dbs = require('../dbs');

function cleanDbSpec(input) {
  const name = String(input.dbName || '').trim().toLowerCase(), user = String(input.dbUser || '').trim().toLowerCase(), password = String(input.dbPassword || '');
  if (!name && !user && !password) return null;
  if (!name) throw new Error('Enter a database name');
  const spec = { name: dbs.cleanName(name, 'Database name'), user: dbs.cleanName(user || name, 'Database user'), password: password || c.genPassword(20) };
  dbs.cleanPassword(spec.password);
  return spec;
}
const PREFIX_RE = /^[A-Za-z][A-Za-z0-9]{0,15}_$/;
function cleanPrefix(v) {
  const p = String(v == null ? '' : v).trim();
  if (!p) return '';
  if (!PREFIX_RE.test(p)) throw new Error('Table prefix: a letter, then letters or numbers, ending with an underscore (for example wp_ or site1_)');
  return p;
}
module.exports = { cleanDbSpec, cleanPrefix, PREFIX_RE };
