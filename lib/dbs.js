'use strict';
// HostPanel databases: a database, its users and their passwords are separate things.
//   database  { name, site, ownerId, users:[...], created }       (registry: db.json "dbs")
//   user      { user, site, ownerId, created }                    (registry: db.json "dbusers")
// A user can be given access to several databases of the SAME website; deleting the last database of a user drops the user.
// Every identifier is validated against NAME_RE and every password against core.PW_RE before it reaches SQL;
// db names inside GRANT/REVOKE have "_" escaped (it is a wildcard there, so wp_a would also match wpXa).
const c = require('./core');
const { sh, load, save, genPassword, validPassword } = c;

const NAME_RE = /^[a-z][a-z0-9_]{2,31}$/;
const RESERVED = new Set(['mysql', 'sys', 'root', 'test', 'mariadb', 'information_schema', 'performance_schema', 'admin', 'debian_sys_maint', 'mysql_native_password', 'phpmyadmin', 'pma']);
const MAX_DBS_CUSTOMER = 10;

const q = (v) => { v = String(v); if (/[\0\r\n\x1a]/.test(v)) throw new Error('Invalid character'); return "'" + v.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'"; };
const bt = (n) => { if (!/^[a-z][a-z0-9_]{1,40}$/.test(n)) throw new Error('Bad name'); return '`' + n + '`'; };
const gdb = (n) => { bt(n); return '`' + n.replace(/_/g, '\\_') + '`'; };
const acct = (u) => { if (!/^[a-z][a-z0-9_]{1,40}$/.test(u)) throw new Error('Bad user'); return q(u) + '@' + q('localhost'); };
const mysql = (sql) => sh('mysql', [], sql);

function cleanName(v, what) {
  const n = String(v || '').trim().toLowerCase();
  if (!NAME_RE.test(n)) throw new Error(what + ': 3-32 characters, a-z 0-9 and _, must start with a letter');
  if (RESERVED.has(n)) throw new Error('That ' + what.toLowerCase() + ' is reserved - choose another');
  return n;
}
function cleanPassword(v) {
  if (!validPassword(v)) throw new Error('Database password: 12-64 characters from A-Z a-z 0-9 and ! @ # % ^ * _ + = . , : ; ~ -');
  return String(v);
}
const dropSql = (name, users) => 'DROP DATABASE IF EXISTS ' + bt(name) + ';\n' + users.map((u) => 'DROP USER IF EXISTS ' + acct(u) + ';\n').join('') + 'FLUSH PRIVILEGES;\n';

/* ---------- create ---------- */
// o: { name, user, password, site, ownerId, extra, requireNewUser }.  Returns { name, user, password, host, reused }.
function create(o) {
  const name = cleanName(o.name, 'Database name'), user = cleanName(o.user || o.name, 'Database user');
  const site = String(o.site || ''), d = load();
  if (d.dbs.find((x) => x.name === name)) throw new Error('Database already exists');
  const known = d.dbusers.find((u) => u.user === user);
  let pass = o.password || '', fresh = true;
  if (known) {
    if (o.requireNewUser || !site || (known.site || '') !== site) throw new Error('That database user name is not available');
    fresh = false; pass = '';
  } else {
    if (!pass) pass = genPassword(20);
    cleanPassword(pass);
  }
  if (sh('mysql', ['-N', '-B'], 'SHOW DATABASES LIKE \'' + name + '\';\n').trim()) throw new Error('A database with that name already exists on this server');
  if (fresh && sh('mysql', ['-N', '-B'], 'SELECT User FROM mysql.user WHERE User = \'' + user + '\';\n').trim()) throw new Error('A database user with that name already exists on this server');
  try {
    mysql('CREATE DATABASE ' + bt(name) + ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n' + (fresh ? 'CREATE USER ' + acct(user) + ' IDENTIFIED BY ' + q(pass) + ';\n' : '') +
      'GRANT ALL PRIVILEGES ON ' + gdb(name) + '.* TO ' + acct(user) + ';\nFLUSH PRIVILEGES;\n');
  } catch (e) {
    // both names were verified free above, so anything that exists now was created by this attempt
    try { mysql('DROP DATABASE IF EXISTS ' + bt(name) + ';\n' + (fresh ? 'DROP USER IF EXISTS ' + acct(user) + ';\n' : '')); } catch (x) {}
    throw e;
  }
  const created = new Date().toISOString();
  try {
    const d2 = load();
    d2.dbs.push(Object.assign({ name, created, site, ownerId: o.ownerId || 'system', user, users: [user] }, o.extra || {}));
    if (fresh) d2.dbusers.push({ user, site, ownerId: o.ownerId || 'system', created });
    save(d2);
  } catch (e) {
    try { mysql(dropSql(name, fresh ? [user] : [])); } catch (x) {} // never leave an unregistered database behind
    throw e;
  }
  if (site) { try { syncPma(site); } catch (e) { c.auditSys('PMA_SYNC_FAILED', site + ': ' + c.errMsg(e)); } }
  return { name, user, password: pass || undefined, host: 'localhost', reused: !fresh };
}

/* ---------- users ---------- */
function find(d, name) { const x = d.dbs.find((y) => y.name === name); if (!x) throw new Error('Database not found'); return x; }
const usedBy = (d, user) => d.dbs.filter((x) => (x.users || []).includes(user));

function addUser(dbName, o) {
  const d = load(), db = find(d, dbName), user = cleanName(o.user, 'Database user');
  if ((db.users || []).includes(user)) throw new Error(user + ' already has access to ' + dbName);
  const known = d.dbusers.find((u) => u.user === user);
  let pass = '', fresh = !known;
  if (known) { if (!db.site || (known.site || '') !== db.site) throw new Error('That database user name is not available'); }
  else {
    if (sh('mysql', ['-N', '-B'], 'SELECT User FROM mysql.user WHERE User = \'' + user + '\';\n').trim()) throw new Error('A database user with that name already exists on this server');
    pass = o.password || genPassword(20); cleanPassword(pass);
  }
  mysql((fresh ? 'CREATE USER ' + acct(user) + ' IDENTIFIED BY ' + q(pass) + ';\n' : '') + 'GRANT ALL PRIVILEGES ON ' + gdb(db.name) + '.* TO ' + acct(user) + ';\nFLUSH PRIVILEGES;\n');
  const d2 = load(), db2 = find(d2, dbName);
  db2.users = (db2.users || []).concat([user]);
  if (fresh) d2.dbusers.push({ user, site: db2.site, ownerId: db2.ownerId, created: new Date().toISOString() });
  save(d2);
  return { user, password: pass || undefined, reused: !fresh };
}
function removeUser(dbName, user) {
  const d = load(), db = find(d, dbName);
  if (!(db.users || []).includes(user)) throw new Error('That user has no access to this database');
  mysql('REVOKE ALL PRIVILEGES ON ' + gdb(db.name) + '.* FROM ' + acct(user) + ';\nFLUSH PRIVILEGES;\n');
  db.users = db.users.filter((u) => u !== user);
  let dropped = false;
  if (!usedBy(d, user).length) { try { mysql('DROP USER IF EXISTS ' + acct(user) + ';\nFLUSH PRIVILEGES;\n'); } catch (e) {} d.dbusers = d.dbusers.filter((u) => u.user !== user); dropped = true; }
  save(d);
  return dropped;
}
function setPassword(user, password) {
  const d = load();
  if (!d.dbusers.find((u) => u.user === user)) throw new Error('Database user not found');
  const pass = password || genPassword(20); cleanPassword(pass);
  mysql('ALTER USER ' + acct(user) + ' IDENTIFIED BY ' + q(pass) + ';\nFLUSH PRIVILEGES;\n');
  return pass;
}

/* ---------- delete ---------- */
function finalDelete(name) {
  const d = load(), db = find(d, name);
  const toDrop = (db.users || []).filter((u) => usedBy(d, u).length === 1);
  mysql(dropSql(name, toDrop).replace('DROP DATABASE IF EXISTS', 'DROP DATABASE'));
  const d2 = load();
  d2.dbs = d2.dbs.filter((x) => x.name !== name);
  d2.dbusers = d2.dbusers.filter((u) => !toDrop.includes(u.user));
  save(d2);
  if (db.site) { try { syncPma(db.site); } catch (e) {} }
  c.auditSys('DB_DELETED', name);
}
// Undo for a database this process just created (failed app install). Idempotent; the registry never keeps a half-dropped entry.
function dropQuiet(name) {
  if (!NAME_RE.test(String(name))) throw new Error('Bad database name');
  const d = load(), db = d.dbs.find((x) => x.name === name), users = db ? (db.users || []).filter((u) => usedBy(d, u).length === 1) : [name];
  try { mysql(dropSql(name, users)); } finally {
    const d2 = load(); d2.dbs = d2.dbs.filter((x) => x.name !== name); d2.dbusers = d2.dbusers.filter((u) => !users.includes(u.user)); save(d2);
  }
}

/* ---------- which website a database belongs to ---------- */
function assignSite(name, site, ownerId) {
  const d = load(), db = find(d, name), old = db.site;
  for (const u of db.users || []) if (usedBy(d, u).some((x) => x.name !== name && (x.site || '') !== (site || ''))) throw new Error('User ' + u + ' is also used by a database of another website');
  db.site = site || ''; db.ownerId = ownerId || 'system';
  for (const u of d.dbusers) if ((db.users || []).includes(u.user)) { u.site = db.site; u.ownerId = db.ownerId; }
  save(d);
  for (const dom of new Set([old, site].filter(Boolean))) { try { syncPma(dom); } catch (e) {} }
}
function reassignOwner(domain, ownerId) { // a website changed owner: its databases and users follow
  const d = load();
  for (const x of d.dbs) if (x.site === domain) x.ownerId = ownerId || 'system';
  for (const u of d.dbusers) if (u.site === domain) u.ownerId = ownerId || 'system';
  save(d);
}
function detachSite(domain) { // website deleted: databases stay (they may hold data) but become administrator-owned
  const d = load();
  for (const x of d.dbs) if (x.site === domain) { x.site = ''; x.ownerId = 'system'; }
  for (const u of d.dbusers) if (u.site === domain) { u.site = ''; u.ownerId = 'system'; }
  save(d);
}

/* ---------- phpMyAdmin account: one MariaDB user per website, privileges only on that website's databases ---------- */
const ADMIN_PMA = '*';
function pmaAccount(domain) {
  const d = load();
  if (domain === ADMIN_PMA) return { user: 'pma_admin', stored: d.settings.pmaAdmin || null, dbs: d.dbs.map((x) => x.name), admin: true };
  const s = d.sites.find((x) => x.domain === domain);
  if (!s) throw new Error('Site not found');
  return { user: 'pma_' + s.user, stored: s.pma || null, dbs: d.dbs.filter((x) => x.site === domain).map((x) => x.name), site: s };
}
// Creates the account if needed and makes its privileges match the registry exactly (REVOKE ALL first: grants on a dropped
// database survive in MariaDB, so a later database with the same name would otherwise be reachable).
function syncPma(domain) {
  const a = pmaAccount(domain), pass = (a.stored && a.stored.password) || genPassword(24);
  mysql('CREATE USER IF NOT EXISTS ' + acct(a.user) + ' IDENTIFIED BY ' + q(pass) + ';\nALTER USER ' + acct(a.user) + ' IDENTIFIED BY ' + q(pass) + ';\n' +
    'REVOKE ALL PRIVILEGES, GRANT OPTION FROM ' + acct(a.user) + ';\n' + a.dbs.map((n) => 'GRANT ALL PRIVILEGES ON ' + gdb(n) + '.* TO ' + acct(a.user) + ';\n').join('') + 'FLUSH PRIVILEGES;\n');
  if (!a.stored) { const d = load(); if (a.admin) d.settings.pmaAdmin = { user: a.user, password: pass }; else d.sites.find((x) => x.domain === domain).pma = { user: a.user, password: pass }; save(d); }
  return { user: a.user, password: pass };
}
function dropPma(domain) {
  try { const a = pmaAccount(domain); mysql('DROP USER IF EXISTS ' + acct(a.user) + ';\nFLUSH PRIVILEGES;\n'); } catch (e) {}
}

module.exports = { NAME_RE, RESERVED, MAX_DBS_CUSTOMER, ADMIN_PMA, q, gdb, cleanName, cleanPassword, create, addUser, removeUser, setPassword, finalDelete, dropQuiet, assignSite, reassignOwner, detachSite, syncPma, dropPma, pmaAccount, usedBy };
