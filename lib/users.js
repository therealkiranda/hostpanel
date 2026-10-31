'use strict';
// Client logins: an administrator creates a login for a client and assigns one or more websites to it. The client signs
// in on the normal login page and only ever sees those websites (and the databases, backups, files... of those websites).
const tenancy = require('./tenancy');
const c = require('./core');
const dbs = require('./dbs');

const DUMMY = c.bcrypt.hashSync('dummy-password-for-timing', 10);
const findByName = (d, name) => d.users.find((u) => u.username.toLowerCase() === String(name || '').trim().toLowerCase()) || null;
const byId = (d, id) => d.users.find((u) => u.id === id) || null;

function add(f) {
  const d = c.load();
  if (String(f.username || '').trim().toLowerCase() === String(d.admin.user).toLowerCase()) throw new Error('That username is reserved');
  const u = tenancy.createUser(d, { username: f.username, email: f.email, password: f.password, role: 'customer' }, (p) => c.bcrypt.hashSync(p, 12));
  const rec = byId(d, u.id); rec.mustChange = f.mustChange !== false; rec.sv = 1; rec.lastLogin = '';
  c.save(d);
  return u;
}
// Returns the user when the password is right and the account is active; always spends one bcrypt comparison.
function authenticate(name, password) {
  const d = c.load(), u = findByName(d, name);
  const okPw = c.bcrypt.compareSync(String(password || ''), u ? u.passwordHash : DUMMY);
  return u && okPw && u.active !== false ? u : null;
}
function touchLogin(id) { const d = c.load(), u = byId(d, id); if (u) { u.lastLogin = new Date().toISOString(); c.save(d); } }
function setPassword(id, pw, mustChange) {
  const d = c.load(), u = byId(d, id); if (!u) throw new Error('User not found');
  pw = String(pw || ''); if (pw.length < 12 || pw.length > 200) throw new Error('Password must be 12-200 characters');
  u.passwordHash = c.bcrypt.hashSync(pw, 12); u.mustChange = !!mustChange; u.sv = (u.sv || 1) + 1; c.save(d); return u.sv;
}
function setActive(id, on) { const d = c.load(), u = byId(d, id); if (!u) throw new Error('User not found'); u.active = !!on; u.sv = (u.sv || 1) + 1; c.save(d); }
function setEmail(id, email) { const d = c.load(), u = byId(d, id); if (!u) throw new Error('User not found'); if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) throw new Error('A valid email is required'); u.email = email.toLowerCase(); c.save(d); }
function remove(id) {
  const d = c.load(), u = byId(d, id); if (!u) throw new Error('User not found');
  for (const s of d.sites) if (s.ownerId === id) s.ownerId = 'system';
  for (const x of d.dbs) if (x.ownerId === id) x.ownerId = 'system';
  for (const x of d.dbusers) if (x.ownerId === id) x.ownerId = 'system';
  d.users = d.users.filter((x) => x.id !== id); c.save(d);
}
const sitesOf = (d, id) => d.sites.filter((s) => s.ownerId === id);
function actorOf(req) {
  if (req.session.role === 'customer') return tenancy.sessionActor({ id: req.session.uid, role: 'customer' });
  return { id: 'admin', tenantId: 'system', role: 'super_admin' };
}
module.exports = { add, authenticate, findByName, byId, touchLogin, setPassword, setActive, setEmail, remove, sitesOf, actorOf, dbs };
