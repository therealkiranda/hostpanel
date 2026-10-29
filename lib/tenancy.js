'use strict';
// Pure tenant ownership and migration helpers. Call authorization helpers in every resource route.
const crypto = require('crypto');
const USER_RE = /^[A-Za-z][A-Za-z0-9_.-]{2,31}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ROLES = new Set(['super_admin', 'manager', 'customer']);
const id = () => crypto.randomBytes(16).toString('hex');

function normalizeDatabase(db) {
  if (!db || typeof db !== 'object' || Array.isArray(db)) throw new Error('Invalid HostPanel database');
  db.users = Array.isArray(db.users) ? db.users : [];
  db.sites = Array.isArray(db.sites) ? db.sites : [];
  db.dbs = Array.isArray(db.dbs) ? db.dbs : [];
  // Legacy sites are explicitly system-owned; never guess a customer based on domain/name.
  for (const s of db.sites) if (!s.ownerId) s.ownerId = 'system';
  for (const d of db.dbs) if (!d.ownerId) d.ownerId = 'system';
  db.tenancySchemaVersion = Math.max(1, Number(db.tenancySchemaVersion) || 0);
  return db;
}

function createUser(db, input, hashPassword) {
  normalizeDatabase(db);
  const username = String(input.username || '').trim();
  const email = String(input.email || '').trim().toLowerCase();
  const password = String(input.password || '');
  const role = String(input.role || 'customer');
  if (!USER_RE.test(username)) throw new Error('Username must be 3-32 safe characters');
  if (!EMAIL_RE.test(email) || email.length > 254) throw new Error('A valid email is required');
  if (password.length < 12 || password.length > 200) throw new Error('Password must be 12-200 characters');
  if (!ROLES.has(role) || role === 'super_admin') throw new Error('This operation cannot create a super administrator');
  if (typeof hashPassword !== 'function') throw new Error('A password hashing adapter is required');
  if (db.users.some((u) => u.username.toLowerCase() === username.toLowerCase() || u.email === email)) throw new Error('Username or email already exists');
  const user = { id: id(), username, email, passwordHash: hashPassword(password), role, active: true, createdAt: new Date().toISOString() };
  db.users.push(user);
  return { ...user, passwordHash: undefined };
}

function publicUser(user) {
  if (!user) return null;
  const { passwordHash, totpSecret, resetToken, ...safe } = user;
  return safe;
}
function userById(db, userId) { normalizeDatabase(db); return db.users.find((u) => u.id === userId && u.active !== false) || null; }
function canManageAll(actor) { return !!actor && ['super_admin', 'manager'].includes(actor.role); }
function owns(actor, resource) {
  if (!actor || !resource) return false;
  if (actor.role === 'super_admin') return true;
  if (actor.role === 'manager') return resource.ownerId === actor.tenantId || resource.ownerId === 'system';
  return !!actor.tenantId && resource.ownerId === actor.tenantId;
}
function assertOwns(actor, resource, label = 'Resource') {
  if (!owns(actor, resource)) { const e = new Error(label + ' not found'); e.status = 404; throw e; }
  return resource;
}
function assignOwner(resource, actor) {
  if (!actor || !actor.tenantId || !['customer', 'manager'].includes(actor.role)) throw new Error('A tenant-scoped actor is required');
  return Object.assign({}, resource, { ownerId: actor.tenantId });
}
function sessionActor(user) {
  if (!user || !user.id || !ROLES.has(user.role)) return null;
  return { id: user.id, tenantId: user.tenantId || user.id, role: user.role };
}
module.exports = { USER_RE, ROLES, normalizeDatabase, createUser, publicUser, userById, canManageAll, owns, assertOwns, assignOwner, sessionActor };
