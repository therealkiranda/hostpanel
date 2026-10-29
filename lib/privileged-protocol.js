'use strict';
// Closed RPC schema for a future root-owned helper. Unknown operations/fields are rejected.
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const USER = /^[A-Za-z][A-Za-z0-9_.-]{2,31}$/;
const DBNAME = /^[a-z][a-z0-9_]{2,31}$/;
const SERVICES = new Set(['nginx', 'mysql', 'mariadb', 'cron', 'fail2ban', 'php8.2-fpm', 'php8.3-fpm', 'php8.4-fpm', 'php8.5-fpm']);
const schemas = {
  'nginx.test': { required: [], optional: [] },
  'nginx.reload': { required: [], optional: [] },
  'service.reload': { required: ['service'], optional: [] },
  'site.create': { required: ['domain', 'type', 'phpVersion', 'ownerId'], optional: [] },
  'site.delete': { required: ['domain', 'ownerId'], optional: [] },
  'database.create': { required: ['domain', 'ownerId'], optional: [] },
  'wordpress.install': { required: ['domain', 'ownerId', 'title', 'adminUsername', 'adminEmail', 'adminPassword'], optional: ['locale'] }
};
function validateRequest(req) {
  if (!req || typeof req !== 'object' || Array.isArray(req)) throw new Error('Request must be an object');
  const keys = Object.keys(req);
  if (keys.some((k) => !['id', 'version', 'operation', 'args'].includes(k))) throw new Error('Unknown request field');
  if (req.version !== 1 || typeof req.id !== 'string' || !/^[a-f0-9]{16,64}$/.test(req.id)) throw new Error('Invalid protocol version or request ID');
  const schema = schemas[req.operation];
  if (!schema) throw new Error('Operation is not allowed');
  if (!req.args || typeof req.args !== 'object' || Array.isArray(req.args)) throw new Error('args must be an object');
  const allowed = new Set(schema.required.concat(schema.optional));
  const argKeys = Object.keys(req.args);
  if (schema.required.some((k) => !Object.prototype.hasOwnProperty.call(req.args, k))) throw new Error('Missing required operation argument');
  if (argKeys.some((k) => !allowed.has(k))) throw new Error('Unknown operation argument');
  const a = req.args;
  if (a.domain !== undefined && (typeof a.domain !== 'string' || !DOMAIN.test(a.domain))) throw new Error('Invalid domain');
  if (a.ownerId !== undefined && (typeof a.ownerId !== 'string' || !/^[a-f0-9]{32}$/.test(a.ownerId))) throw new Error('Invalid owner ID');
  if (a.type !== undefined && !['php', 'laravel', 'static', 'wordpress'].includes(a.type)) throw new Error('Invalid site type');
  if (a.phpVersion !== undefined && !/^\d+\.\d+$/.test(String(a.phpVersion))) throw new Error('Invalid PHP version');
  if (a.service !== undefined && !SERVICES.has(a.service)) throw new Error('Service is not allowlisted');
  if (a.title !== undefined && (typeof a.title !== 'string' || !a.title.trim() || a.title.length > 120 || /[\0\r\n]/.test(a.title))) throw new Error('Invalid site title');
  if (a.adminUsername !== undefined && !USER.test(a.adminUsername)) throw new Error('Invalid WordPress username');
  if (a.adminEmail !== undefined && (typeof a.adminEmail !== 'string' || a.adminEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(a.adminEmail))) throw new Error('Invalid administrator email');
  if (a.adminPassword !== undefined && (typeof a.adminPassword !== 'string' || a.adminPassword.length < 16 || a.adminPassword.length > 200 || /[\0\r\n]/.test(a.adminPassword))) throw new Error('Invalid administrator password');
  if (a.locale !== undefined && !/^[a-z]{2,3}(?:_[A-Z]{2})?$/.test(a.locale)) throw new Error('Invalid locale');
  return req;
}
function safeResponse(id, ok, result) {
  return { version: 1, id, ok: !!ok, ...(ok ? { result: result === undefined ? null : result } : { error: String(result || 'Operation failed').slice(0, 240) }) };
}
module.exports = { validateRequest, safeResponse, operations: Object.keys(schemas) };
