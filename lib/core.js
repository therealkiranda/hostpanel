'use strict';
// HostPanel core: paths, helpers, database file, TOTP, background jobs, session store.
const fs = require('fs');
const net = require('net');
const crypto = require('crypto');
const { execFileSync, spawn, spawnSync } = require('child_process');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const tenancy = require('./tenancy');

const E = process.env;
const BASE = E.HP_BASE || '/opt/hostpanel';
const P = {
  BASE,
  DATA: BASE + '/data',
  BACKUPS: BASE + '/backups',
  DB_FILE: BASE + '/data/db.json',
  AUDIT: BASE + '/data/audit.log',
  AUTHLOG: E.HP_AUTHLOG || '/var/log/hostpanel-auth.log',
  CRED_FILE: E.HP_CRED || '/root/hostpanel-credentials.txt',
  HOMES: E.HP_HOMES || '/home',
  NGINX: E.HP_NGINX || '/etc/nginx',
  PHP: E.HP_PHP || '/etc/php',
  LE: E.HP_LE || '/etc/letsencrypt',
  WEBROOT: E.HP_WEBROOT || '/var/www/letsencrypt',
  SSHD_D: E.HP_SSHD_D || '/etc/ssh/sshd_config.d',
  SSHD_CONF: E.HP_SSHD_CONF || '/etc/ssh/sshd_config',
  KEYS: E.HP_KEYS || '/etc/ssh/hostpanel-keys',
  NGLOG: E.HP_NGLOG || '/var/log/nginx'
};
const VERSION = require('../package.json').version;
const PORT = parseInt(E.PANEL_PORT || '8443', 10);
const IS_ROOT = typeof process.getuid === 'function' && process.getuid() === 0;

/* ================= helpers ================= */
const rand = (n) => crypto.randomBytes(n).toString('hex');
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
const sh = (cmd, args, input) => execFileSync(cmd, args || [], { encoding: 'utf8', input: input, stdio: ['pipe', 'pipe', 'pipe'], timeout: 300000, maxBuffer: 32 * 1048576 });
// soft: stdout only, '' on any failure. ok: true when exit code is 0.
const soft = (cmd, args) => { const r = spawnSync(cmd, args || [], { encoding: 'utf8', timeout: 60000, maxBuffer: 16 * 1048576 }); return r.status === 0 ? (r.stdout || '') : ''; };
const both = (cmd, args) => { const r = spawnSync(cmd, args || [], { encoding: 'utf8', timeout: 60000, maxBuffer: 16 * 1048576 }); return (r.stdout || '') + (r.stderr || ''); };
const ALNUM = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
const genPassword = (n) => { let o = ''; for (let i = 0; i < (n || 20); i++) o += ALNUM[crypto.randomInt(ALNUM.length)]; return o; };
// Database / client passwords end up inside SQL, wp-config.php and .env: only characters that are safe in all of them.
const PW_RE = /^[A-Za-z0-9!@#%^*_+=.,:;~-]{12,64}$/;
const validPassword = (p) => PW_RE.test(String(p || ''));
const ok = (cmd, args) => spawnSync(cmd, args || [], { stdio: 'ignore', timeout: 60000 }).status === 0;
const errMsg = (e) => String((e && (e.stderr || e.message)) || e).trim().slice(0, 800);
const safeEq = (a, b) => { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const fmtSize = (n) => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : n < 1073741824 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1073741824).toFixed(2) + ' GB');
const fmtDate = (t) => new Date(t * 1000).toISOString().slice(0, 16).replace('T', ' ');
const stamp = () => new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);

/* ================= database file ================= */
const defaults = () => ({
  sftpPassword: true, phpPolicy: 'strict', panelDomain: '', panelSsl: false, directIps: [], ip: '',
  backup: { enabled: false, hour: 3, keep: 7, remote: '', last: '' }
});
const save = (d) => { fs.writeFileSync(P.DB_FILE + '.tmp', JSON.stringify(d, null, 2), { mode: 0o600 }); fs.renameSync(P.DB_FILE + '.tmp', P.DB_FILE); };
const load = () => {
  const d = JSON.parse(fs.readFileSync(P.DB_FILE, 'utf8'));
  const def = defaults();
  d.settings = Object.assign(def, d.settings || {});
  d.settings.backup = Object.assign(defaults().backup, (d.settings && d.settings.backup) || {});
  d.admin.totp = d.admin.totp || null;
  d.admin.sv = d.admin.sv || 1; // session version: bumping it signs out every existing session
  d.admin.knownIps = Array.isArray(d.admin.knownIps) ? d.admin.knownIps : [];
  d.email = d.email || '';
  tenancy.normalizeDatabase(d); // users, sites, dbs arrays; legacy sites/databases are owned by 'system'
  d.dbusers = Array.isArray(d.dbusers) ? d.dbusers : [];
  for (const x of d.dbs) { // 1.0.3 databases had one user with the same name as the database
    if (!Array.isArray(x.users) || !x.users.length) x.users = [x.user || x.name];
    x.site = x.site || '';
    for (const u of x.users) if (!d.dbusers.some((y) => y.user === u)) d.dbusers.push({ user: u, site: x.site, ownerId: x.ownerId, created: x.created || new Date().toISOString() });
  }
  for (const u of d.users) { u.sv = u.sv || 1; }
  return d;
};

let proxySecret = '';
function init() {
  fs.mkdirSync(P.DATA, { recursive: true, mode: 0o700 });
  fs.mkdirSync(P.BACKUPS, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(P.DB_FILE)) {
    const pass = rand(8);
    save({ secret: rand(32), proxySecret: rand(24), admin: { user: 'admin', hash: bcrypt.hashSync(pass, 12), mustChange: true, totp: null, totpLast: 0 }, email: '', settings: defaults(), sites: [], dbs: [] });
    fs.writeFileSync(P.CRED_FILE, 'Panel user: admin\nPanel password: ' + pass + '\n(You must change the password at first login)\n', { mode: 0o600 });
  }
  const d = load();
  if (!d.proxySecret) { d.proxySecret = rand(24); save(d); }
  proxySecret = d.proxySecret;
  return d;
}
const getProxySecret = () => proxySecret;
const bumpSessions = (d) => { d.admin.sv = (d.admin.sv || 1) + 1; return d.admin.sv; };

/* ================= client ip / logging ================= */
// X-Real-IP is only trusted from the local nginx proxy, which proves itself with a secret header
// (the nginx panel config is root-only, so site users cannot read the secret and spoof it).
const cleanIp = (req) => {
  const raw = String(req.socket.remoteAddress || '?').replace(/^::ffff:/, '');
  if ((raw === '127.0.0.1' || raw === '::1') && proxySecret && req.headers['x-hp-proxy'] && safeEq(req.headers['x-hp-proxy'], proxySecret)) {
    const x = String(req.headers['x-real-ip'] || '').trim();
    if (net.isIP(x)) return x;
  }
  return raw;
};
function audit(req, action, detail) {
  try {
    fs.appendFileSync(P.AUDIT, new Date().toISOString() + ' ' + cleanIp(req) + ' ' + ((req.session && req.session.user) || '-') + ' ' + action + ' ' +
      String(detail || '').replace(/[\r\n]/g, ' ').slice(0, 200) + '\n', { mode: 0o600 });
  } catch (e) {}
}
function auditSys(action, detail) {
  try { fs.appendFileSync(P.AUDIT, new Date().toISOString() + ' system - ' + action + ' ' + String(detail || '').replace(/[\r\n]/g, ' ').slice(0, 200) + '\n', { mode: 0o600 }); } catch (e) {}
}
function authFail(req, user) {
  try { fs.appendFileSync(P.AUTHLOG, new Date().toISOString() + ' LOGIN_FAIL ip=' + cleanIp(req) + ' user=' + String(user || '').replace(/[^\w.-]/g, '').slice(0, 32) + '\n'); } catch (e) {}
}

/* ================= TOTP (2FA) ================= */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf) { let bits = '', o = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) o += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return o; }
function b32dec(s) { let bits = ''; for (const ch of String(s).toUpperCase()) { const v = B32.indexOf(ch); if (v >= 0) bits += v.toString(2).padStart(5, '0'); } const o = []; for (let i = 0; i + 8 <= bits.length; i += 8) o.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(o); }
function hotp(secret, counter) {
  const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', b32dec(secret)).update(b).digest();
  const o = h[19] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}
// d (optional) is the db object: when given, a code can only be used once (replay protection).
function totpCheck(secret, code, d) {
  code = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(code)) return false;
  const cur = Math.floor(Date.now() / 30000);
  for (let i = -1; i <= 1; i++) {
    if (crypto.timingSafeEqual(Buffer.from(hotp(secret, cur + i)), Buffer.from(code))) {
      if (d) { if ((d.admin.totpLast || 0) >= cur + i) return false; d.admin.totpLast = cur + i; }
      return true;
    }
  }
  return false;
}

/* ================= background jobs (one at a time) ================= */
let job = null;
const getJob = () => job;
const setJobOwner = (id) => { if (job && !job.end) job.owner = id || 'system'; };
const jobRunning = () => !!(job && !job.end);
function runSteps(label, steps, done) {
  if (jobRunning()) throw new Error('Another task is running (see Tasks page). Try again when it has finished.');
  const j = (job = { label, start: Date.now(), end: 0, code: null, log: '' });
  const finish = (code) => {
    if (j.end) return;
    j.end = Date.now(); j.code = code;
    if (code === 0 && done) { try { done(j); } catch (e) { j.log += '\nFollow-up step failed: ' + errMsg(e) + '\n'; j.code = 1; } }
  };
  (function next(i) {
    if (i >= steps.length) return finish(0);
    const [cmd, args, env] = steps[i];
    j.log += '\n$ ' + cmd + ' ' + args.map((a) => (/\s/.test(a) && a.length > 40 ? '<script>' : a)).join(' ') + '\n';
    const p = spawn(cmd, args, { env: Object.assign({}, process.env, { DEBIAN_FRONTEND: 'noninteractive', NEEDRESTART_MODE: 'a' }, env || {}), stdio: ['ignore', 'pipe', 'pipe'] });
    const add = (x) => { j.log += x.toString(); if (j.log.length > 80000) j.log = j.log.slice(-50000); };
    p.stdout.on('data', add); p.stderr.on('data', add);
    p.on('error', (e) => { j.log += 'ERROR ' + e.message + '\n'; finish(1); });
    p.on('close', (code) => { if (j.end) return; if (code !== 0) { j.log += '\nExit code ' + code + '\n'; finish(code || 1); } else next(i + 1); });
  })(0);
}

// Same job slot as runSteps, but the work is a JS async function (used by the release updater).
function runAsync(label, fn) {
  if (jobRunning()) throw new Error('Another task is running (see Tasks page). Try again when it has finished.');
  const j = (job = { label, start: Date.now(), end: 0, code: null, log: '' });
  const log = (m) => { j.log += String(m) + '\n'; if (j.log.length > 80000) j.log = j.log.slice(-50000); };
  Promise.resolve().then(() => fn(log)).then(() => { j.end = Date.now(); j.code = 0; }, (e) => { log('ERROR: ' + errMsg(e)); j.end = Date.now(); j.code = 1; });
  return j;
}

/* ================= session store ================= */
// In-memory store with hard caps. Anonymous (login-page) sessions can never evict an admin session,
// and expired entries are pruned, so scanners cannot grow memory.
class PruneStore extends session.Store {
  constructor() {
    super();
    this.anon = new Map(); this.auth = new Map();
    this.maxAnon = 500; this.maxAuth = 300; this.anonTtl = 10 * 60 * 1000;
    setInterval(() => this.prune(), 60000).unref();
  }
  _exp(sess, anon) {
    const e = sess && sess.cookie && sess.cookie.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 1800000;
    return anon ? Math.min(e, Date.now() + this.anonTtl) : e;
  }
  get(sid, cb) {
    const e = this.auth.get(sid) || this.anon.get(sid);
    if (!e) return cb(null, null);
    if (e.exp < Date.now()) { this.auth.delete(sid); this.anon.delete(sid); return cb(null, null); }
    cb(null, JSON.parse(e.d));
  }
  set(sid, sess, cb) {
    const isAuth = !!sess.user, m = isAuth ? this.auth : this.anon;
    this.auth.delete(sid); this.anon.delete(sid);
    m.set(sid, { d: JSON.stringify(sess), exp: this._exp(sess, !isAuth) });
    const max = isAuth ? this.maxAuth : this.maxAnon;
    while (m.size > max) m.delete(m.keys().next().value);
    cb && cb(null);
  }
  touch(sid, sess, cb) {
    const e = this.auth.get(sid) || this.anon.get(sid);
    if (e) e.exp = this._exp(sess, !sess.user);
    cb && cb(null);
  }
  destroy(sid, cb) { this.auth.delete(sid); this.anon.delete(sid); cb && cb(null); }
  prune() {
    const t = Date.now();
    for (const m of [this.anon, this.auth]) for (const [k, v] of m) if (v.exp < t) m.delete(k);
  }
  clearAll() { this.anon.clear(); this.auth.clear(); }
}

const every = (ms, fn) => setInterval(() => { try { fn(); } catch (e) { auditSys('SCHEDULER_ERROR', errMsg(e)); } }, ms).unref();

module.exports = {
  P, PORT, IS_ROOT, VERSION, rand, genPassword, validPassword, PW_RE, setJobOwner, esc, sh, soft, both, ok, errMsg, safeEq, fmtSize, fmtDate, stamp,
  save, load, init, defaults, getProxySecret, cleanIp, audit, auditSys, authFail,
  b32enc, totpCheck, runSteps, runAsync, bumpSessions, getJob, jobRunning, PruneStore, every, bcrypt
};
