'use strict';
// Billing API (1.0.8): boots the real server.js unprivileged in a temp folder, with fake system tools on PATH
// (useradd, usermod, nginx, ...), and drives /api/v1 over HTTPS like a billing system would.
// Uses real express if installed (CI); otherwise the stand-ins in test/shims.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

/* ---------- 1. unit checks of the key logic with an in-memory database ---------- */
(function keyUnits() {
  const { createBilling, ApiError } = require('../lib/billing');
  let db = { apiKeys: [] };
  const c = { load: () => JSON.parse(JSON.stringify(db)), save: (d) => { db = JSON.parse(JSON.stringify(d)); }, rand: (n) => crypto.randomBytes(n).toString('hex') };
  const S = { cleanIpList: (t) => String(t || '').split(/[\s,]+/).filter(Boolean) };
  const b = createBilling({ c, S, U: {}, sys: {}, runtime: {}, tools: {}, host: {} });
  const k = b.createKey({ name: 'fossbilling', scopes: 'write', ips: '203.0.113.10 10.0.0.0/8' });
  assert.match(k.token, /^hpk_[a-f0-9]{8}_[a-f0-9]{48}$/);
  assert.deepEqual(k.scopes.sort(), ['read', 'write'], 'write implies read');
  assert.ok(!JSON.stringify(db).includes(k.token.split('_')[2]), 'the secret itself is never stored');
  assert.equal(b.verifyKey(k.token).name, 'fossbilling');
  assert.equal(b.verifyKey(k.token.slice(0, -1) + (k.token.endsWith('0') ? '1' : '0')), null, 'one wrong character is refused');
  assert.equal(b.verifyKey('nonsense'), null); assert.equal(b.verifyKey(''), null);
  const rec = db.apiKeys[0];
  assert.ok(b.ipAllowed(rec, '203.0.113.10') && b.ipAllowed(rec, '10.20.30.40') && !b.ipAllowed(rec, '203.0.113.11') && !b.ipAllowed(rec, 'garbage'));
  assert.ok(b.ipAllowed({ ips: [] }, '1.2.3.4'), 'no list = any address');
  assert.throws(() => b.createKey({ name: 'fossbilling' }), /already exists/);
  assert.throws(() => b.createKey({ name: '<script>' }), /Key name/);
  assert.throws(() => b.createKey({ name: 'x1', scopes: 'admin' }), /scope/);
  assert.throws(() => b.revokeKey('00000000'), (e) => e instanceof ApiError && e.status === 404);
  b.revokeKey(k.id); assert.equal(b.verifyKey(k.token), null, 'a revoked key stops working');
  for (let i = 0; i < 20; i++) b.createKey({ name: 'k' + i });
  assert.throws(() => b.createKey({ name: 'one-more' }), /At most 20/);
})();

/* ---------- 2. the real server with fake system tools ---------- */
const ROOT = path.join(__dirname, '..');
const T = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-api-')); fs.chmodSync(T, 0o777);
const dirs = {};
for (const n of ['base', 'base/data', 'homes', 'php', 'php/8.4', 'php/8.4/fpm', 'php/8.4/fpm/pool.d', 'nginx', 'bin']) { fs.mkdirSync(T + '/' + n, { recursive: true }); fs.chmodSync(T + '/' + n, 0o777); dirs[n] = T + '/' + n; }
const BASE = dirs.base, HOMES = dirs.homes, CALLS = T + '/calls.log';
fs.writeFileSync(CALLS, ''); fs.chmodSync(CALLS, 0o666);
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', BASE + '/data/panel.key', '-out', BASE + '/data/panel.crt', '-subj', '/CN=test'], { stdio: 'ignore' });
fs.chmodSync(BASE + '/data/panel.key', 0o644);
// every fake logs its arguments; chpasswd also drains stdin
for (const n of ['useradd', 'userdel', 'chpasswd', 'chown', 'usermod', 'pkill', 'nginx', 'systemctl', 'php-fpm8.4', 'mysql', 'crontab', 'certbot']) {
  fs.writeFileSync(dirs.bin + '/' + n, '#!/bin/sh\necho "' + n + ' $*" >> "' + CALLS + '"\ncat > /dev/null\nexit 0\n', { mode: 0o755 });
}
const PORT = 20000 + Math.floor(Math.random() * 20000);
const env = Object.assign({}, process.env, { PATH: dirs.bin + ':' + process.env.PATH, HP_NO_NETWORK: '1', HP_BASE: BASE, HP_CRED: T + '/cred.txt', HP_AUTHLOG: T + '/auth.log', HP_HOMES: HOMES, HP_PHP: dirs.php, HP_NGINX: dirs.nginx, HP_KEYS: T + '/keys', PANEL_PORT: String(PORT), PANEL_HOST: '127.0.0.1', NODE_PATH: path.join(__dirname, 'shims') });
const dropRoot = process.getuid && process.getuid() === 0;
const cmd = dropRoot ? 'setpriv' : process.execPath;
const args = (dropRoot ? ['--reuid=65534', '--regid=65534', '--clear-groups', process.execPath] : []).concat([path.join(ROOT, 'server.js')]);

function call(method, url, o) {
  o = o || {};
  return new Promise((resolve, reject) => {
    const body = o.json !== undefined ? JSON.stringify(o.json) : o.raw;
    const headers = Object.assign({}, o.headers || {});
    if (o.key) headers.Authorization = 'Bearer ' + o.key;
    if (o.json !== undefined) headers['Content-Type'] = 'application/json';
    if (body !== undefined) headers['Content-Length'] = Buffer.byteLength(body);
    const r = https.request({ host: '127.0.0.1', port: PORT, path: url, method, headers, rejectUnauthorized: false }, (res) => {
      const chunks = []; res.on('data', (x) => chunks.push(x));
      res.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let json = null; try { json = JSON.parse(text); } catch (e) {} resolve({ status: res.statusCode, headers: res.headers, text, json }); });
    });
    r.on('error', reject); r.end(body);
  });
}
const dbFile = BASE + '/data/db.json';
const readDb = () => JSON.parse(fs.readFileSync(dbFile, 'utf8'));
const writeDb = (d) => { fs.writeFileSync(dbFile + '.tmp', JSON.stringify(d)); fs.renameSync(dbFile + '.tmp', dbFile); };
const mkKey = (name, scopes, ips) => {
  const id = crypto.randomBytes(4).toString('hex'), secret = crypto.randomBytes(24).toString('hex'), d = readDb();
  d.apiKeys = (d.apiKeys || []).concat([{ id, name, hash: crypto.createHash('sha256').update(secret).digest('hex'), scopes, ips: ips || [], created: new Date().toISOString(), lastUsed: '', lastIp: '' }]);
  writeDb(d); return 'hpk_' + id + '_' + secret;
};
const calls = () => fs.readFileSync(CALLS, 'utf8');
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

let server; const outp = [];
async function start() {
  server = spawn(cmd, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
  server.stdout.on('data', (x) => outp.push(String(x))); server.stderr.on('data', (x) => outp.push(String(x)));
  for (let i = 0; i < 100; i++) { if (outp.join('').includes('on https://')) return; if (server.exitCode !== null) throw new Error('server exited: ' + outp.join('')); await pause(100); }
  throw new Error('server did not start: ' + outp.join(''));
}

(async () => {
  await start();
  const RW = mkKey('billing', ['read', 'write']), RO = mkKey('reporting', ['read']), LOCKED = mkKey('locked', ['read', 'write'], ['10.9.9.9']);

  /* ---------- authentication, scopes, routing ---------- */
  let r = await call('GET', '/api/v1/ping'); assert.equal(r.status, 401); assert.equal(r.json.error.code, 'unauthorized');
  r = await call('GET', '/api/v1/ping', { key: 'hpk_00000000_' + '0'.repeat(48) }); assert.equal(r.status, 401);
  r = await call('GET', '/api/v1/ping', { headers: { Authorization: 'Basic abc' } }); assert.equal(r.status, 401);
  r = await call('GET', '/api/v1/ping', { key: RW }); assert.equal(r.status, 200); assert.equal(r.json.version, '1.0.10'); assert.equal(r.json.key, 'billing');
  assert.ok(!r.headers['set-cookie'], 'API calls never create a session cookie');
  assert.match(r.headers['content-type'], /application\/json/);
  r = await call('GET', '/api/v1/openapi.json'); assert.equal(r.status, 200); assert.equal(r.json.openapi, '3.1.0'); assert.equal(r.json.info.version, '1.0.10'); assert.ok(r.json.paths['/api/v1/services']);
  r = await call('GET', '/api/v2/ping', { key: RW }); assert.equal(r.status, 404);
  r = await call('GET', '/api/v1/nope', { key: RW }); assert.equal(r.status, 404);
  r = await call('DELETE', '/api/v1/ping', { key: RW }); assert.equal(r.status, 405);
  r = await call('GET', '/api/v1/server', { key: RO }); assert.equal(r.status, 200); assert.deepEqual(r.json.phpVersions, ['8.4']); assert.ok(r.json.types.includes('php'));
  r = await call('POST', '/api/v1/services', { key: RO, json: { domain: 'a.example.com', username: 'alice', email: 'a@example.com' } }); assert.equal(r.status, 403); assert.equal(r.json.error.code, 'insufficient_scope');
  r = await call('GET', '/api/v1/server', { key: LOCKED }); assert.equal(r.status, 403); assert.equal(r.json.error.code, 'ip_not_allowed');
  r = await call('POST', '/api/v1/services', { key: RW, raw: '{"domain":', headers: { 'Content-Type': 'application/json' } }); assert.equal(r.status, 400); assert.equal(r.json.error.code, 'bad_json');
  r = await call('POST', '/api/v1/services', { key: RW, raw: 'domain=x', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }); assert.equal(r.status, 415);
  r = await call('POST', '/api/v1/services', { key: RW, raw: JSON.stringify({ pad: 'x'.repeat(40000) }), headers: { 'Content-Type': 'application/json' } }); assert.equal(r.status, 413);

  /* ---------- validation ---------- */
  const good = { domain: 'shop.example.com', username: 'alice', email: 'Alice@Example.com', externalId: 'svc-1001', plan: 'Starter', limits: { diskMb: 1, bandwidthMb: 5000 } };
  for (const [patch, code] of [[{ domain: 'not a domain' }, 'invalid_domain'], [{ type: 'ftp' }, 'invalid_type'], [{ username: 'a' }, 'invalid_username'], [{ email: 'nope' }, 'invalid_email'], [{ php: '5.6' }, 'invalid_php'], [{ password: 'short' }, 'invalid_password'], [{ externalId: 'bad id!' }, 'invalid_external_id'], [{ limits: { diskMb: -5 } }, 'invalid_limits'], [{ plan: '<b>' }, 'invalid_plan']]) {
    r = await call('POST', '/api/v1/services', { key: RW, json: Object.assign({}, good, patch) }); assert.equal(r.status, 422, JSON.stringify(patch)); assert.equal(r.json.error.code, code);
  }
  assert.equal(readDb().sites.length, 0, 'nothing was created by the failed requests'); assert.equal(readDb().users.length, 0);

  /* ---------- provisioning ---------- */
  r = await call('POST', '/api/v1/services', { key: RW, json: good });
  assert.equal(r.status, 201, r.text); assert.equal(r.json.created, true);
  const svc = r.json.service, cred = r.json.credentials;
  assert.equal(svc.domain, 'shop.example.com'); assert.equal(svc.status, 'active'); assert.equal(svc.externalId, 'svc-1001'); assert.equal(svc.plan, 'Starter'); assert.equal(svc.client.email, 'alice@example.com'); assert.equal(svc.php, '8.4');
  assert.match(cred.sftp.user, /^w[a-f0-9]{10}$/); assert.match(cred.sftp.password, /^[a-f0-9]{18}$/); assert.equal(cred.sftp.port, 22);
  assert.equal(cred.panel.username, 'alice'); assert.equal(cred.panel.password.length, 20); assert.equal(cred.panel.mustChangePassword, true);
  assert.ok(!JSON.stringify(svc).includes(cred.panel.password) && !JSON.stringify(svc).includes(cred.sftp.password), 'the service view carries no secrets');
  let db = readDb(), site = db.sites[0], user = db.users[0];
  assert.equal(site.ownerId, user.id); assert.equal(user.username, 'alice'); assert.equal(site.createdVia, 'api'); assert.ok(user.passwordHash && user.passwordHash !== cred.panel.password, 'only a hash is stored');
  assert.ok(fs.existsSync(HOMES + '/' + site.user + '/public_html/index.php'), 'website folder exists');
  assert.ok(fs.existsSync(dirs.nginx + '/sites-available/shop.example.com.conf')); assert.ok(fs.existsSync(dirs.php + '/8.4/fpm/pool.d/' + site.user + '.conf'));
  assert.match(calls(), new RegExp('useradd .*' + site.user)); assert.match(calls(), new RegExp('chpasswd'));

  // retrying the same request is safe and returns no credentials
  r = await call('POST', '/api/v1/services', { key: RW, json: good }); assert.equal(r.status, 200); assert.equal(r.json.created, false); assert.equal(r.json.credentials, null);
  assert.equal(readDb().sites.length, 1);
  r = await call('POST', '/api/v1/services', { key: RW, json: Object.assign({}, good, { externalId: 'other' }) }); assert.equal(r.status, 409); assert.equal(r.json.error.code, 'domain_exists');
  r = await call('POST', '/api/v1/services', { key: RW, json: Object.assign({}, good, { domain: 'b.example.com', externalId: 'x', email: 'someone@else.com' }) }); assert.equal(r.status, 409); assert.equal(r.json.error.code, 'client_conflict');
  r = await call('POST', '/api/v1/services', { key: RW, json: Object.assign({}, good, { domain: 'b.example.com', externalId: 'x', username: 'bob' }) }); assert.equal(r.status, 409, 'an email cannot be shared by two usernames'); assert.equal(r.json.error.code, 'client_conflict');
  r = await call('POST', '/api/v1/services', { key: RW, json: { domain: 'x.example.com', username: 'admin', email: 'x@example.com' } }); assert.equal(r.status, 409, 'the administrator name is reserved'); assert.equal(readDb().sites.length, 1);

  // the same client buys a second service (static): the login is reused, no new password
  r = await call('POST', '/api/v1/services', { key: RW, json: { domain: 'docs.example.com', username: 'alice', email: 'alice@example.com', type: 'static', externalId: 'svc-1002' } });
  assert.equal(r.status, 201, r.text); assert.equal(r.json.credentials.panel.password, null); assert.equal(readDb().users.length, 1); assert.equal(r.json.service.type, 'static'); assert.equal(r.json.service.php, null);

  r = await call('GET', '/api/v1/services/shop.example.com', { key: RO }); assert.equal(r.status, 200); assert.equal(r.json.domain, 'shop.example.com');
  r = await call('GET', '/api/v1/services/missing.example.com', { key: RO }); assert.equal(r.status, 404);
  r = await call('GET', '/api/v1/services?username=alice', { key: RO }); assert.equal(r.json.total, 2);
  r = await call('GET', '/api/v1/services?externalId=svc-1002', { key: RO }); assert.equal(r.json.total, 1); assert.equal(r.json.items[0].domain, 'docs.example.com');
  r = await call('GET', '/api/v1/clients/alice', { key: RO }); assert.equal(r.status, 200); assert.deepEqual(r.json.services.sort(), ['docs.example.com', 'shop.example.com']); assert.equal(r.json.active, true); assert.ok(!('passwordHash' in r.json));

  /* ---------- suspend / unsuspend ---------- */
  const conf = () => fs.readFileSync(dirs.nginx + '/sites-available/shop.example.com.conf', 'utf8');
  assert.ok(!conf().includes('return 503'));
  r = await call('POST', '/api/v1/services/shop.example.com/suspend', { key: RW, json: { reason: 'Unpaid invoice #42' } });
  assert.equal(r.status, 200); assert.equal(r.json.status, 'suspended'); assert.equal(r.json.suspendReason, 'Unpaid invoice #42');
  assert.match(conf(), /return 503/); assert.ok(conf().includes('acme-challenge'), 'certificate renewal keeps working');
  assert.match(calls(), new RegExp('usermod -e 1 ' + site.user)); assert.match(calls(), new RegExp('pkill -u ' + site.user));
  r = await call('GET', '/api/v1/services?status=suspended', { key: RO }); assert.equal(r.json.total, 1);
  const before = calls().length; r = await call('POST', '/api/v1/services/shop.example.com/suspend', { key: RW, json: {} }); assert.equal(r.status, 200); assert.equal(calls().length, before, 'suspending twice does nothing the second time');
  r = await call('POST', '/api/v1/services/shop.example.com/unsuspend', { key: RW, json: {} }); assert.equal(r.status, 200); assert.equal(r.json.status, 'active'); assert.equal(r.json.suspendReason, null);
  assert.ok(!conf().includes('return 503')); assert.match(calls(), new RegExp('usermod -e  ' + site.user));
  r = await call('POST', '/api/v1/services/nope.example.com/suspend', { key: RW, json: {} }); assert.equal(r.status, 404);

  /* ---------- password, sftp, plan, usage ---------- */
  r = await call('POST', '/api/v1/services/shop.example.com/password', { key: RW, json: { password: 'short' } }); assert.equal(r.status, 422);
  r = await call('POST', '/api/v1/services/shop.example.com/password', { key: RW, json: { password: 'A-brand-new-secret-1' } }); assert.equal(r.status, 200);
  const bc = require('bcryptjs'); db = readDb(); assert.ok(bc.compareSync('A-brand-new-secret-1', db.users[0].passwordHash)); assert.equal(db.users[0].mustChange, false); assert.ok(db.users[0].sv > 1, 'client is signed out');
  r = await call('POST', '/api/v1/services/shop.example.com/sftp-password', { key: RW, json: {} }); assert.equal(r.status, 200); assert.match(r.json.password, /^[a-f0-9]{18}$/); assert.notEqual(r.json.password, cred.sftp.password);
  r = await call('POST', '/api/v1/services/shop.example.com/plan', { key: RW, json: { plan: 'Business', limits: { diskMb: 2 } } }); assert.equal(r.status, 200); assert.equal(r.json.plan, 'Business'); assert.equal(r.json.limits.diskMb, 2); assert.equal(r.json.limits.bandwidthMb, 5000, 'untouched limits stay');
  fs.writeFileSync(HOMES + '/' + site.user + '/public_html/big.bin', Buffer.alloc(3 * 1048576));
  r = await call('GET', '/api/v1/services/shop.example.com/usage', { key: RO }); assert.equal(r.status, 200); assert.ok(r.json.disk.usedMb >= 3); assert.equal(r.json.disk.limitMb, 2); assert.equal(r.json.disk.overLimit, true); assert.equal(r.json.bandwidth.measured, false); assert.equal(r.json.databases, 0);
  r = await call('GET', '/api/v1/tasks/current', { key: RO }); assert.equal(r.status, 200); assert.equal(r.json.running, false);

  /* ---------- terminate ---------- */
  r = await call('DELETE', '/api/v1/clients/alice', { key: RW }); assert.equal(r.status, 409); assert.equal(r.json.error.code, 'client_in_use');
  r = await call('DELETE', '/api/v1/services/docs.example.com?skipBackup=1', { key: RW }); assert.equal(r.status, 200, r.text); assert.equal(r.json.status, 'deleted');
  assert.ok(!readDb().sites.some((s) => s.domain === 'docs.example.com')); assert.equal(readDb().users[0].active !== false, true, 'the client still has a website, so the login stays');
  r = await call('DELETE', '/api/v1/services/shop.example.com', { key: RW }); assert.equal(r.status, 202, r.text); assert.equal(r.json.status, 'deleting');
  for (let i = 0; i < 100; i++) { r = await call('GET', '/api/v1/tasks/current', { key: RO }); if (!r.json.running) break; await pause(100); }
  assert.equal(r.json.running, false); assert.equal(r.json.exitCode, 0, 'final backup + delete finished');
  assert.equal(readDb().sites.length, 0); assert.ok(fs.readdirSync(BASE + '/backups').some((f) => /^site-shop\.example\.com-\d{14}\.tar\.gz$/.test(f)), 'a final backup was kept');
  assert.equal(readDb().users[0].active, false, 'the last website is gone: the client login is closed');
  r = await call('DELETE', '/api/v1/clients/alice', { key: RW }); assert.equal(r.status, 200); assert.equal(readDb().users.length, 0);
  r = await call('GET', '/api/v1/clients/alice', { key: RO }); assert.equal(r.status, 404);

  /* ---------- audit log, key bookkeeping ---------- */
  const audit = fs.readFileSync(BASE + '/data/audit.log', 'utf8');
  assert.match(audit, /api:billing API POST \/services shop\.example\.com/); assert.match(audit, /API_IP_DENIED locked/);
  assert.ok(!audit.includes(RW.split('_')[2]) && !audit.includes(cred.panel.password) && !audit.includes(cred.sftp.password), 'no secret ever reaches the audit log');
  assert.ok(readDb().apiKeys.find((k) => k.name === 'billing').lastUsed, 'last-used time is recorded');

  /* ---------- the panel itself is unaffected ---------- */
  r = await call('GET', '/login'); assert.equal(r.status, 200); assert.match(r.headers['content-security-policy'], /default-src 'none'/);
  r = await call('POST', '/sites/new/php', { raw: 'x=1', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }); assert.equal(r.status, 401, 'cookie routes still need a login');

  /* ---------- brute force: 10 bad keys, then the address is locked out (valid keys too) ---------- */
  for (let i = 0; i < 12; i++) r = await call('GET', '/api/v1/ping', { key: 'hpk_deadbeef_' + '1'.repeat(48) });
  assert.equal(r.status, 429); assert.equal(r.headers['retry-after'], '900');
  r = await call('GET', '/api/v1/ping', { key: RW }); assert.equal(r.status, 429, 'the lock-out applies to the address');

  console.log('billing-api: all checks passed');
})().then(() => { server.kill(); process.exit(0); }, (e) => { console.error(e); console.error(outp.join('').slice(-2000)); try { server.kill(); } catch (x) {} process.exit(1); });
