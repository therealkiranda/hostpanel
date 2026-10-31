'use strict';
// Client logins: boots the real server.js (unprivileged, in a temp folder) and drives it over HTTPS like a browser would.
// Uses real express if installed (CI); otherwise the stand-ins in test/shims. System tools are not needed.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const T = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-e2e-')); fs.chmodSync(T, 0o777);
const BASE = T + '/base', HOMES = T + '/homes';
fs.mkdirSync(BASE + '/data', { recursive: true }); fs.mkdirSync(HOMES, { recursive: true });
for (const d of [BASE, BASE + '/data', HOMES]) fs.chmodSync(d, 0o777);
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', BASE + '/data/panel.key', '-out', BASE + '/data/panel.crt', '-subj', '/CN=test'], { stdio: 'ignore' });
fs.chmodSync(BASE + '/data/panel.key', 0o644);
const PORT = 20000 + Math.floor(Math.random() * 20000);
const CRED = T + '/cred.txt';
fs.mkdirSync(T + '/bin'); fs.writeFileSync(T + '/bin/mysql', '#!/bin/sh\ncat >> "' + T + '/mysql.log"\nexit 0\n', { mode: 0o755 });
const env = Object.assign({}, process.env, { PATH: T + '/bin:' + process.env.PATH, HP_NO_NETWORK: '1', HP_BASE: BASE, HP_CRED: CRED, HP_AUTHLOG: T + '/auth.log', HP_HOMES: HOMES, PANEL_PORT: String(PORT), PANEL_HOST: '127.0.0.1', NODE_PATH: path.join(__dirname, 'shims') });
const dropRoot = process.getuid && process.getuid() === 0;
const cmd = dropRoot ? 'setpriv' : process.execPath;
const args = (dropRoot ? ['--reuid=65534', '--regid=65534', '--clear-groups', process.execPath] : []).concat([path.join(ROOT, 'server.js')]);

/* ---- tiny browser ---- */
const jar = () => ({ cookie: '' });
function call(method, url, o) {
  o = o || {};
  return new Promise((resolve, reject) => {
    const body = o.form ? new URLSearchParams(o.form).toString() : o.body;
    const headers = Object.assign({}, o.headers || {});
    if (o.jar && o.jar.cookie) headers.Cookie = o.jar.cookie;
    if (o.form) { headers['Content-Type'] = 'application/x-www-form-urlencoded'; headers['Content-Length'] = Buffer.byteLength(body); }
    else if (body !== undefined) headers['Content-Length'] = Buffer.byteLength(body);
    const r = https.request({ host: '127.0.0.1', port: PORT, path: url, method, headers, rejectUnauthorized: false }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const sc = res.headers['set-cookie'];
        if (o.jar && sc) { for (const c of sc) { const [kv] = c.split(';'); if (/Max-Age=0/.test(c)) o.jar.cookie = ''; else o.jar.cookie = kv; } }
        resolve({ status: res.statusCode, headers: res.headers, buf: Buffer.concat(chunks), text: Buffer.concat(chunks).toString('utf8'), setCookie: sc });
      });
    });
    r.on('error', reject); r.end(body);
  });
}
const csrfOf = (html) => { const m = /name="_csrf" value="([a-f0-9]+)"|data-csrf="([a-f0-9]+)"/.exec(html); return m && (m[1] || m[2]); };
async function login(j, user, pass, headers) {
  const page = await call('GET', '/login', { jar: j, headers });
  const r = await call('POST', '/login', { jar: j, headers, form: { _csrf: csrfOf(page.text), user, pass, code: '' } });
  return r;
}
const post = async (j, url, form) => { const t = await getCsrf(j); return call('POST', url, { jar: j, form: Object.assign({ _csrf: t }, form) }); };
const getCsrf = async (j) => csrfOf((await call('GET', '/account', { jar: j })).text) || csrfOf((await call('GET', '/', { jar: j })).text);
const flashOf = async (j, url) => { let r = await call('GET', url, { jar: j }); if (r.status === 302 && /^\/(files|sites|cron|login)/.test(r.headers.location) && r.headers.location !== url) { const again = await call('GET', r.headers.location, { jar: j }); if (/class="flash/.test(again.text)) r = again; } const m = /<div class="flash (?:ok|err)[^"]*"[^>]*>([\s\S]*?)(?:<button|<\/div>)/.exec(r.text); return { status: r.status, flash: m ? m[1].replace(/&#39;/g, "'").replace(/&quot;/g, '"') : '', text: r.text }; };

let server; const outp = [];
async function start() {
  server = spawn(cmd, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
  server.stdout.on('data', (d) => outp.push(String(d))); server.stderr.on('data', (d) => outp.push(String(d)));
  for (let i = 0; i < 100; i++) { if (outp.join('').includes('on https://')) return; if (server.exitCode !== null) throw new Error('server exited: ' + outp.join('')); await new Promise((r) => setTimeout(r, 100)); }
  throw new Error('server did not start: ' + outp.join(''));
}
const pause = (ms) => new Promise((r) => setTimeout(r, ms));


(async () => {
  await start();
  const A = jar(), C = jar();
  const pass0 = /Panel password: (\S+)/.exec(fs.readFileSync(CRED, 'utf8'))[1];
  await login(A, 'admin', pass0); const pass1 = 'a-much-longer-password-1'; await post(A, '/account', { cur: pass0, nw: pass1 });

  // two websites (as if created by the wizard) and one legacy 1.0.3-style database without users/owner
  const mk = (dom, user) => { const home = HOMES + '/' + user; for (const d of ['', '/public_html', '/tmp', '/logs']) fs.mkdirSync(home + d, { recursive: true, mode: 0o755 }); return { domain: dom, type: 'static', user, home, root: home + '/public_html', docroot: home + '/public_html', created: new Date().toISOString(), ssl: false, certNames: [], cfg: {}, autoSsl: false }; };
  const s1 = mk('example.com', 'wuser00001'), s2 = mk('other.com', 'wuser00002');
  if (dropRoot) execFileSync('chown', ['-R', '65534:65534', HOMES]);
  let db = JSON.parse(fs.readFileSync(BASE + '/data/db.json', 'utf8'));
  db.sites.push(s1, s2); db.dbs = [{ name: 'legacy_db', created: new Date().toISOString(), site: 'other.com' }];
  fs.writeFileSync(BASE + '/data/db.json', JSON.stringify(db));
  fs.mkdirSync(BASE + '/backups', { recursive: true });
  for (const f of ['site-example.com-20260101000000.tar.gz', 'site-other.com-20260101000000.tar.gz', 'db-legacy_db-20260101000000.sql.gz']) fs.writeFileSync(BASE + '/backups/' + f, 'x');

  /* ---------- administrator creates the client ---------- */
  let r = await post(A, '/users/add', { username: 'kiran', email: 'kiran@example.com', password: 'short', sites: 'example.com' });
  assert.match((await flashOf(A, '/users')).flash, /12/, 'weak client password refused');
  r = await post(A, '/users/add', { username: 'admin', email: 'k@example.com', password: 'Client-Pass-12345', sites: 'example.com' });
  assert.match((await flashOf(A, '/users')).flash, /reserved/, 'cannot reuse the administrator name');
  r = await post(A, '/users/add', { username: 'kiran', email: 'kiran@example.com', password: 'Client-Pass-12345', sites: 'example.com' });
  assert.match((await flashOf(A, '/users')).flash, /Client created/);
  db = JSON.parse(fs.readFileSync(BASE + '/data/db.json', 'utf8'));
  const kiran = db.users[0]; assert.equal(db.users.length, 1); assert.ok(kiran.passwordHash && !JSON.stringify(db).includes('Client-Pass-12345'), 'password is stored hashed');
  assert.equal(db.sites.find((s) => s.domain === 'example.com').ownerId, kiran.id); assert.ok(!db.sites.find((s) => s.domain === 'other.com').ownerId || db.sites.find((s) => s.domain === 'other.com').ownerId === 'system');
  for (const p of ['/users', '/users/manage?id=' + kiran.id, '/sites', '/sites/manage?domain=example.com']) assert.equal((await call('GET', p, { jar: A })).status, 200, p);
  assert.ok((await call('GET', '/sites', { jar: A })).text.includes('kiran'), 'administrator sees the client column');

  /* ---------- client login: first login forces a new password ---------- */
  r = await login(C, 'kiran', 'wrong-password-123'); assert.equal(r.headers.location, '/login');
  r = await login(C, 'kiran', 'Client-Pass-12345'); assert.equal(r.headers.location, '/');
  r = await call('GET', '/', { jar: C }); assert.equal(r.headers.location, '/account', 'forced password change');
  r = await call('GET', '/sites', { jar: C }); assert.equal(r.headers.location, '/account');
  const cpost = async (url, form) => { const t = csrfOf((await call('GET', '/account', { jar: C })).text); return call('POST', url, { jar: C, form: Object.assign({ _csrf: t }, form) }); };
  await cpost('/account', { current: 'Client-Pass-12345', password: 'Client-Pass-12345', again: 'Client-Pass-12345' });
  assert.match((await flashOf(C, '/account')).flash, /not used/);
  await cpost('/account', { current: 'Client-Pass-12345', password: 'My-New-Client-Pass-9', again: 'My-New-Client-Pass-9' });
  assert.equal((await call('GET', '/', { jar: C })).status, 200, 'signed in after changing the password');

  /* ---------- the client sees only their website ---------- */
  r = await call('GET', '/', { jar: C }); assert.ok(r.text.includes('example.com') && !r.text.includes('other.com') && !r.text.includes('Settings') && !r.text.includes('Services'), 'client dashboard + menu');
  r = await call('GET', '/sites', { jar: C }); assert.ok(r.text.includes('example.com') && !r.text.includes('other.com') && !r.text.includes('New website'));
  assert.equal((await call('GET', '/sites/manage?domain=example.com', { jar: C })).status, 200);
  r = await call('GET', '/sites/manage?domain=example.com', { jar: C }); assert.ok(!r.text.includes('Delete website') && !r.text.includes('Client access'), 'no delete / assignment for clients');
  for (const p of ['/sites/manage?domain=other.com', '/files?site=other.com&p=/public_html', '/cron?site=other.com', '/logs?site=other.com&type=error', '/files/edit?site=other.com&p=/public_html/a.txt']) assert.equal((await call('GET', p, { jar: C })).status, 404, 'foreign website: ' + p);
  for (const p of ['/files?site=example.com&p=/public_html', '/cron?site=example.com', '/logs?site=example.com', '/databases', '/backups', '/tasks', '/account']) assert.equal((await call('GET', p, { jar: C })).status, 200, p);
  for (const p of ['/settings', '/services', '/security', '/updates', '/audit', '/users', '/users/manage?id=' + kiran.id, '/sites/new', '/sites/new/node', '/sites/new/python']) assert.equal((await call('GET', p, { jar: C })).status, 403, 'admin-only: ' + p);
  const dbBefore = fs.readFileSync(BASE + '/data/db.json', 'utf8');
  for (const [url, form] of [['/sites/delete', { domain: 'example.com', confirm: 'example.com' }], ['/users/add', { username: 'evil1', email: 'e@e.co', password: 'Evil-Password-123' }], ['/services/action', { name: 'nginx', action: 'stop' }], ['/settings/email', { email: 'x@y.co' }], ['/backups/all', {}], ['/backups/schedule', {}], ['/tools/install', { id: 'python' }], ['/sites/owner', { domain: 'example.com', ownerId: 'system' }], ['/sites/new/node', { domain: 'n.example.com' }], ['/account/username', { username: 'x' }], ['/databases/assign', { name: 'shop_db', site: '' }]]) {
    r = await cpost(url, form); assert.equal(r.status, 403, 'POST ' + url);
  }
  for (const [url, form] of [['/sites/php', { domain: 'other.com', php: '8.3' }], ['/sites/ssl', { domain: 'other.com', email: 'a@b.co' }], ['/backups/site', { domain: 'other.com' }], ['/sites/sftp-reset', { domain: 'other.com' }], ['/cron/save', { domain: 'other.com', content: '* * * * * x' }], ['/files/mkdir', { site: 'other.com', p: '/public_html', name: 'x' }], ['/databases/add', { site: 'other.com', name: 'steal_db', user: 'steal_user', password: 'Str0ngPassw0rd!x' }]]) {
    r = await cpost(url, form); assert.equal(r.status, 404, 'foreign POST ' + url);
  }
  assert.equal(fs.readFileSync(BASE + '/data/db.json', 'utf8'), dbBefore, 'refused requests change nothing');
  assert.ok(!fs.existsSync(HOMES + '/wuser00002/public_html/x'), 'nothing was written to the other website');

  // a client can install an application only onto a website of their own
  r = await cpost('/sites/new/wordpress', { target: 'other.com', title: 'T', adminUsername: 'owner1', adminEmail: 'a@b.co', adminPassword: 'x'.repeat(20), locale: 'en_US', dbName: 'wp_x1', dbUser: 'wpu_x1', dbPassword: 'Str0ngPassw0rd!x' });
  assert.match((await flashOf(C, r.headers.location)).flash, /not found/i, 'foreign target refused');
  r = await cpost('/sites/new/wordpress', { target: '__new__', domain: 'mine.example.org', title: 'T', adminUsername: 'owner1', adminEmail: 'a@b.co', adminPassword: 'x'.repeat(20), locale: 'en_US' });
  assert.equal(r.status, 404, 'a client naming a domain that is not theirs is refused before anything runs');
  assert.ok(!JSON.parse(fs.readFileSync(BASE + '/data/db.json', 'utf8')).sites.some((x) => x.domain === 'mine.example.org'));

  /* ---------- databases: name, user and password are separate; scoped to the client's website ---------- */
  r = await call('GET', '/databases', { jar: C }); assert.ok(r.text.includes('name="name"') && r.text.includes('name="user"') && r.text.includes('name="password"') && !r.text.includes('legacy_db'), 'separate fields; foreign database hidden');
  r = await cpost('/databases/add', { site: 'example.com', name: 'shop_db', user: 'shop_user', password: 'weak' });
  assert.match((await flashOf(C, '/databases')).flash, /Database password/);
  r = await cpost('/databases/add', { site: 'example.com', name: 'shop_db', user: 'shop_user', password: 'Str0ngPassw0rd!x' });
  assert.match((await flashOf(C, '/databases')).flash, /DB name: shop_db\nDB user: shop_user/);
  db = JSON.parse(fs.readFileSync(BASE + '/data/db.json', 'utf8'));
  const shop = db.dbs.find((x) => x.name === 'shop_db'); assert.deepEqual(shop.users, ['shop_user']); assert.equal(shop.site, 'example.com'); assert.equal(shop.ownerId, kiran.id);
  const sqlLog = fs.readFileSync(T + '/mysql.log', 'utf8');
  assert.ok(sqlLog.includes("CREATE USER 'shop_user'@'localhost' IDENTIFIED BY 'Str0ngPassw0rd!x'") && sqlLog.includes('GRANT ALL PRIVILEGES ON `shop\\_db`.* TO \'shop_user\'@\'localhost\''), 'user created separately, "_" escaped in GRANT:\n' + sqlLog);
  assert.ok(sqlLog.includes("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'pma_wuser00001'@'localhost'") && sqlLog.includes('GRANT ALL PRIVILEGES ON `shop\\_db`.* TO \'pma_wuser00001\'@\'localhost\''), 'per-website phpMyAdmin account is synchronised');
  assert.ok(!sqlLog.includes('legacy'), 'the other website\'s database is untouched');
  assert.equal((await call('GET', '/databases/manage?name=shop_db', { jar: C })).status, 200);
  r = await call('GET', '/databases/manage?name=legacy_db', { jar: C }); assert.equal(r.headers.location, '/databases', 'foreign database is not found');
  for (const [url, form] of [['/databases/user/add', { name: 'legacy_db', user: 'x_user_1', password: 'Str0ngPassw0rd!x' }], ['/databases/delete', { name: 'legacy_db', confirm: 'legacy_db' }], ['/databases/backup', { name: 'legacy_db' }], ['/databases/user/password', { name: 'legacy_db', user: 'legacy_db' }]]) {
    await cpost(url, form); assert.match((await flashOf(C, '/databases')).flash, /not found/i, url);
  }
  await cpost('/databases/user/add', { name: 'shop_db', user: 'report_user', password: 'An0ther-Str0ng-Pw' });
  assert.deepEqual(JSON.parse(fs.readFileSync(BASE + '/data/db.json', 'utf8')).dbs.find((x) => x.name === 'shop_db').users, ['shop_user', 'report_user']);
  await cpost('/databases/user/remove', { name: 'shop_db', user: 'report_user' });
  assert.deepEqual(JSON.parse(fs.readFileSync(BASE + '/data/db.json', 'utf8')).dbs.find((x) => x.name === 'shop_db').users, ['shop_user']);
  r = await cpost('/databases/pma', { domain: 'example.com' }); assert.match((await flashOf(C, '/databases')).flash, /not enabled/, 'phpMyAdmin not installed yet');
  r = await cpost('/databases/pma', { domain: '*' }); assert.equal(r.status, 404, 'clients cannot ask for the all-databases phpMyAdmin');
  // administrator: legacy 1.0.3 database was migrated to a user with the same name
  r = await call('GET', '/databases/manage?name=legacy_db', { jar: A }); assert.equal(r.status, 200); assert.ok(r.text.includes('legacy_db'));
  assert.ok((await call('GET', '/databases', { jar: A })).text.includes('Install and enable phpMyAdmin'));

  /* ---------- backups are filtered ---------- */
  r = await call('GET', '/backups', { jar: C }); assert.ok(r.text.includes('site-example.com-') && !r.text.includes('site-other.com-') && !r.text.includes('db-legacy_db-'));
  assert.equal((await call('GET', '/backups/download?f=site-example.com-20260101000000.tar.gz', { jar: C })).status, 200);
  assert.equal((await call('GET', '/backups/download?f=site-other.com-20260101000000.tar.gz', { jar: C })).status, 404);
  r = await cpost('/backups/delete', { f: 'site-other.com-20260101000000.tar.gz' }); assert.ok(fs.existsSync(BASE + '/backups/site-other.com-20260101000000.tar.gz'), 'foreign backup not deleted');
  await cpost('/backups/restore', { f: 'db-legacy_db-20260101000000.sql.gz', confirm: 'legacy_db' }); assert.match((await flashOf(C, '/backups')).flash, /Backup not found/);

  /* ---------- administrator moves / disables / deletes ---------- */
  await post(A, '/sites/owner', { domain: 'other.com', ownerId: kiran.id });
  assert.ok((await call('GET', '/sites', { jar: C })).text.includes('other.com'), 'assigned website shows up at once');
  await post(A, '/users/sites', { id: kiran.id, sites: 'example.com' });
  assert.ok(!(await call('GET', '/sites', { jar: C })).text.includes('other.com'), 'removed website disappears');
  await post(A, '/users/toggle', { id: kiran.id, on: '0' });
  r = await call('GET', '/sites', { jar: C }); assert.equal(r.headers.location, '/login', 'disabled login is signed out at once');
  r = await login(jar(), 'kiran', 'My-New-Client-Pass-9'); assert.equal(r.headers.location, '/login');
  await post(A, '/users/toggle', { id: kiran.id, on: '1' });
  r = await login(C, 'kiran', 'My-New-Client-Pass-9'); assert.equal(r.headers.location, '/');
  await post(A, '/users/password', { id: kiran.id, password: 'Reset-By-Admin-123' });
  assert.equal((await call('GET', '/sites', { jar: C })).headers.location, '/login', 'password reset signs the client out');
  await post(A, '/users/delete', { id: kiran.id, confirm: 'kiran' });
  db = JSON.parse(fs.readFileSync(BASE + '/data/db.json', 'utf8')); assert.equal(db.users.length, 0); assert.ok(db.sites.every((s) => !s.ownerId || s.ownerId === 'system') && db.dbs.every((x) => x.ownerId === 'system'), 'deleted client: websites and databases fall back to the administrator');

  assert.ok(!outp.join('').match(/Error|TypeError|ReferenceError|UnhandledPromise/), 'server printed errors:\n' + outp.join(''));
  console.log('client login / isolation end-to-end tests passed');
})().then(() => cleanup(0), (e) => { console.error(e); console.error('--- server output ---\n' + outp.join('').slice(-1500)); cleanup(1); });
function cleanup(code) { try { server.kill('SIGKILL'); } catch (e) {} try { fs.rmSync(T, { recursive: true, force: true }); } catch (e) {} process.exitCode = code; }
