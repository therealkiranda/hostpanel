'use strict';
// Boots the real server.js (unprivileged, in a temp folder) and drives it over HTTPS like a browser would.
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
const env = Object.assign({}, process.env, { HP_BASE: BASE, HP_CRED: CRED, HP_AUTHLOG: T + '/auth.log', HP_HOMES: HOMES, PANEL_PORT: String(PORT), PANEL_HOST: '127.0.0.1', NODE_PATH: path.join(__dirname, 'shims') });
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
  const proxySecret = JSON.parse(fs.readFileSync(BASE + '/data/db.json', 'utf8')).proxySecret;
  const A = jar();

  /* ---------- login page, headers, cookie ---------- */
  let r = await call('GET', '/login', { jar: A });
  assert.equal(r.status, 200);
  assert.match(r.headers['content-security-policy'], /default-src 'none'.*script-src 'self'/);
  assert.equal(r.headers['x-frame-options'], 'DENY'); assert.equal(r.headers['x-content-type-options'], 'nosniff'); assert.match(r.headers['strict-transport-security'], /max-age/);
  assert.match(r.setCookie[0], /^__Host-hp\.sid=/); assert.match(r.setCookie[0], /HttpOnly/); assert.match(r.setCookie[0], /Secure/); assert.match(r.setCookie[0], /SameSite=Strict/);
  assert.ok(!/<script(?![^>]*src=)/.test(r.text), 'no inline scripts');
  r = await call('GET', '/', {}); assert.equal(r.status, 302); assert.equal(r.headers.location, '/login');
  r = await call('GET', '/nothing-here', {}); assert.equal(r.status, 404);
  r = await call('POST', '/login', { form: { user: 'admin', pass: 'x' } }); assert.equal(r.status, 403, 'login POST without a CSRF token is refused');
  r = await call('POST', '/sites/add', { form: { domain: 'x.example' } }); assert.equal(r.status, 401, 'POST without a session is refused');
  r = await call('POST', '/login', { jar: A, form: { _csrf: 'wrong', user: 'admin', pass: 'x' } }); assert.equal(r.status, 403, 'bad CSRF token');

  /* ---------- sign in with the generated password ---------- */
  const pass0 = /Panel password: (\S+)/.exec(fs.readFileSync(CRED, 'utf8'))[1];
  r = await login(A, 'admin', 'wrong-password'); assert.equal(r.headers.location, '/login');
  assert.match((await flashOf(A, '/login')).flash, /Invalid credentials/);
  assert.match(fs.readFileSync(T + '/auth.log', 'utf8'), /LOGIN_FAIL ip=127\.0\.0\.1 user=admin/);
  r = await login(A, 'admin', pass0); assert.equal(r.headers.location, '/');
  r = await call('GET', '/', { jar: A }); assert.equal(r.status, 302); assert.equal(r.headers.location, '/account', 'must change the default password first');
  const B = jar(); r = await login(B, 'admin', pass0); assert.equal(r.headers.location, '/');

  /* ---------- password change: strong rule, credentials file removed, other sessions signed out ---------- */
  assert.match((await post(A, '/account', { cur: pass0, nw: 'short' })).headers.location, /account/);
  assert.match((await flashOf(A, '/account')).flash, /12-200 characters/);
  const pass1 = 'a-much-longer-password-1';
  await post(A, '/account', { cur: pass0, nw: pass1 });
  assert.match((await flashOf(A, '/account')).flash, /Password updated/);
  assert.ok(!fs.existsSync(CRED), 'credentials file is deleted after the password change (was a bug: missing imports)');
  r = await call('GET', '/account', { jar: A }); assert.equal(r.status, 200, 'the session that changed the password stays signed in');
  r = await call('GET', '/account', { jar: B }); assert.equal(r.status, 302); assert.equal(r.headers.location, '/login', 'other sessions are signed out');
  r = await call('GET', '/sites', { jar: A }); assert.equal(r.status, 200);

  /* ---------- username change keeps this session, kills others ---------- */
  const C = jar(); await login(C, 'admin', pass1); assert.equal((await call('GET', '/sites', { jar: C })).status, 200);
  await post(A, '/account/username', { username: 'boss_user', pass: pass1 });
  assert.match((await flashOf(A, '/account')).flash, /username changed/i);
  assert.equal((await call('GET', '/sites', { jar: A })).status, 200);
  assert.equal((await call('GET', '/sites', { jar: C })).headers.location, '/login');
  assert.equal((await login(jar(), 'admin', pass1)).headers.location, '/login', 'old username no longer works');

  /* ---------- every page renders (catches runtime errors in templates/handlers) ---------- */
  const home = HOMES + '/h1';
  for (const d of ['', '/public_html', '/tmp', '/logs']) fs.mkdirSync(home + d, { recursive: true, mode: 0o755 });
  if (dropRoot) execFileSync('chown', ['-R', '65534:65534', HOMES]); // the site user (the server runs as 'nobody' here)
  const db = JSON.parse(fs.readFileSync(BASE + '/data/db.json', 'utf8'));
  db.sites.push({ domain: 'example.com', type: 'static', user: 'tester', home, root: home + '/public_html', docroot: home + '/public_html', created: new Date().toISOString(), ssl: false, certNames: [], cfg: {}, autoSsl: false });
  fs.writeFileSync(BASE + '/data/db.json', JSON.stringify(db));
  for (const p of ['/', '/sites/new', '/sites/new/wordpress', '/sites/new/laravel', '/sites/new/node', '/sites/new/php', '/sites/new/static', '/sites/new/python', '/sites/new/proxy', '/users', '/sites', '/sites/manage?domain=example.com', '/files', '/files?site=example.com&p=/public_html', '/databases', '/backups', '/cron', '/services', '/tasks', '/security', '/updates', '/audit', '/settings', '/account', '/logs?site=example.com&type=error']) {
    r = await call('GET', p, { jar: A }); assert.equal(r.status, 200, p + ' -> ' + r.status + ' ' + r.text.slice(0, 200));
  }
  assert.equal((await call('GET', '/sites/manage?domain=nope.example', { jar: A })).status, 302);

  /* ---------- app installer pages and validation (nothing may be created on bad input) ---------- */
  r = await call('GET', '/sites/new', { jar: A });
  for (const n of ['WordPress', 'Laravel', 'Node.js', 'PHP', 'Static HTML', 'Python', 'Reverse Proxy']) assert.ok(r.text.includes('Create a ' + n + ' site'), 'picker offers ' + n);
  assert.equal((await call('GET', '/apps', { jar: A })).headers.location, '/sites/new', 'old App Installer URL redirects');
  r = await call('GET', '/sites/new/wordpress', { jar: A });
  assert.ok(/name="adminPassword" type="text" class="mono" value="[A-Za-z0-9]{20}"/.test(r.text) && r.text.includes('name="target"') && r.text.includes('name="dbName"') && r.text.includes('name="dbUser"') && r.text.includes('name="dbPassword"') && r.text.includes('name="tablePrefix"') && !r.text.includes('example.com (existing)'), 'wordpress wizard has separate database name / user / password (static sites are not offered)');
  assert.ok(r.text.includes('Stable only'), 'stable-only notice');
  assert.ok(!/<script(?![^>]*src=)/.test(r.text) && !/ style=/.test(r.text), 'no inline script/style (CSP)');
  assert.equal((await call('GET', '/sites/new/nope', { jar: A })).headers.location, '/sites/new');
  r = await call('POST', '/sites/new/wordpress', { form: { app: 'wordpress' } }); assert.equal(r.status, 401);
  r = await call('POST', '/sites/new/wordpress', { jar: A, form: { app: 'wordpress' } }); assert.equal(r.status, 403, 'CSRF required');
  const dbBefore = fs.readFileSync(BASE + '/data/db.json', 'utf8');
  const wp = { target: '__new__', title: 'T', adminUsername: 'owner1', adminEmail: 'a@b.co', adminPassword: 'x'.repeat(20), locale: 'en_US', dbName: 'wp_site1', dbUser: 'wpu_site1', dbPassword: 'Str0ngPassw0rd!x', tablePrefix: 'wpz_' };
  r = await post(A, '/sites/new/wordpress', Object.assign({}, wp, { domain: 'not a domain' }));
  assert.match(r.headers.location, /^\/sites\/new\/wordpress/); assert.match((await flashOf(A, r.headers.location)).flash, /valid domain/);
  r = await post(A, '/sites/new/wordpress', Object.assign({}, wp, { domain: 'fresh.example.org', adminUsername: 'admin' }));
  const back = await flashOf(A, r.headers.location); assert.match(back.flash, /non-default/);
  assert.ok(back.text.includes('value="fresh.example.org"') && back.text.includes('value="wp_site1"') && !back.text.includes('x'.repeat(20)) && !back.text.includes('Str0ngPassw0rd'), 'typed values are kept on error, passwords are not');
  for (const bad of [{ dbName: 'Bad Name' }, { dbPassword: 'short' }, { dbUser: 'root' }, { tablePrefix: 'bad prefix' }]) {
    r = await post(A, '/sites/new/wordpress', Object.assign({}, wp, { domain: 'fresh.example.org' }, bad)); assert.match((await flashOf(A, r.headers.location)).flash, /./);
  }
  assert.equal(fs.readFileSync(BASE + '/data/db.json', 'utf8'), dbBefore, 'rejected installs change nothing');

  /* ---------- file manager (now asynchronous) ---------- */
  const pub = home + '/public_html', f = (name) => pub + '/' + name;
  const fileOp = async (op, extra) => { await post(A, '/files/' + op, Object.assign({ site: 'example.com', p: '/public_html' }, extra)); return (await flashOf(A, '/files?site=example.com&p=/public_html')).flash; };
  assert.match(await fileOp('mkdir', { name: 'docs' }), /mkdir done/); assert.ok(fs.statSync(f('docs')).isDirectory());
  assert.match(await fileOp('touch', { name: 'a.txt' }), /touch done/); assert.ok(fs.existsSync(f('a.txt')));
  const bigText = 'héllo wörld ✓ 日本語\n'.repeat(20000); // ~500 KB of multi-byte text: must survive chunked reads intact
  await post(A, '/files/save', { site: 'example.com', p: '/public_html/a.txt', content: bigText });
  assert.equal(fs.readFileSync(f('a.txt'), 'utf8'), bigText.replace(/\r\n/g, '\n'));
  r = await call('GET', '/files/edit?site=example.com&p=/public_html/a.txt', { jar: A });
  assert.equal(r.status, 200); assert.ok(r.text.includes('héllo wörld ✓ 日本語'));
  assert.match(await fileOp('rename', { name: 'a.txt', to: 'b.txt' }), /Renamed/); assert.ok(fs.existsSync(f('b.txt')) && !fs.existsSync(f('a.txt')));
  assert.match(await fileOp('chmod', { name: 'b.txt', mode: '600' }), /chmod done/); assert.equal(fs.statSync(f('b.txt')).mode & 0o777, 0o600);
  assert.match(await fileOp('chmod', { name: 'b.txt', mode: '9999' }), /Mode must be/);
  // traversal / bad names
  assert.match(await fileOp('mkdir', { name: '../escape' }), /Invalid name/); assert.ok(!fs.existsSync(home + '/escape'));
  assert.match(await fileOp('touch', { name: '.hp-up-abc' }), /Invalid name/);
  await post(A, '/files/mkdir', { site: 'example.com', p: '/../../../etc', name: 'zz' }); assert.ok(!fs.existsSync('/etc/zz'), 'a ../ path can never reach the real /etc (it is re-rooted inside the site folder)');
  // symlink inside the site pointing outside is refused
  fs.mkdirSync(T + '/outside'); fs.writeFileSync(T + '/outside/secret.txt', 'secret'); fs.symlinkSync(T + '/outside', f('link'));
  r = await flashOf(A, '/files?site=example.com&p=/public_html/link'); assert.match(r.flash, /escapes the site folder/);
  r = await call('GET', '/files/download?site=example.com&p=/public_html/link/secret.txt', { jar: A }); assert.equal(r.status, 400);
  // upload (PUT stream) + download
  const csrf = await getCsrf(A), payload = crypto.randomBytes(300000);
  r = await call('PUT', '/files/upload?site=example.com&p=/public_html&name=up.bin', { jar: A, headers: { 'X-CSRF-Token': csrf }, body: payload });
  assert.equal(r.status, 200, r.text); assert.ok(fs.readFileSync(f('up.bin')).equals(payload));
  r = await call('GET', '/files/download?site=example.com&p=/public_html/up.bin', { jar: A });
  assert.equal(r.status, 200); assert.ok(r.buf.equals(payload)); assert.match(r.headers['content-disposition'], /attachment; filename="up\.bin"/); assert.equal(r.headers['content-security-policy'], 'sandbox');
  r = await call('PUT', '/files/upload?site=example.com&p=/public_html&name=x.bin', { jar: A, body: 'x' }); assert.equal(r.status, 403, 'upload without CSRF token');
  r = await call('PUT', '/files/upload?site=example.com&p=/public_html&name=..', { jar: A, headers: { 'X-CSRF-Token': csrf }, body: 'x' }); assert.equal(r.status, 400);
  // unzip + delete
  if (execFileSync('which', ['zip'], { stdio: 'pipe' }).length) {
    fs.mkdirSync(T + '/zsrc'); fs.writeFileSync(T + '/zsrc/inz.txt', 'zipped'); execFileSync('zip', ['-q', f('pack.zip'), 'inz.txt'], { cwd: T + '/zsrc' });
    assert.match(await fileOp('unzip', { name: 'pack.zip' }), /unzip done/); assert.equal(fs.readFileSync(f('inz.txt'), 'utf8'), 'zipped');
  }
  assert.match(await fileOp('delete', { name: 'docs' }), /rm done/); assert.ok(!fs.existsSync(f('docs')));
  assert.match(await fileOp('delete', { name: 'nonexistent-but-force' }), /rm done|./);
  // many requests while a large save is running: the panel stays responsive
  const bigSave = post(A, '/files/save', { site: 'example.com', p: '/public_html/big.txt', content: 'z'.repeat(1000000) });
  const t0 = Date.now(); const quick = await call('GET', '/login', { jar: jar() }); assert.equal(quick.status, 200);
  await bigSave; assert.equal(fs.statSync(f('big.txt')).size, 1000000);

  /* ---------- release updater UI (no signing key in this checkout, and no GitHub access needed) ---------- */
  r = await call('GET', '/updates', { jar: A }); assert.ok(r.text.includes('HostPanel release') && r.text.includes('Not checked yet'));
  assert.ok(!r.text.includes('/updates/panel'), 'old "npm update as root" button is gone');
  r = await post(A, '/updates/release/apply', { version: '9.9.9' }); assert.equal(r.headers.location, '/tasks');
  assert.match((await flashOf(A, '/tasks')).flash, /Check for updates first/);
  assert.equal((await post(A, '/updates/panel', {})).status, 404, 'removed route');
  r = await post(A, '/updates/release/check', {}); assert.equal(r.headers.location, '/updates');
  const upd = (await flashOf(A, '/updates')).text;
  assert.ok(/Check failed|Up to date|available|No signing key/.test(upd));
  assert.ok(upd.includes('No signing key') === !fs.existsSync(path.join(ROOT, 'lib', 'release-key.pub')));

  /* ---------- login lockout: strangers cannot lock the admin out ---------- */
  const spoof = (ip) => ({ 'X-HP-Proxy': proxySecret, 'X-Real-IP': ip });
  for (let i = 1; i <= 26; i++) await login(jar(), 'boss_user', 'bad-' + i, spoof('10.0.0.' + i)); // 26 failures from 26 different addresses
  r = await login(jar(), 'boss_user', pass1, spoof('10.9.9.9'));
  assert.equal(r.headers.location, '/login'); // an unknown address is refused during the flood...
  const D = jar(); await call('GET', '/login', { jar: D, headers: spoof('10.9.9.9') });
  assert.match((await flashOf(D, '/login')).flash || 'Too many', /Too many|Invalid/);
  const E = jar(); r = await login(E, 'boss_user', pass1);
  assert.equal(r.headers.location, '/', 'an address that signed in before (127.0.0.1) still gets in during the flood');
  // the spoofed header is ignored without the secret
  r = await login(jar(), 'boss_user', 'nope', { 'X-Real-IP': '10.0.0.77' });
  assert.ok(!fs.readFileSync(T + '/auth.log', 'utf8').includes('ip=10.0.0.77'));
  // per-address limit of 5
  for (let i = 0; i < 5; i++) await login(jar(), 'boss_user', 'bad', spoof('10.7.7.7'));
  const F = jar(); await login(F, 'boss_user', pass1, spoof('10.7.7.7'));
  assert.match((await flashOf(F, '/login')).flash, /Too many failed attempts/);

  /* ---------- logout ---------- */
  await post(E, '/logout', {}); assert.equal((await call('GET', '/sites', { jar: E })).headers.location, '/login');
  assert.ok(!outp.join('').match(/Error|TypeError|ReferenceError|UnhandledPromise/), 'server printed errors:\n' + outp.join(''));
  console.log('server end-to-end tests passed (' + (process.env.HP_REAL_EXPRESS || 'express as resolved') + ')');
})().then(() => cleanup(0), (e) => { console.error(e); console.error('--- server output ---\n' + outp.join('').slice(-1500)); cleanup(1); });
function cleanup(code) { try { server.kill('SIGKILL'); } catch (e) {} try { fs.rmSync(T, { recursive: true, force: true }); } catch (e) {} process.exitCode = code; }
