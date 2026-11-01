'use strict';
// 1.0.6: mandatory two-factor building blocks, PHP version tools, WordPress password minimum, access list.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const T = fs.mkdtempSync(os.tmpdir() + '/hp-v106-');
process.env.HP_BASE = T + '/base'; process.env.HP_HOMES = T + '/homes';
fs.mkdirSync(T + '/base/data', { recursive: true }); fs.mkdirSync(T + '/homes');
fs.writeFileSync(T + '/base/data/db.json', JSON.stringify({ secret: 'x', admin: { user: 'a', hash: 'h' }, sites: [], dbs: [], settings: {} }));
const c = require('../lib/core');
const sys = require('../lib/sys');
const tools = require('../lib/tools');
const access = require('../lib/access');
const twofa = require('../lib/twofa');
const { validate } = require('../lib/wordpress-installer');

try {
  /* TOTP: right code accepted once per holder, wrong/short/non-numeric refused, no secret = refused */
  const secret = c.b32enc(Buffer.from('12345678901234567890'));
  const now = Date.now(), holder = { totpLast: 0 };
  assert.equal(c.totpCode(secret, 59000), '287082', 'RFC 6238 test vector (SHA-1, T=59s)');
  assert.ok(c.totpCheck(secret, c.totpCode(secret, now), holder), 'current code accepted');
  assert.ok(!c.totpCheck(secret, c.totpCode(secret, now), holder), 'the same code is refused the second time (replay)');
  assert.ok(!c.totpCheck(secret, c.totpCode(secret, now - 30000), holder), 'an older step cannot be used after a newer one');
  assert.ok(c.totpCheck(secret, c.totpCode(secret, now + 30000), { totpLast: 0 }), 'one step of clock drift is tolerated');
  assert.ok(!c.totpCheck(secret, c.totpCode(secret, now + 120000), { totpLast: 0 }), 'two minutes away is refused');
  for (const bad of ['', '12345', '1234567', 'abcdef', '12 34', null, undefined]) assert.ok(!c.totpCheck(secret, bad, null), 'refused: ' + bad);
  assert.ok(!c.totpCheck('', c.totpCode(secret, now), null) && !c.totpCheck(null, '123456', null), 'no secret = never valid');

  /* who still has to set up an authenticator, and what they may open meanwhile */
  const d = { admin: { user: 'a', totp: null }, users: [{ id: 'u1', username: 'k', totpSecret: null }, { id: 'u2', username: 'j', totpSecret: secret }] };
  const adminReq = { session: { role: 'admin' } }, k = { session: { role: 'customer', uid: 'u1' } }, j = { session: { role: 'customer', uid: 'u2' } };
  assert.ok(twofa.pending(adminReq, d) && twofa.pending(k, d) && !twofa.pending(j, d), 'login without a secret is pending');
  d.admin.totp = secret; assert.ok(!twofa.pending(adminReq, d));
  assert.ok(twofa.pending({ session: { role: 'customer', uid: 'gone' } }, d), 'unknown login is treated as pending (never open)');
  for (const p of ['/account', '/account/2fa/start', '/account/2fa/enable', '/logout']) assert.ok(twofa.pendingAllowed({ path: p }), p);
  for (const p of ['/', '/sites', '/files', '/databases', '/settings', '/users', '/sites/new', '/accountx', '/tasks']) assert.ok(!twofa.pendingAllowed({ path: p }), p + ' stays closed');
  for (const p of ['start', 'enable', 'cancel']) assert.ok(access.customerAllowed('POST', '/account/2fa/' + p), 'clients may set up their authenticator');
  assert.ok(!access.customerAllowed('POST', '/account/2fa/disable') && !access.customerAllowed('POST', '/account/username'), 'there is no way to switch 2FA off or rename the administrator');
  const uri = twofa.card({ session: { role: 'admin', pendingTotp: secret, csrf: 'a' }, headers: { host: 'host.example.com:8443' } }, { admin: { user: 'boss', totp: null }, users: [] });
  assert.ok(uri.includes('otpauth://totp/') && uri.includes('secret=' + secret) && uri.includes('Open in my authenticator app'), 'setup card offers the tap-to-open link');
  assert.ok(!/Disable 2FA|disable/i.test(twofa.card({ session: { role: 'admin', csrf: 'a' }, headers: {} }, { admin: { user: 'boss', totp: secret }, users: [] })), 'no disable button once it is on');

  /* PHP 8.4 / 8.5 tools */
  for (const v of ['8.4', '8.5']) {
    const t = tools.TOOLS['php' + v.replace('.', '')]; assert.ok(t, 'tool for PHP ' + v);
    const s = t.steps(); assert.equal(s[0][0], 'bash'); assert.ok(s[0][1][1].includes('ppa:ondrej/php') && s[0][1][1].includes('php' + v + '-fpm'), 'PPA only when the distro lacks it');
    const inst = s.find((x) => x[0] === 'apt-get' && x[1].includes('install')); for (const e of ['fpm', 'cli', 'mysql', 'curl', 'gd', 'mbstring', 'xml', 'zip', 'intl', 'bcmath']) assert.ok(inst[1].includes('php' + v + '-' + e), e);
    assert.ok(s.some((x) => x[0] === 'systemctl' && x[1].join(' ') === 'enable --now php' + v + '-fpm'));
    assert.equal(t.ready(), sys.phpVersions().includes(v), 'ready() follows what is installed on this machine (CI runners ship PHP)');
  }
  assert.equal(sys.defaultPhp(['8.3', '8.4', '8.5']), '8.4'); assert.equal(sys.defaultPhp(['8.3']), '8.3'); assert.equal(sys.defaultPhp(['8.3', '8.5']), '8.5'); assert.equal(sys.defaultPhp([]), '');
  assert.ok(require('../lib/privileged-protocol') && fs.readFileSync(__dirname + '/../lib/privileged-protocol.js', 'utf8').includes('php8.4-fpm') && fs.readFileSync(__dirname + '/../lib/privileged-protocol.js', 'utf8').includes('php8.5-fpm'));

  /* WordPress administrator password: 8 characters is enough, 7 is not */
  const input = { domain: 'a.example.com', title: 'T', adminUsername: 'siteowner', adminEmail: 'a@b.co', adminPassword: '12345678' };
  assert.equal(validate(input).adminPassword, '12345678');
  assert.throws(() => validate(Object.assign({}, input, { adminPassword: '1234567' })), /8-200/);
  assert.throws(() => validate(Object.assign({}, input, { adminPassword: 'abcdefgh\nij' })), /8-200/);
  console.log('1.0.6 unit tests passed');
} catch (e) { console.error(e); process.exitCode = 1; } finally { fs.rmSync(T, { recursive: true, force: true }); }
