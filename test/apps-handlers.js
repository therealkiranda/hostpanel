'use strict';
// WordPress / Laravel handler details: generated config is valid PHP / .env, secrets never reach argv or logs, and the
// WP-CLI / Composer steps run in the right order. Uses real `php -l` to check the generated wp-config.php.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const wordpress = require('../lib/apps/wordpress');
const laravel = require('../lib/apps/laravel');

const db = { name: 'wp_example_a1b2c3', user: 'wp_example_a1b2c3', password: 'f'.repeat(24), host: 'localhost' };
const base = { domain: 'example.com', title: 'My Site', adminUsername: 'siteowner', adminEmail: 'o@example.com', adminPassword: 'very-long-and-random-password-2026', locale: 'en_US' };

/* ---- WordPress input rules ---- */
let x = wordpress.validate(Object.assign({ path: '/Blog/', https: '1' }, base));
assert.equal(x.path, 'blog'); assert.equal(x.https, true); assert.equal(wordpress.validate(base).https, false); assert.equal(wordpress.validate(base).path, '');
assert.throws(() => wordpress.validate(Object.assign({}, base, { title: 'a\nb' })), /Site title/);
assert.ok(wordpress.LOCALES.every(([code]) => /^[a-z]{2,3}(?:_[A-Z]{2})?$/.test(code)), 'every offered locale passes the validator');
assert.ok(wordpress.fields({ email: 'e@x.co', password: 'pw' }).find((f) => f.name === 'adminPassword').value === 'pw');

/* ---- wp-config.php is valid PHP even with hostile-looking values ---- */
const T = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-wpcfg-'));
const nasty = { name: 'wp_a_b', user: 'wp_a_b', password: "pa'ss\\word\"$x;", host: "local'host" };
for (const [d, https] of [[db, false], [nasty, true]]) {
  const text = wordpress.wpConfig(d, { https }, 'wpab12_');
  const f = path.join(T, 'wp-config.php'); fs.writeFileSync(f, text);
  const lint = spawnSync('php', ['-l', f], { encoding: 'utf8' });
  assert.equal(lint.status, 0, 'php -l failed: ' + lint.stdout + lint.stderr);
  // evaluate it with a stub ABSPATH/wp-settings to read back the constants exactly as WordPress would
  fs.writeFileSync(path.join(T, 'wp-settings.php'), '<?php echo json_encode([DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, $table_prefix, defined("FORCE_SSL_ADMIN"), DISALLOW_FILE_EDIT, WP_DEBUG, strlen(AUTH_KEY), AUTH_KEY !== SECURE_AUTH_KEY]);');
  const run = spawnSync('php', [f], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const [n, u, p, h, pre, ssl, noEdit, dbg, saltLen, distinct] = JSON.parse(run.stdout);
  assert.deepEqual([n, u, p, h, pre, ssl, noEdit, dbg, saltLen >= 60, distinct], [d.name, d.user, d.password, d.host || 'localhost', 'wpab12_', https, true, false, true, true]);
}
fs.rmSync(T, { recursive: true, force: true });

/* ---- WordPress install sequence (fake host) ---- */
function fakeHost() {
  const h = { phpCalls: [], writes: [], logs: [] };
  h.ensureTool = async () => '/opt/hostpanel/bin/wp-cli.phar';
  h.makeTemp = async () => ({ rel: '/tmp/hp-install-1', abs: '/home/w1/tmp/hp-install-1' });
  h.removeTemp = async () => { h.removed = true; };
  h.php = async (site, args, opts) => { h.phpCalls.push({ args, opts: opts || {} }); const a = args.join(' '); if (/core version/.test(a)) return 'Success\n6.8.3\n'; if (/--version/.test(a)) return 'Laravel Framework 12.4.1'; return ''; };
  h.writeFile = async (site, rel, content, mode) => { h.writes.push({ rel, content, mode }); };
  h.readFile = async (site, rel) => { if (/\.env$/.test(rel) && h.noEnv) throw new Error('ENOENT'); return rel.endsWith('.env') ? 'APP_NAME=Laravel\nAPP_KEY=base64:abc\n# DB_CONNECTION=sqlite\nDB_PASSWORD=\n' : 'APP_NAME=Laravel\nAPP_KEY=\nDB_CONNECTION=sqlite\n# DB_HOST=127.0.0.1\n'; };
  return h;
}
const site = { domain: 'example.com', home: '/home/w1', user: 'w1', php: '8.3' };
const target = { dir: '/home/w1/public_html', rel: '/public_html' };
(async () => {
  let h = fakeHost(); const logs = [];
  x = wordpress.validate(Object.assign({ https: '1' }, base));
  let r = await wordpress.install({ x, site, target, db, host: h, log: (m) => logs.push(m) });
  const KEYWORDS = ['core', 'eval', 'rewrite', '-l'];
  const stepOf = (c) => { const i = c.args.findIndex((a) => KEYWORDS.includes(a)); return c.args[i] + (c.args[i] === 'core' ? ' ' + c.args[i + 1] : ''); };
  assert.deepEqual(h.phpCalls.map(stepOf), ['core download', '-l', 'core install', 'eval', 'core version', 'rewrite']);
  assert.ok(h.phpCalls.every((c, i) => i === 1 || c.args.includes('--path=/home/w1/public_html')), 'wp-cli always targets the install folder');
  assert.ok(h.phpCalls[0].args.includes('--locale=en_US'));
  // secrets: the real admin password only goes through stdin; the DB password only into the 600 config file
  const allArgs = JSON.stringify(h.phpCalls.map((c) => c.args));
  assert.ok(!allArgs.includes(base.adminPassword) && !allArgs.includes(db.password), 'no secret in any command line');
  assert.ok(!logs.join('\n').includes(base.adminPassword) && !logs.join('\n').includes(db.password), 'no secret in the log');
  const setPw = h.phpCalls.find((c) => c.args.includes('eval'));
  assert.equal(setPw.opts.input, base.adminPassword + '\n'); assert.equal(setPw.opts.env.HP_WP_ADMIN, 'siteowner');
  assert.equal(h.writes.length, 1); assert.equal(h.writes[0].rel, '/public_html/wp-config.php'); assert.equal(h.writes[0].mode, '600'); assert.ok(h.writes[0].content.includes(db.password));
  const inst = h.phpCalls.find((c) => c.args.includes('install')).args;
  assert.ok(inst.includes('--url=https://example.com') && inst.includes('--title=My Site') && inst.includes('--admin_user=siteowner') && inst.includes('--skip-email'));
  const throwaway = inst.find((a) => a.startsWith('--admin_password=')).slice(17); assert.ok(throwaway.length >= 20 && throwaway !== base.adminPassword);
  assert.equal(r.adminUrl, 'https://example.com/wp-admin/'); assert.equal(r.meta.version, '6.8.3'); assert.ok(h.removed, 'temp folder is removed');
  // sub-folder + http
  h = fakeHost(); x = wordpress.validate(Object.assign({ path: 'blog' }, base));
  r = await wordpress.install({ x, site, target: { dir: '/home/w1/public_html/blog', rel: '/public_html/blog' }, db, host: h, log: () => {} });
  assert.equal(r.url, 'http://example.com/blog/'); assert.ok(h.phpCalls[2].args.includes('--url=http://example.com/blog'));
  // pretty permalinks are cosmetic: a failure there must not fail the install
  h = fakeHost(); const orig = h.php; h.php = async (s, a, o) => { if (a.includes('rewrite')) throw new Error('rewrite failed'); return orig(s, a, o); };
  x = wordpress.validate(base); r = await wordpress.install({ x, site, target, db, host: h, log: (m) => logs.push(m) }); assert.ok(logs.some((l) => /permalinks were not set/.test(l)));
  // a failing core install propagates (the engine rolls back) and still cleans the temp folder
  h = fakeHost(); const o2 = h.php; h.php = async (s, a, o) => { if (a.includes('install')) throw new Error('db down'); return o2(s, a, o); };
  await assert.rejects(() => wordpress.install({ x, site, target, db, host: h, log: () => {} }), /db down/); assert.ok(h.removed);

  /* ---- Laravel ---- */
  assert.throws(() => laravel.validate({ domain: 'example.com', title: 'x"; rm', path: '' }), /Application name/);
  assert.throws(() => laravel.validate({ domain: 'example.com', title: 'App', path: 'sub' }), /site root/);
  assert.throws(() => laravel.validate({ domain: 'bad', title: 'App' }), /valid domain/);
  const lx = laravel.validate({ domain: 'Example.com', title: 'My App', https: '1' });
  assert.deepEqual([lx.domain, lx.https, lx.path], ['example.com', true, '']);
  const env = laravel.setEnv('APP_NAME=Laravel\n# DB_HOST=127.0.0.1\nDB_CONNECTION=sqlite\n', { APP_NAME: 'My App', DB_HOST: 'localhost', DB_CONNECTION: 'mysql', DB_PASSWORD: 'a$b"c\\d', NEW_KEY: 'v' });
  assert.equal(env, 'APP_NAME="My App"\nDB_HOST=localhost\nDB_CONNECTION=mysql\nDB_PASSWORD="a\\$b\\"c\\\\d"\nNEW_KEY=v\n');
  assert.equal(laravel.setEnv('', { A: '1' }), 'A=1\n'); assert.equal(laravel.setEnv('X=1', { A: '2' }), 'X=1\nA=2\n');
  h = fakeHost(); const lsite = Object.assign({}, site, { type: 'laravel' });
  r = await laravel.install({ x: lx, site: lsite, target, db, host: h, log: () => {} });
  const create = h.phpCalls[0].args; assert.ok(create.includes('create-project') && create.includes('laravel/laravel') && create.includes('/home/w1/public_html'));
  assert.equal(h.phpCalls[0].opts.env.COMPOSER_HOME, '/home/w1/tmp/hp-install-1/composer');
  const envFile = h.writes.find((w) => w.rel === '/public_html/.env'); assert.equal(envFile.mode, '600');
  assert.match(envFile.content, /DB_CONNECTION=mysql\n/); assert.match(envFile.content, /DB_DATABASE=wp_example_a1b2c3\n/); assert.match(envFile.content, /APP_URL=https:\/\/example\.com\n/); assert.match(envFile.content, /APP_DEBUG=false/);
  assert.ok(!JSON.stringify(h.phpCalls.map((c) => c.args)).includes(db.password), 'DB password only in .env');
  assert.ok(!h.phpCalls.some((c) => c.args.includes('key:generate')), 'an existing APP_KEY is kept');
  assert.ok(h.phpCalls.some((c) => c.args.includes('migrate') && c.args.includes('--force'))); assert.equal(r.meta.version, '12.4.1'); assert.ok(h.removed);
  h = fakeHost(); h.readFile = async (s, rel) => { if (rel.endsWith('/.env')) throw new Error('ENOENT'); return 'APP_KEY=\nDB_CONNECTION=sqlite\n'; };
  await laravel.install({ x: lx, site: lsite, target, db, host: h, log: () => {} });
  assert.ok(h.phpCalls.some((c) => c.args.includes('key:generate')), 'a missing APP_KEY is generated'); assert.ok(h.writes[0].content.includes('DB_DATABASE='));
  console.log('app installer handler tests passed');
})().catch((e) => { console.error(e); process.exitCode = 1; });
