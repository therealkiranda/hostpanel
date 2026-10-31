'use strict';
// 1.0.4 building blocks: stable-only versions, service unit text, phpMyAdmin files, database SQL safety.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const T = fs.mkdtempSync(os.tmpdir() + '/hp-v104-');
process.env.HP_BASE = T + '/base'; process.env.HP_HOMES = T + '/homes'; process.env.HP_SYSTEMD = T;
fs.mkdirSync(T + '/bin'); fs.writeFileSync(T + '/bin/mysql', '#!/bin/sh\ncat >> "' + T + '/sql.log"\nexit 0\n', { mode: 0o755 });
process.env.PATH = T + '/bin:' + process.env.PATH;
fs.mkdirSync(T + '/base/data', { recursive: true }); fs.mkdirSync(T + '/base/backups', { recursive: true }); fs.mkdirSync(T + '/homes');
fs.writeFileSync(T + '/base/data/db.json', JSON.stringify({ secret: 'x', admin: { user: 'a', hash: 'h' }, sites: [], dbs: [], settings: {} }));
const stable = require('../lib/apps/stable');
const runtime = require('../lib/runtime');
const pma = require('../lib/pma');
const dbs = require('../lib/dbs');
const c = require('../lib/core');
const access = require('../lib/access');

(async () => {
  /* stable only */
  for (const v of ['6.8.3', '12.0.1', 'v12.1.0', '6.9']) assert.ok(stable.isStable(v), v);
  for (const v of ['6.9-beta1', '6.9-RC2', 'v13.0.0-alpha', 'dev-master', '12.x-dev', '', null, '6.9.0-rc1']) assert.ok(!stable.isStable(v), String(v));
  assert.equal((await stable.latestWordPress({ getJson: async () => ({ offers: [{ version: '6.9-RC2' }, { version: '6.8.3' }, { version: '6.8.2' }, { version: '7.0-beta1' }] }) })).version, '6.8.3');
  const lv = await stable.latestLaravel({ getJson: async () => ({ packages: { 'laravel/laravel': [{ version: 'dev-master' }, { version: 'v13.0.0-beta1', require: { php: '^8.4' } }, { version: 'v12.0.2', require: { php: '^8.2' } }, { version: 'v12.0.1' }] } }) });
  assert.deepEqual(lv, { version: '12.0.2', php: '8.2' });
  assert.ok(stable.phpAtLeast('8.3', '8.2') && !stable.phpAtLeast('8.1', '8.2') && stable.phpAtLeast('8.2', null));
  await assert.rejects(stable.getJson('https://evil.example/x'), /Blocked/); await assert.rejects(stable.getJson('http://api.wordpress.org/x'), /Blocked/);

  /* service unit for Node.js / Python sites */
  const site = { domain: 'app.example.com', type: 'node', user: 'wabcdef0123', home: '/home/wabcdef0123', port: 3010, cmd: 'node server.js --port {PORT}' };
  const unit = runtime.unitText(site);
  assert.ok(unit.includes('User=wabcdef0123') && unit.includes("ExecStart=/bin/sh -c 'exec node server.js --port 3010'") && unit.includes('NoNewPrivileges=true') && unit.includes('TemporaryFileSystem=/home:ro') && unit.includes('BindPaths=/home/wabcdef0123') && !/StandardOutput=append/.test(unit), unit);
  for (const bad of ["node a.js; rm -rf /", 'node $(id)', "node 'x'", 'node a.js\nExecStartPre=/bin/evil', 'node a.js && x', '../../bin/sh', 'node `id`', 'node a.js | tee', 'x'.repeat(250), 'node /etc/shadow']) assert.throws(() => runtime.cleanCmd(bad, 'node'), /./, bad);
  assert.equal(runtime.cleanCmd('', 'python'), 'venv/bin/python app.py');
  assert.throws(() => runtime.unitText(Object.assign({}, site, { user: 'root' })), /Unsafe/); assert.throws(() => runtime.unitText(Object.assign({}, site, { port: '3010\nUser=root' })), /Unsafe/);
  runtime.install = runtime.install; // writes into HP_SYSTEMD; systemctl is absent here, so only check the file writer
  assert.equal(runtime.nextPort({ sites: [{ port: 3001 }, { port: 3002 }] }), 3003);

  /* phpMyAdmin files */
  const cfg = pma.configPhp('a'.repeat(32));
  assert.ok(cfg.includes("'auth_type'] = 'signon'") && cfg.includes("AllowNoPassword'] = false") && cfg.includes("AllowArbitraryServer'] = false")); assert.throws(() => pma.configPhp("x'; system('id'); '"), /Bad secret/);
  const pool = pma.poolConf(); assert.ok(pool.includes('open_basedir') && pool.includes('user = www-data') && !pool.includes('root'));
  assert.ok(pma.urlFor('panel.example.com:8443', 'ab').startsWith('https://panel.example.com:8444/hp-signon?t=ab')); assert.throws(() => pma.urlFor('bad host/../x', 'ab'), /address/);
  const signon = fs.readFileSync(__dirname + '/../lib/pma/signon.php', 'utf8'); assert.ok(signon.includes('unlink($file)') && signon.includes('[a-f0-9]{48}') && signon.includes("'secure' => true") && signon.includes('(int)$j[\'exp\'] < time()'), 'single-use, expiring ticket');

  /* database SQL safety */
  assert.equal(dbs.q("a'b\\c"), "'a\\'b\\\\c'"); assert.throws(() => dbs.q('a\nb'), /Invalid/); assert.equal(dbs.gdb('wp_site_1'), '`wp\\_site\\_1`'); assert.throws(() => dbs.gdb('x`; DROP'), /Bad/);
  for (const n of ['ab', 'Mysql', '1abc', 'a-b', 'a b', 'x'.repeat(40), 'root', 'mysql', 'pma']) assert.throws(() => dbs.cleanName(n, 'Database name'), /./, n);
  for (const p of ['short', 'has space 12345', "quote'quote1234", 'back\\slash1234', 'back`tick12345', 'dollar$sign1234', 'x'.repeat(65)]) assert.throws(() => dbs.cleanPassword(p), /Database password/, p);
  assert.doesNotThrow(() => dbs.cleanPassword('Str0ng!@#%^*_+=.,:;~-')); assert.ok(c.validPassword(c.genPassword(20)));
  const r = dbs.create({ name: 'blog_db', user: 'blog_user', password: 'Str0ngPassw0rd!x', site: '', ownerId: 'system' });
  assert.deepEqual([r.name, r.user, r.host], ['blog_db', 'blog_user', 'localhost']);
  assert.throws(() => dbs.create({ name: 'other_db', user: 'blog_user', password: 'Str0ngPassw0rd!x' }), /not available/, 'a user name cannot be reused across websites');
  assert.throws(() => dbs.create({ name: 'blog_db', user: 'x_user_2' }), /already exists/);
  dbs.finalDelete('blog_db'); assert.equal(c.load().dbs.length, 0); assert.equal(c.load().dbusers.length, 0);
  const sql = fs.readFileSync(T + '/sql.log', 'utf8'); assert.ok(sql.includes('DROP DATABASE `blog_db`') && sql.includes("DROP USER IF EXISTS 'blog_user'@'localhost'"));

  /* client access list is default-deny */
  assert.ok(access.customerAllowed('GET', '/databases') && access.customerAllowed('POST', '/databases/pma') && access.customerAllowed('PUT', '/files/upload'));
  for (const [m, p] of [['GET', '/settings'], ['POST', '/sites/delete'], ['GET', '/users'], ['POST', '/tools/install'], ['GET', '/sites/new'], ['GET', '/sites/new/node'], ['POST', '/databases/assign'], ['GET', '/sites/manage/../../settings'], ['POST', '/services/action'], ['GET', '/audit']]) assert.ok(!access.customerAllowed(m, p), m + ' ' + p);
  console.log('1.0.4 unit tests passed');
})().then(() => { fs.rmSync(T, { recursive: true, force: true }); }, (e) => { console.error(e); fs.rmSync(T, { recursive: true, force: true }); process.exit(1); });
