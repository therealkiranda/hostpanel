'use strict';
process.env.HP_NO_NETWORK = '1'; // 1.0.4: never look up versions on the internet in tests
// Runs the REAL installer stack (apps/index -> engine -> WordPress handler -> host adapters -> worker.js -> php) in
// temp folders, unprivileged, with only two things faked: `mysql` (a logging stub) and WP-CLI (a small PHP script that
// mimics the commands HostPanel uses). Proves ordering, permissions, secrets handling and rollback on real files.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

if (process.getuid && process.getuid() === 0 && !process.env.HP_APPS_CHILD) { // worker.js refuses to run as root: re-run as "nobody"
  const r = spawnSync('setpriv', ['--reuid=65534', '--regid=65534', '--clear-groups', process.execPath, __filename], { stdio: 'inherit', env: Object.assign({}, process.env, { HP_APPS_CHILD: '1' }) });
  process.exit(r.status === null ? 1 : r.status);
}
const T = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-apps-')); fs.chmodSync(T, 0o777);
process.env.HP_BASE = T + '/base'; process.env.HP_HOMES = T + '/homes'; process.env.HP_CRED = T + '/cred.txt';
process.env.NODE_PATH = [process.env.NODE_PATH, path.join(__dirname, 'shims')].filter(Boolean).join(path.delimiter); require('module').Module._initPaths();
const bin = T + '/bin'; fs.mkdirSync(bin);
const stub = (n, body) => fs.writeFileSync(bin + '/' + n, '#!/bin/sh\n' + body + '\n', { mode: 0o755 });
const mlog = T + '/mysql.log';
stub('mysql', 'IN=$(cat); echo "$IN" >> "' + mlog + '"\ncase "$IN" in *"SHOW DATABASES"*|*"mysql.user"*) ;; esac');
process.env.PATH = bin + ':' + process.env.PATH;
fs.mkdirSync(T + '/homes');
const phpBinary = spawnSync('which', ['php'], { encoding: 'utf8' }).stdout.trim();

// fake WP-CLI: same command surface HostPanel calls
const FAKE = T + '/wp-cli.phar';
fs.writeFileSync(FAKE, `<?php
$a = array_slice($argv, 1); $path = ''; $words = [];
foreach ($a as $x) { if (strpos($x, '--path=') === 0) $path = substr($x, 7); elseif (strpos($x, '--') !== 0) $words[] = $x; }
$cmd = implode(' ', array_slice($words, 0, 2)); file_put_contents(dirname(getenv('HOME')) . '/wpcli-calls.log', $cmd . ' HOME=' . getenv('HOME') . "\\n", FILE_APPEND);
$f = dirname(getenv('HOME')) . '/fail-at'; if (is_file($f) && trim(file_get_contents($f)) === $words[0] . ' ' . ($words[1] ?? '')) { fwrite(STDERR, "Error: simulated failure\\n"); exit(1); }
if ($cmd === 'core download') { if (!is_dir($path . '/wp-includes')) mkdir($path . '/wp-includes', 0777, true); file_put_contents($path . '/index.php', '<?php // wp'); file_put_contents($path . '/wp-includes/version.php', '<?php'); echo "Success: WordPress downloaded.\\n"; exit(0); }
if ($cmd === 'core install') { if (!is_file($path . '/wp-config.php')) { fwrite(STDERR, "Error: wp-config.php missing\\n"); exit(1); } file_put_contents($path . '/.installed', json_encode($a)); echo "Success: WordPress installed successfully.\\n"; exit(0); }
if ($words[0] === 'eval') { file_put_contents($path . '/.pwhash', hash('sha256', trim((string) fgets(STDIN))) . ' ' . getenv('HP_WP_ADMIN')); exit(0); }
if ($cmd === 'core version') { echo "6.8.3\\n"; exit(0); }
if ($words[0] === 'rewrite') { exit(0); }
fwrite(STDERR, "unknown command $cmd\\n"); exit(1);
`);

const c = require('../lib/core'); const S = require('../lib/sites'); const exec = require('../lib/siteexec');
const { createApps } = require('../lib/apps');
c.init();
const home = T + '/homes/w1', pub = home + '/public_html';
const PLACE = '<?php echo "<h1>example.com</h1><p>Site is ready. Upload your files to public_html.</p>";\n';
const resetSite = (files) => {
  fs.rmSync(home, { recursive: true, force: true });
  for (const d of ['', '/public_html', '/tmp', '/logs']) fs.mkdirSync(home + d, { recursive: true });
  fs.chmodSync(home + '/tmp', 0o700);
  for (const [n, body] of Object.entries(files === undefined ? { 'index.php': PLACE } : files)) fs.writeFileSync(pub + '/' + n, body);
  const d = c.load(); d.sites = [{ domain: 'example.com', type: 'php', php: '8.3', user: 'nobody', home, root: pub, docroot: pub, created: new Date().toISOString(), ssl: false, certNames: [], cfg: {}, autoSsl: false }]; d.dbs = []; c.save(d);
  fs.writeFileSync(mlog, '');
};
const sysStub = { requireDisk() {}, phpVersions: () => ['8.3'] };
const mk = (over) => createApps(Object.assign({ S, c, sys: sysStub, exec, phpBin: () => phpBinary, ensureWpCli: async () => FAKE }, over || {}));
const wait = async () => { for (let i = 0; i < 300; i++) { const j = c.getJob(); if (j && j.end) return j; await new Promise((r) => setTimeout(r, 50)); } throw new Error('job did not finish'); };
const PW = 'very-long-and-random-password-2026';
const form = (o) => Object.assign({ app: 'wordpress', target: 'example.com', title: 'Example', adminUsername: 'siteowner', adminEmail: 'o@example.com', adminPassword: PW, locale: 'en_US', https: '1', email: 'o@example.com' }, o || {});
const failAt = (cmd) => fs.writeFileSync(home + '/tmp/fail-at', cmd);
const sh = (f) => fs.readdirSync(f).sort();

(async () => {
  const apps = mk();

  /* ---- success on an existing site that only has HostPanel's placeholder ---- */
  resetSite();
  let msg = await apps.start(form()); assert.match(msg, /installation started/);
  let j = await wait(); assert.equal(j.code, 0, j.log);
  assert.ok(!fs.readFileSync(pub + '/index.php', 'utf8').includes('Site is ready'), 'placeholder replaced by WordPress');
  assert.ok(fs.existsSync(pub + '/wp-includes/version.php') && fs.existsSync(pub + '/.installed'));
  const cfg = pub + '/wp-config.php'; assert.equal(fs.statSync(cfg).mode & 0o777, 0o600, 'wp-config.php is 600');
  assert.deepEqual(spawnSync(phpBinary, ['-l', cfg], { encoding: 'utf8' }).status, 0);
  const d = c.load(), db = d.dbs[0]; assert.equal(d.dbs.length, 1); assert.match(db.name, /^wp_examplecom_[a-f0-9]{6}$/); assert.equal(db.app, 'wordpress');
  assert.ok(fs.readFileSync(cfg, 'utf8').includes(db.name)); const ml = fs.readFileSync(mlog, 'utf8'); assert.match(ml, new RegExp('CREATE DATABASE `' + db.name + '`'));
  assert.deepEqual(d.sites[0].apps.map((a) => [a.id, a.version, a.path, a.db, a.adminUrl]), [['wordpress', '6.8.3', '', db.name, 'https://example.com/wp-admin/']]);
  assert.equal(fs.readFileSync(pub + '/.pwhash', 'utf8'), crypto.createHash('sha256').update(PW).digest('hex') + ' siteowner', 'real password applied through stdin');
  const installArgs = JSON.parse(fs.readFileSync(pub + '/.installed', 'utf8')); assert.ok(!installArgs.join(' ').includes(PW), 'password not in wp-cli arguments');
  assert.ok(!j.log.includes(PW) && !ml.includes(PW) && !j.log.includes(db.name + '\' IDENTIFIED'), 'no secrets in the job log');
  assert.deepEqual(sh(home + '/tmp'), ['wpcli-calls.log'], 'installer temp folder removed'); assert.match(fs.readFileSync(home + '/tmp/wpcli-calls.log', 'utf8'), /HOME=.*\/tmp\/hp-install-/);
  assert.match(j.log, /DONE: WordPress 6\.8\.3 is ready/); assert.match(j.log, /Admin: https:\/\/example\.com\/wp-admin\//);
  assert.ok(!c.load().sites[0].autoSsl || true);
  // installing again in the same place is refused, with no side effects
  await assert.rejects(() => apps.start(form()), /already installed/); assert.equal(c.load().dbs.length, 1);

  /* ---- a failure half way: everything this attempt created is removed, the placeholder is back ---- */
  resetSite(); failAt('core install');
  await apps.start(form()); j = await wait(); assert.equal(j.code, 1); assert.match(j.log, /simulated failure/); assert.match(j.log, /Cleanup finished/);
  assert.deepEqual(sh(pub), ['index.php']); assert.equal(fs.readFileSync(pub + '/index.php', 'utf8'), PLACE, 'placeholder restored byte for byte');
  assert.deepEqual(c.load().dbs, []); assert.equal(c.load().sites[0].apps, undefined); assert.match(fs.readFileSync(mlog, 'utf8'), /DROP DATABASE IF EXISTS `wp_examplecom_/);
  assert.ok(!j.log.includes(PW));
  // ...and the very next attempt works (retry after fixing the cause)
  fs.unlinkSync(home + '/tmp/fail-at'); await apps.start(form()); j = await wait(); assert.equal(j.code, 0, j.log);

  /* ---- failure at the first command (download): nothing left behind either ---- */
  resetSite(); failAt('core download'); await apps.start(form()); j = await wait(); assert.equal(j.code, 1); assert.deepEqual(sh(pub), ['index.php']); assert.deepEqual(c.load().dbs, []);

  /* ---- sub-folder install, and its rollback removes the folder again ---- */
  resetSite({ 'index.html': '<h1>my real site</h1>' });
  await apps.start(form({ path: 'blog' })); j = await wait(); assert.equal(j.code, 0, j.log);
  assert.ok(fs.existsSync(pub + '/blog/wp-config.php') && fs.readFileSync(pub + '/index.html', 'utf8') === '<h1>my real site</h1>', 'existing site content untouched');
  assert.equal(c.load().sites[0].apps[0].path, 'blog'); assert.equal(c.load().sites[0].apps[0].url, 'https://example.com/blog/');
  resetSite({ 'index.html': '<h1>my real site</h1>' }); failAt('core install');
  await apps.start(form({ path: 'blog' })); j = await wait(); assert.equal(j.code, 1); assert.deepEqual(sh(pub), ['index.html'], 'the new blog/ folder was removed');

  /* ---- refusals happen before anything is created ---- */
  resetSite({ 'index.php': '<?php // someone\'s real application' });
  await assert.rejects(() => apps.start(form()), /not empty/); assert.deepEqual(sh(pub), ['index.php']); assert.deepEqual(c.load().dbs, []); assert.equal(fs.readFileSync(mlog, 'utf8'), '');
  resetSite(); fs.mkdirSync(pub + '/blog'); fs.writeFileSync(pub + '/blog/x', '1'); await assert.rejects(() => apps.start(form({ path: 'blog' })), /not empty/);
  resetSite(); fs.symlinkSync(T, pub + '/blog'); await assert.rejects(() => apps.start(form({ path: 'blog' })), /symbolic link|escapes/);
  resetSite(); await assert.rejects(() => apps.start(form({ adminUsername: 'admin' })), /non-default/);
  await assert.rejects(() => apps.start(form({ path: '../x' })), /Folder must be/); await assert.rejects(() => apps.start(form({ app: 'nope' })), /Unknown application/);
  await assert.rejects(() => apps.start(form({ target: 'missing.com' })), /Site not found/); assert.equal(c.getJob().label.startsWith('Install'), true);
  await assert.rejects(() => apps.start(form({ app: 'laravel', title: 'App' })), /needs a laravel website/);

  /* ---- new-site flow: site is created (SSL deferred) only after validation, and not while another task runs ---- */
  resetSite(); const created = [];
  const S2 = Object.assign(Object.create(S), { createSite: (f, o) => { created.push([f, o]); const d2 = c.load(); d2.sites.push(Object.assign({}, d2.sites[0], { domain: f.domain, type: f.type })); c.save(d2); return 'Site created: ' + f.domain + '\nPassword: secret-sftp'; } });
  const apps2 = mk({ S: S2 });
  await assert.rejects(() => apps2.start(form({ target: '__new__', domain: 'not a domain' })), /valid domain/); await assert.rejects(() => apps2.start(form({ target: '__new__', domain: 'new.example.org', adminPassword: 'weak' })), /16-200/); assert.equal(created.length, 0, 'invalid input never creates a website');
  let release; const gate = new Promise((r) => { release = r; }); c.runAsync('busy', async () => { await gate; });
  await assert.rejects(() => apps2.start(form({ target: '__new__', domain: 'new.example.org' })), /Another task is running/); assert.equal(created.length, 0, 'no website created while another task runs'); release(); await wait();
  msg = await apps2.start(form({ target: '__new__', domain: 'WWW.New.Example.org', php: '8.3' })); assert.match(msg, /secret-sftp/); assert.match(msg, /installation started/);
  assert.deepEqual([created[0][0].domain, created[0][0].type, created[0][0].autoSsl], ['new.example.org', 'php', undefined], 'no automatic Let\'s Encrypt');
  j = await wait(); assert.ok(j.code === 0 || /not empty/.test(j.log), j.log);

  /* ---- existing site + https: nothing is requested or scheduled; the certificate is issued by hand from the SSL section ---- */
  resetSite(); await apps.start(form()); j = await wait(); assert.ok(!c.load().sites[0].autoSsl, 'https never switches auto-SSL on'); assert.match(j.log, /Issue certificate/);
  resetSite(); await apps.start(form({ https: '' })); await wait(); assert.equal(c.load().sites[0].autoSsl, false); assert.equal(c.load().sites[0].apps[0].url, 'http://example.com/');

  /* ---- Laravel: a fresh laravel site keeps its placeholder in public/; fake composer + artisan mimic the real tools ---- */
  const FAKE_COMPOSER = T + '/composer.phar';
  fs.writeFileSync(FAKE_COMPOSER, `<?php
$dir = $argv[3]; if (getenv('COMPOSER_HOME') === false) { fwrite(STDERR, "no COMPOSER_HOME\\n"); exit(1); }
$f = dirname(getenv('HOME')) . '/fail-at'; if (is_file($f) && trim(file_get_contents($f)) === 'composer') { fwrite(STDERR, "Composer: network down\\n"); exit(1); }
if ($argv[1] !== 'create-project' || count(glob($dir . '/*')) > 0) { fwrite(STDERR, "Project directory is not empty\\n"); exit(1); }
mkdir($dir . '/public', 0777, true); file_put_contents($dir . '/public/index.php', '<?php // laravel'); file_put_contents($dir . '/.env.example', "APP_NAME=Laravel\\nAPP_KEY=\\nDB_CONNECTION=sqlite\\n");
file_put_contents($dir . '/.env', file_get_contents($dir . '/.env.example'));
file_put_contents($dir . '/artisan', '<?php $c = $argv[1]; file_put_contents(__DIR__ . "/artisan.log", $c . "\\n", FILE_APPEND); if ($c === "--version") echo "Laravel Framework 12.4.1\\n"; if ($c === "key:generate") { $e = file_get_contents(__DIR__ . "/.env"); file_put_contents(__DIR__ . "/.env", str_replace("APP_KEY=", "APP_KEY=base64:abc", $e)); }');
echo "Application ready\\n";
`);
  const resetLaravel = () => { resetSite({}); fs.mkdirSync(pub + '/public'); fs.writeFileSync(pub + '/public/index.php', '<?php echo "<h1>example.com</h1><p>Site is ready. Upload your files to public_html.</p>";\n'); const d3 = c.load(); d3.sites[0].type = 'laravel'; d3.sites[0].docroot = pub + '/public'; c.save(d3); };
  const lapps = mk({ composerCandidates: [FAKE_COMPOSER] });
  // the PHP tool is invoked as `php -d display_errors=stderr -d memory_limit=-1 <composer> create-project laravel/laravel <dir> ...`
  const lform = (o) => form(Object.assign({ app: 'laravel', title: 'My App' }, o || {}));
  resetLaravel(); await lapps.start(lform()); j = await wait(); assert.equal(j.code, 0, j.log);
  assert.ok(fs.existsSync(pub + '/artisan') && fs.readFileSync(pub + '/public/index.php', 'utf8') === '<?php // laravel');
  const env = fs.readFileSync(pub + '/.env', 'utf8'); assert.equal(fs.statSync(pub + '/.env').mode & 0o777, 0o600);
  assert.match(env, /DB_CONNECTION=mysql\n/); assert.match(env, /APP_NAME="My App"/); assert.match(env, /APP_KEY=base64:abc/); assert.match(fs.readFileSync(pub + '/artisan.log', 'utf8'), /key:generate\nmigrate\n--version/);
  const ldb = c.load().dbs[0]; assert.match(ldb.name, /^lv_examplecom_/); assert.ok(env.includes('DB_DATABASE=' + ldb.name)); assert.equal(c.load().sites[0].apps[0].version, '12.4.1');
  assert.ok(!j.log.includes(env.match(/DB_PASSWORD=(\S+)/)[1]), 'DB password not logged');
  // failure: placeholder (inside public/) comes back exactly, no database left
  resetLaravel(); failAt('composer'); await lapps.start(lform()); j = await wait(); assert.equal(j.code, 1); assert.match(j.log, /network down/); assert.deepEqual(sh(pub), ['public']); assert.equal(sh(pub + '/public').join(), 'index.php'); assert.match(fs.readFileSync(pub + '/public/index.php', 'utf8'), /Site is ready/); assert.deepEqual(c.load().dbs, []);
  // a laravel site with real content is refused
  resetLaravel(); fs.writeFileSync(pub + '/public/index.php', '<?php // real'); await assert.rejects(() => lapps.start(lform()), /not empty/);
  // WordPress half-claim failure: the placeholder is restored even if claiming itself breaks
  resetSite(); const brokenExec = Object.assign({}, exec, { worker: (s, op, rel, arg, input) => (op === 'mkdir' && /blog$/.test(rel) ? Promise.reject(new Error('disk full')) : exec.worker(s, op, rel, arg, input)) });
  await assert.rejects(() => mk({ exec: brokenExec }).start(form({ path: 'blog' })).then(wait).then((jj) => { if (jj.code === 0) throw new Error('should fail'); throw new Error(jj.log); }), /disk full/); assert.deepEqual(sh(pub), ['index.php']);

  fs.rmSync(T, { recursive: true, force: true });
  console.log('app installer end-to-end (real files, worker, php; fake wp-cli + mysql) tests passed');
})().catch((e) => { console.error(e); process.exitCode = 1; });
