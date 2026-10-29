'use strict';
// Database creation guards, safe site restore, disk guard and the async job runner, using the real lib code
// with fake `mysql`/`df` commands and real tar/find. Runs unprivileged in temp folders.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const T = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-sites-'));
process.env.HP_BASE = T + '/base'; process.env.HP_HOMES = T + '/homes';
process.env.NODE_PATH = [process.env.NODE_PATH, path.join(__dirname, 'shims')].filter(Boolean).join(path.delimiter); require('module').Module._initPaths();
const bin = T + '/bin'; fs.mkdirSync(bin);
const log = T + '/mysql.log';
const stub = (n, body) => { fs.writeFileSync(bin + '/' + n, '#!/bin/sh\n' + body + '\n', { mode: 0o755 }); };
stub('mysql', 'IN=$(cat); echo "$IN" >> "' + log + '"\ncase "$IN" in\n *"SHOW DATABASES"*) [ -f "' + T + '/exists-db" ] && echo found;;\n *"mysql.user"*) [ -f "' + T + '/exists-user" ] && echo found;;\n *"CREATE USER"*) [ -f "' + T + '/fail-create" ] && exit 1;;\nesac\nexit 0');
process.env.PATH = bin + ':' + process.env.PATH;
fs.mkdirSync(T + '/base/data', { recursive: true }); fs.mkdirSync(T + '/base/backups', { recursive: true }); fs.mkdirSync(T + '/homes');
const c = require('../lib/core'); const S = require('../lib/sites'); const sys = require('../lib/sys');
const user = 'wtest0001', home = T + '/homes/' + user;
const writeDb = (extra) => fs.writeFileSync(c.P.DB_FILE, JSON.stringify(Object.assign({ secret: 'x', admin: { user: 'a', hash: 'h' }, sites: [{ domain: 'ex.com', type: 'static', user, home, root: home + '/public_html', docroot: home + '/public_html', cfg: {} }], dbs: [] }, extra || {})));
writeDb();
const wait = async () => { for (let i = 0; i < 200; i++) { const j = c.getJob(); if (j && j.end) return j; await new Promise((r) => setTimeout(r, 50)); } throw new Error('job did not finish'); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  /* ---- database creation ---- */
  assert.throws(() => S.createDb('mysql'), /reserved/); assert.throws(() => S.createDb('root'), /reserved/); assert.throws(() => S.createDb('ab'), /Name:/); assert.throws(() => S.createDb('x; DROP DATABASE y'), /Name:/);
  assert.match(S.createDb('shop_db'), /Password: [a-f0-9]{24}/); assert.deepEqual(c.load().dbs.map((d) => d.name), ['shop_db']);
  assert.throws(() => S.createDb('shop_db'), /already exists/);
  fs.writeFileSync(log, ''); fs.writeFileSync(T + '/exists-db', '1');
  assert.throws(() => S.createDb('blog_db'), /already exists on this server/); assert.ok(!fs.readFileSync(log, 'utf8').includes('CREATE DATABASE'), 'never touches an existing database'); fs.rmSync(T + '/exists-db');
  fs.writeFileSync(T + '/exists-user', '1'); assert.throws(() => S.createDb('blog_db'), /user with that name already exists/); fs.rmSync(T + '/exists-user');
  fs.writeFileSync(log, ''); fs.writeFileSync(T + '/fail-create', '1');
  assert.throws(() => S.createDb('blog_db'), /./);
  assert.match(fs.readFileSync(log, 'utf8'), /DROP DATABASE IF EXISTS `blog_db`/, 'a half-created database is removed again');
  assert.deepEqual(c.load().dbs.map((d) => d.name), ['shop_db']); fs.rmSync(T + '/fail-create');

  /* ---- disk guard ---- */
  stub('df', 'echo "Filesystem 1K-blocks Used Available Use% Mounted on"; echo "/dev/x 100 96 4 96% /"');
  assert.throws(() => sys.requireDisk('/', 90, 'the backup'), /96% full/); assert.throws(() => S.backupAll(), /96% full/); assert.throws(() => S.backupSite('ex.com'), /96% full/);
  stub('df', 'echo "Filesystem 1K-blocks Used Available Use% Mounted on"; echo "/dev/x 100 40 60 40% /"'); sys.requireDisk('/', 90, 'x');
  fs.rmSync(bin + '/df');

  /* ---- site restore ---- */
  const put = (rel, body) => { const f = home + '/' + rel; fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, body); };
  put('public_html/index.php', 'orig'); put('public_html/sub/a.txt', 'a'); put('tmp/s', 's'); put('logs/php.log', 'l');
  fs.mkdirSync(T + '/outside'); fs.writeFileSync(T + '/outside/victim.txt', 'precious');
  S.backupSite('ex.com'); let j = await wait(); assert.equal(j.code, 0, j.log);
  const backups = () => fs.readdirSync(c.P.BACKUPS).filter((n) => /^site-ex\.com-/.test(n)).sort();
  const good = backups()[0]; assert.ok(good);
  // damage the live site, including a planted symlink that points at a folder outside the site
  put('public_html/index.php', 'HACKED'); put('public_html/stale.txt', 'stale'); fs.symlinkSync(T + '/outside', home + '/public_html/sub-link'); fs.rmSync(home + '/public_html/sub', { recursive: true }); fs.symlinkSync(T + '/outside', home + '/public_html/sub');
  await sleep(1100); // new timestamp for the safety backup
  assert.throws(() => S.restoreBackup(good, 'wrong.com'), /Confirmation did not match/);
  S.restoreBackup(good, 'ex.com'); j = await wait(); assert.equal(j.code, 0, j.log);
  assert.equal(fs.readFileSync(home + '/public_html/index.php', 'utf8'), 'orig');
  assert.ok(!fs.existsSync(home + '/public_html/stale.txt'), 'files that were not in the backup are gone'); assert.ok(!fs.existsSync(home + '/public_html/sub-link'), 'planted symlink is removed');
  assert.ok(fs.lstatSync(home + '/public_html/sub').isDirectory() && fs.readFileSync(home + '/public_html/sub/a.txt', 'utf8') === 'a', 'a symlink planted where the backup has a folder is replaced by the folder');
  assert.equal(fs.readFileSync(T + '/outside/victim.txt', 'utf8'), 'precious'); assert.deepEqual(fs.readdirSync(T + '/outside'), ['victim.txt'], 'nothing was written through the symlink');
  assert.equal(backups().length, 2, 'a safety backup of the pre-restore state was made');
  assert.match(j.log, /Archive looks safe/);

  // a booby-trapped archive is refused before anything is deleted
  const evilSrc = T + '/evil/' + user; fs.mkdirSync(evilSrc + '/public_html', { recursive: true }); fs.writeFileSync(evilSrc + '/public_html/a', 'x'); fs.linkSync(evilSrc + '/public_html/a', evilSrc + '/public_html/b');
  const evil = 'site-ex.com-20200101000000.tar.gz'; execFileSync('tar', ['-czf', c.P.BACKUPS + '/' + evil, '-C', T + '/evil', user]);
  put('public_html/marker.txt', 'still here');
  S.restoreBackup(evil, 'ex.com'); j = await wait(); assert.notEqual(j.code, 0); assert.match(j.log, /ARCHIVE REJECTED/);
  assert.equal(fs.readFileSync(home + '/public_html/marker.txt', 'utf8'), 'still here', 'live site untouched when the archive is rejected');
  assert.throws(() => S.restoreBackup('../../etc/passwd', 'x'), /Backup not found/);

  /* ---- async job runner ---- */
  let release; const gate = new Promise((r) => { release = r; });
  const job = c.runAsync('slow thing', async (l) => { l('started'); await gate; l('finished'); });
  assert.throws(() => c.runAsync('second', async () => {}), /Another task is running/); assert.equal(c.jobRunning(), true);
  release(); await wait(); assert.equal(c.getJob().code, 0); assert.match(c.getJob().log, /started\nfinished/);
  c.runAsync('boom', async () => { throw new Error('nope'); }); j = await wait(); assert.equal(j.code, 1); assert.match(j.log, /ERROR: nope/);
  const d = c.load(); const sv = d.admin.sv; assert.equal(c.bumpSessions(d), sv + 1);

  fs.rmSync(T, { recursive: true, force: true });
  console.log('database guards, safe restore, disk guard and job runner tests passed');
})().catch((e) => { console.error(e); process.exitCode = 1; });
