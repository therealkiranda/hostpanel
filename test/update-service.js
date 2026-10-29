'use strict';
// End-to-end test of the GitHub release updater against a temporary install folder.
// GitHub, npm, systemd and curl are replaced by fakes; the tarball, signatures, file swapping and the generated
// watchdog shell script are all real, so both the success path and the automatic rollback are exercised.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const { createService, checkUrl, API_URL } = require('../lib/update-service');
const { manifestPayload } = require('../lib/updater');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-upd-'));
const w = (f, body, mode) => { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, body, mode ? { mode } : undefined); };
const read = (f) => fs.readFileSync(f, 'utf8');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---- fake system commands, first in PATH ---- */
const bin = path.join(root, 'bin'); fs.mkdirSync(bin);
const calls = path.join(root, 'calls.log');
const stub = (name, body) => w(path.join(bin, name), '#!/bin/sh\n' + body + '\n', 0o755);
stub('systemctl', 'echo "systemctl $*" >> "' + calls + '"');
stub('curl', 'echo "curl $*" >> "' + calls + '"; [ -f "' + root + '/panel-healthy" ]');
stub('systemd-run', 'echo "systemd-run $*" >> "' + calls + '"\nfor a in "$@"; do case "$a" in /*) S="$a";; esac; done\n/bin/sh "$S" >/dev/null 2>&1 &');
stub('npm', 'echo "npm $*" >> "' + calls + '"\n[ -f "' + root + '/npm-fails" ] && { echo "npm broke" >&2; exit 1; }\ncase "$*" in *--ignore-scripts*) ;; *) echo "npm must run with --ignore-scripts" >&2; exit 1;; esac\nmkdir -p node_modules/express && echo \'{"name":"express"}\' > node_modules/express/package.json');
process.env.PATH = bin + ':' + process.env.PATH;

/* ---- a fake "installed" panel at 1.0.1 ---- */
const installBase = () => {
  const b = path.join(root, 'opt-' + crypto.randomBytes(3).toString('hex'));
  w(b + '/server.js', '// OLD server\n'); w(b + '/cli.js', '// OLD cli\n'); w(b + '/worker.js', '// OLD worker\n');
  w(b + '/package.json', '{"name":"hostpanel","version":"1.0.1"}\n');
  w(b + '/lib/core.js', '// OLD core\n'); w(b + '/public/app.js', '// OLD app\n'); w(b + '/node_modules/express/package.json', '{"name":"express","old":true}');
  w(b + '/data/db.json', '{"admin":{"user":"x"}}\n', 0o600);
  return b;
};

/* ---- build a signed release ---- */
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const other = crypto.generateKeyPairSync('ed25519');
function release(version, mutate) {
  const dir = path.join(root, 'rel-' + version + '-' + crypto.randomBytes(3).toString('hex')); const top = dir + '/hostpanel';
  w(top + '/server.js', '// NEW server ' + version + '\n'); w(top + '/cli.js', '// NEW cli\n'); w(top + '/worker.js', '// NEW worker\n');
  w(top + '/package.json', JSON.stringify({ name: 'hostpanel', version }) + '\n'); w(top + '/package-lock.json', '{"lockfileVersion":3}\n');
  w(top + '/lib/core.js', '// NEW core\n'); w(top + '/lib/sites.js', '// NEW sites\n'); w(top + '/public/app.js', '// NEW app\n');
  if (mutate) mutate(top);
  const tgz = dir + '.tar.gz';
  execFileSync('tar', ['-czf', tgz, '-C', dir, 'hostpanel']);
  const sha = crypto.createHash('sha256').update(fs.readFileSync(tgz)).digest('hex');
  const m = { version, assetUrl: 'https://github.com/therealkiranda/hostpanel/releases/download/v' + version + '/hostpanel-' + version + '.tar.gz', sha256: sha };
  m.signature = crypto.sign(null, Buffer.from(manifestPayload(m)), privateKey).toString('base64');
  return { version, tgz, m, sha };
}
function fakeGithub(rel, opts) {
  opts = opts || {};
  const manifestUrl = 'https://github.com/therealkiranda/hostpanel/releases/download/v' + rel.version + '/manifest.json';
  return {
    fetchBuffer: async (url) => {
      if (url === API_URL) { if (opts.noRelease) { const e = new Error('Not found on GitHub (no release published yet?)'); throw e; } return Buffer.from(JSON.stringify({ tag_name: 'v' + rel.version, name: 'v' + rel.version, assets: [{ name: 'manifest.json', browser_download_url: opts.badAssetUrl || manifestUrl }] })); }
      if (url === manifestUrl) return Buffer.from(JSON.stringify(opts.manifest || rel.m));
      throw new Error('unexpected fetch ' + url);
    },
    fetchToFile: async (url, dest) => { assert.equal(url, rel.m.assetUrl); fs.copyFileSync(opts.tgzOverride || rel.tgz, dest, fs.constants.COPYFILE_EXCL); }
  };
}
const logs = [];
const runAsync = (label, fn) => fn((m) => logs.push(m)); // same contract as core.runAsync, but returns the promise
const svc = (base, rel, extra, gh) => createService(Object.assign({ base, port: 8443, version: '1.0.1', publicKey, healthSeconds: 3, restartDelay: 0 }, gh || fakeGithub(rel), extra || {}));
const waitResult = async (base) => { for (let i = 0; i < 100; i++) { const f = base + '/updates/last-result'; if (fs.existsSync(f)) return read(f).trim().split('|'); await sleep(100); } throw new Error('watchdog never finished'); };

(async () => {
  // URL policy
  assert.ok(checkUrl('https://github.com/therealkiranda/hostpanel/releases/download/v1.0.2/x.tar.gz'));
  assert.ok(checkUrl('https://objects.githubusercontent.com/a'));
  for (const bad of ['http://github.com/x', 'https://evil.example/x', 'https://github.com.evil.example/x', 'https://user:pw@github.com/x', 'https://github.com:8443/x', 'file:///etc/passwd', 'not a url']) assert.throws(() => checkUrl(bad), /Blocked|Invalid/, bad);

  // ---------- 1. check(): newer, verified ----------
  const r102 = release('1.0.2');
  let base = installBase();
  let s = svc(base, r102);
  let st = await s.check();
  assert.equal(st.newer, true); assert.equal(st.verified, true); assert.equal(st.latest, '1.0.2'); assert.ok(!st.error);

  // not newer: same version, and an older "latest"
  assert.equal((await svc(base, release('1.0.1')).check()).newer, false);
  assert.equal((await svc(base, release('1.0.0')).check()).newer, false);
  // no release published
  assert.match((await svc(base, r102, {}, fakeGithub(r102, { noRelease: true })).check()).error, /Not found/);
  // signed by someone else
  const forged = release('1.0.3'); forged.m.signature = crypto.sign(null, Buffer.from(manifestPayload(forged.m)), other.privateKey).toString('base64');
  st = await svc(base, forged, {}, fakeGithub(forged)).check();
  assert.equal(st.verified, false); assert.match(st.error, /signature/i);
  // manifest for another version than the tag
  const mismatch = release('1.0.4'); const evilM = Object.assign({}, release('1.0.5').m);
  st = await svc(base, mismatch, {}, fakeGithub(mismatch, { manifest: evilM })).check();
  assert.equal(st.verified, false);
  // asset URL outside the repo
  st = await svc(base, r102, {}, fakeGithub(r102, { badAssetUrl: 'https://github.com/someone-else/hostpanel/releases/download/v1.0.2/manifest.json' })).check();
  assert.equal(st.verified, false); assert.match(st.error, /manifest/);
  // no key configured: can look, will not install
  const noKey = createService(Object.assign({ base, port: 8443, version: '1.0.1', publicKey: null }, fakeGithub(r102)));
  st = await noKey.check(); assert.equal(st.newer, true); assert.equal(st.verified, false); assert.match(st.error, /no release signing key/);
  assert.throws(() => noKey.startUpdate(runAsync), /no release signing key/);

  // ---------- 2. refuse a downgrade even with a valid signature ----------
  const r100 = release('1.0.0');
  await assert.rejects(() => svc(base, r100).startUpdate(runAsync), /Already up to date/);

  // ---------- 3. bad downloads leave the live install untouched ----------
  const snapshot = (b) => ['server.js', 'lib/core.js', 'public/app.js', 'package.json'].map((f) => read(b + '/' + f)).join('|') + read(b + '/node_modules/express/package.json');
  const before = snapshot(base);
  const tampered = release('1.0.6'); const badTgz = tampered.tgz + '.bad'; fs.writeFileSync(badTgz, Buffer.concat([fs.readFileSync(tampered.tgz), Buffer.from('x')]));
  await assert.rejects(() => svc(base, tampered, {}, fakeGithub(tampered, { tgzOverride: badTgz })).startUpdate(runAsync), /SHA-256 mismatch/);
  const withLink = release('1.0.7', (top) => fs.symlinkSync('/etc', top + '/lib/evil'));
  await assert.rejects(() => svc(base, withLink).startUpdate(runAsync), /symlink/);
  const missingFile = release('1.0.8', (top) => fs.rmSync(top + '/public/app.js'));
  await assert.rejects(() => svc(base, missingFile).startUpdate(runAsync), /missing public\/app.js/);
  const badVersion = release('1.0.9', (top) => w(top + '/package.json', '{"version":"9.9.9"}'));
  await assert.rejects(() => svc(base, badVersion).startUpdate(runAsync), /does not match the signed release/);
  const syntaxErr = release('1.1.0', (top) => w(top + '/lib/core.js', 'this is not javascript ((('));
  await assert.rejects(() => svc(base, syntaxErr).startUpdate(runAsync), /failed/);
  w(root + '/npm-fails', '1');
  await assert.rejects(() => svc(base, r102).startUpdate(runAsync), /npm/);
  fs.rmSync(root + '/npm-fails');
  assert.equal(snapshot(base), before, 'failed updates must not change the live install');
  assert.ok(!fs.existsSync(base + '/updates/last-result'));

  // ---------- 4. success: swap + watchdog sees a healthy panel ----------
  fs.writeFileSync(calls, ''); w(root + '/panel-healthy', '1');
  await svc(base, r102).startUpdate(runAsync);
  assert.deepEqual((await waitResult(base)).slice(1), ['ok', '1.0.2']);
  assert.match(read(base + '/server.js'), /NEW server 1.0.2/);
  assert.match(read(base + '/lib/core.js'), /NEW core/);
  assert.equal(JSON.parse(read(base + '/package.json')).version, '1.0.2');
  assert.ok(fs.existsSync(base + '/node_modules/express/package.json') && !read(base + '/node_modules/express/package.json').includes('old'));
  assert.equal(fs.statSync(base + '/server.js').mode & 0o777, 0o600, 'server.js stays private');
  assert.equal(fs.statSync(base + '/worker.js').mode & 0o077 & 0o022, 0, 'no group/world write');
  const oldDirs = fs.readdirSync(base + '/updates').filter((n) => n.startsWith('old-'));
  assert.equal(oldDirs.length, 1); assert.match(read(base + '/updates/' + oldDirs[0] + '/server.js'), /OLD server/);
  assert.equal(read(base + '/updates/' + oldDirs[0] + '/db.json.bak'), read(base + '/data/db.json'));
  assert.equal(fs.readdirSync(base + '/updates').filter((n) => /^(dl|stage)-/.test(n)).length, 0, 'downloads and staging are cleaned up');
  assert.match(read(calls), /systemd-run --no-block --collect --unit=hostpanel-update-/);
  assert.equal((read(calls).match(/systemctl restart hostpanel/g) || []).length, 1);
  assert.match(read(calls), /curl -ksf -m 3 -o \/dev\/null https:\/\/127\.0\.0\.1:8443\/login/);
  assert.equal(fs.readFileSync(base + '/data/db.json', 'utf8'), '{"admin":{"user":"x"}}\n', 'panel data is never touched');

  // ---------- 5. failure after the swap: the watchdog rolls back ----------
  base = installBase(); fs.writeFileSync(calls, ''); fs.rmSync(root + '/panel-healthy');
  const r103 = release('1.0.3');
  await svc(base, r103).startUpdate(runAsync);
  assert.deepEqual((await waitResult(base)).slice(1), ['rolled-back', '1.0.3']);
  assert.equal(snapshot(base), before.replace(/x/g, 'x'), 'rollback restores every swapped item');
  assert.match(read(base + '/server.js'), /OLD server/); assert.match(read(base + '/node_modules/express/package.json'), /old/);
  assert.equal((read(calls).match(/systemctl restart hostpanel/g) || []).length, 2, 'restarted once for the update and once after rollback');

  // ---------- 6. rollback of a half-finished swap, and a first-time item that did not exist before ----------
  base = installBase(); fs.rmSync(base + '/node_modules', { recursive: true }); // old install had no node_modules at all
  const a = svc(base, r103).makeAdapters((m) => logs.push(m), '1.0.3');
  const f = await a.download(r103.m.assetUrl); await a.validateArchive(f); await a.backup(); const stage = await a.stage(f, '1.0.3');
  await a.atomicSwitch(stage);
  assert.match(read(base + '/server.js'), /NEW server/); assert.ok(fs.existsSync(base + '/node_modules'));
  await a.rollback();
  assert.match(read(base + '/server.js'), /OLD server/); assert.ok(!fs.existsSync(base + '/node_modules'), 'items that did not exist before are removed again');
  assert.ok(!fs.existsSync(base + '/package-lock.json'));

  // ---------- 7. watchdog script is generated only from safe values ----------
  assert.throws(() => createService({ base: '/opt/hp; rm -rf /', port: 8443, version: '1.0.1' }), /Unsafe/);
  const script = read(svc(base, r103).writeWatchdog('t1', base + '/updates/old-t1', '1.0.3'));
  assert.ok(!/\$\(|`/.test(script.replace(/\$\(date[^)]*\)|\$\(\(i\+1\)\)/g, '')), 'no command substitution beyond date/arithmetic');
  assert.throws(() => svc(base, r103).writeWatchdog('t1', '/x; touch /tmp/pwned', '1.0.3'), /Unsafe/);
  assert.equal(spawnSync('sh', ['-n', base + '/updates/watchdog-t1.sh']).status, 0, 'generated script is valid sh');

  fs.rmSync(root, { recursive: true, force: true });
  console.log('GitHub release updater end-to-end tests passed');
})().catch((e) => { console.error(e); try { console.error(logs.slice(-15).join('\n')); } catch (x) {} process.exitCode = 1; });
