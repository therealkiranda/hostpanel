'use strict';
// SSH login banner: installs an executable update-motd script that prints /etc/hostpanel/motd, keeps user edits,
// is idempotent, and the optional "quiet" mode is reversible and limited to the noisy stock parts.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const T = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-motd-'));
Object.assign(process.env, { HP_MOTD_D: T + '/update-motd.d', HP_MOTD_CONF: T + '/etc/hostpanel/motd', HP_MOTD_STATE: T + '/etc/hostpanel/motd-disabled' });
const m = require('../lib/motd');

// the banner: aligned, and containing the requested text
const lines = m.BANNER.split('\n');
assert.equal(lines[0].length, 56); assert.equal(lines[1].length, 56); assert.equal(lines[2], lines[0]); assert.match(lines[1], /^### +Welcome to Hostpanel +###$/);
assert.ok(m.BANNER.includes('* Website:         https://www.khadkakiran.com.np\n* Documentation:   coming soon\n'));

assert.match(m.install(), /installed/);
const script = T + '/update-motd.d/00-hostpanel';
assert.equal(fs.statSync(script).mode & 0o777, 0o755); assert.equal(fs.readFileSync(T + '/etc/hostpanel/motd', 'utf8'), m.BANNER);
let r = spawnSync(script, { encoding: 'utf8' }); assert.equal(r.status, 0); assert.equal(r.stdout, m.BANNER);
assert.equal(spawnSync('sh', ['-n', script]).status, 0);
// run-parts is what pam_motd uses on Ubuntu
if (spawnSync('which', ['run-parts']).status === 0) { r = spawnSync('run-parts', [T + '/update-motd.d'], { encoding: 'utf8' }); assert.equal(r.stdout, m.BANNER, 'run-parts output'); }
// a user-edited text survives re-install (upgrade), and a missing text file never breaks login
fs.writeFileSync(T + '/etc/hostpanel/motd', 'my own banner\n'); assert.match(m.install(), /kept your edited/);
assert.equal(spawnSync(script, { encoding: 'utf8' }).stdout, 'my own banner\n');
fs.unlinkSync(T + '/etc/hostpanel/motd'); r = spawnSync(script, { encoding: 'utf8' }); assert.equal(r.status, 0); assert.equal(r.stdout, '');
m.install(); m.install(); assert.deepEqual(fs.readdirSync(T + '/update-motd.d'), ['00-hostpanel']);

// quiet / default
for (const n of m.STOCK_NOISE.concat(['90-updates-available', '98-reboot-required', '98-fsck-at-reboot'])) fs.writeFileSync(T + '/update-motd.d/' + n, '#!/bin/sh\necho ' + n + '\n', { mode: 0o755 });
fs.writeFileSync(T + '/update-motd.d/10-help-text', '#!/bin/sh\necho help\n', { mode: 0o755 });
assert.match(m.quiet(), /Hid the standard Ubuntu greeting parts/);
const x = (n) => !!(fs.statSync(T + '/update-motd.d/' + n).mode & 0o111);
assert.ok(m.STOCK_NOISE.every((n) => !x(n)), 'noisy parts hidden'); assert.ok(x('90-updates-available') && x('98-reboot-required') && x('98-fsck-at-reboot') && x('00-hostpanel'), 'security notices and our banner stay');
m.quiet(); assert.match(m.status(), /Hidden Ubuntu parts: 10-help-text/);
assert.match(m.restoreDefault(), /Restored 7/); assert.ok(m.STOCK_NOISE.every(x)); assert.match(m.status(), /Hidden Ubuntu parts: none/);
fs.writeFileSync(T + '/etc/hostpanel/motd-disabled', JSON.stringify(['00-hostpanel', '../../etc/passwd'])); m.restoreDefault(); // a tampered state file cannot make us touch other files
assert.equal(fs.statSync(script).mode & 0o777, 0o755);
assert.match(m.remove(), /removed/); assert.ok(!fs.existsSync(script)); m.remove();

// the CLI wiring (root only: hostpanel-cli refuses to run otherwise)
if (process.getuid && process.getuid() === 0) {
  const cli = (...a) => spawnSync(process.execPath, [path.join(__dirname, '..', 'cli.js'), ...a], { encoding: 'utf8', env: Object.assign({}, process.env, { NODE_PATH: path.join(__dirname, 'shims') }) });
  r = cli('motd', 'install'); assert.equal(r.status, 0, r.stderr); assert.ok(fs.existsSync(script));
  assert.match(cli('motd', 'status').stdout, /Banner: installed/); assert.notEqual(cli('motd', 'bogus').status, 0);
}
fs.rmSync(T, { recursive: true, force: true });
console.log('SSH login banner tests passed');
