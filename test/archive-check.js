'use strict';
// Builds real tar.gz files and checks that the pre-extraction scanner accepts good ones and rejects dangerous ones.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { check } = require('../lib/archive-check');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-arc-'));
const sh = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, stdio: 'pipe' });
const build = (name, setup, tarArgs) => {
  const dir = path.join(tmp, name + '-src'); fs.mkdirSync(dir, { recursive: true });
  setup(dir);
  const out = path.join(tmp, name + '.tar.gz');
  sh('tar', ['-czf', out].concat(tarArgs || ['site']), dir);
  return out;
};
const mk = (dir, rel, body) => { const f = path.join(dir, rel); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, body || 'x'); };

const good = build('good', (d) => { mk(d, 'site/public_html/index.php'); mk(d, 'site/public_html/with space/a file.txt'); });
assert.ok(check(good, 'site').entries >= 3);

const withLink = build('link', (d) => { mk(d, 'site/public_html/a'); fs.symlinkSync('/etc', path.join(d, 'site/public_html/etc-link')); });
assert.throws(() => check(withLink, 'site'), /symlink/);
assert.ok(check(withLink, 'site', { allowSymlinks: true }), 'site restore tolerates plain symlinks');

const hard = build('hard', (d) => { mk(d, 'site/a'); fs.linkSync(path.join(d, 'site/a'), path.join(d, 'site/b')); });
assert.throws(() => check(hard, 'site', { allowSymlinks: true }), /forbidden entry type/);

const wrongTop = build('top', (d) => { mk(d, 'other/a'); }, ['other']);
assert.throws(() => check(wrongTop, 'site'), /outside "site\/"/);

const dotdot = build('dotdot', (d) => { mk(d, 'site/a'); fs.mkdirSync(path.join(d, 'x')); }, ['--transform=s,^site/a,site/../../evil,', 'site']);
assert.throws(() => check(dotdot, 'site'), /escapes/);

const abs = build('abs', (d) => { mk(d, 'site/a'); }, ['-P', '--transform=s,^site/a,/tmp/evil,', 'site']);
assert.throws(() => check(abs, 'site'), /escapes|outside/);

// an entry stored *under* a symlink that is in the same archive (classic extract-through-symlink trick)
const through = path.join(tmp, 'through.tar');
{
  const d = path.join(tmp, 'through-src'); fs.mkdirSync(path.join(d, 'site'), { recursive: true });
  fs.symlinkSync('/tmp', path.join(d, 'site/lnk'));
  sh('tar', ['-cf', through, 'site'], d);
  const d2 = path.join(tmp, 'through-src2'); fs.mkdirSync(path.join(d2, 'site/lnk'), { recursive: true }); fs.writeFileSync(path.join(d2, 'site/lnk/evil'), 'x');
  sh('tar', ['-rf', through, 'site/lnk/evil'], d2);
  sh('gzip', ['-f', through]);
}
assert.throws(() => check(through + '.gz', 'site', { allowSymlinks: true }), /through a symlink/);

assert.throws(() => check(path.join(tmp, 'missing.tar.gz'), 'site'), /cannot be read/);
fs.writeFileSync(path.join(tmp, 'junk.tar.gz'), 'not a tar');
assert.throws(() => check(path.join(tmp, 'junk.tar.gz'), 'site'), /cannot be read/);
assert.throws(() => check(good, 'site', { maxBytes: 1 }), /larger than/);
fs.rmSync(tmp, { recursive: true, force: true });
console.log('archive safety scanner tests passed');
