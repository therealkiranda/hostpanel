'use strict';
// The "install PHP x.y" task picks a package source by Ubuntu release. Run the real script against stand-in commands.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const { spawnSync } = require('child_process');
const T = fs.mkdtempSync(os.tmpdir() + '/hp-phprepo-');
process.env.HP_BASE = T + '/base'; process.env.HP_HOMES = T + '/homes';
fs.mkdirSync(T + '/base/data', { recursive: true }); fs.mkdirSync(T + '/homes');
fs.writeFileSync(T + '/base/data/db.json', JSON.stringify({ secret: 'x', admin: { user: 'a', hash: 'h' }, sites: [], dbs: [], settings: {} }));
const { PHP_REPO_SH } = require('../lib/tools');
try {
  const bin = T + '/bin'; fs.mkdirSync(bin);
  const stub = (n, body) => fs.writeFileSync(bin + '/' + n, '#!/bin/bash\necho "' + n + ' $*" >> "$HP_T_LOG"\n' + body + '\n', { mode: 0o755 });
  stub('apt-cache', 'case " $HP_T_HAVE " in *" ${2#php}"*|*" ${2%-fpm}"*) exit 0;; esac; for h in $HP_T_HAVE; do [ "$2" = "php$h-fpm" ] && exit 0; done; exit 100');
  stub('curl', 'case "$1" in -fsSI) [ "$HP_T_SURY" = 1 ] && exit 0 || exit 22;; -fsSL) touch "$3"; exit 0;; esac');
  for (const n of ['dpkg', 'apt-get', 'add-apt-repository']) stub(n, 'exit 0');
  const run = (codename, o) => {
    const dir = T + '/src-' + codename + '-' + Math.random().toString(36).slice(2, 7); fs.mkdirSync(dir);
    const rel = dir + '/os-release'; fs.writeFileSync(rel, 'ID=ubuntu\nVERSION_CODENAME=' + codename + '\n');
    const log = dir + '/calls.log'; fs.writeFileSync(log, '');
    if (o.stale) fs.writeFileSync(dir + '/ondrej-ubuntu-php-' + codename + '.sources', 'Types: deb\n');
    const r = spawnSync('bash', ['-c', PHP_REPO_SH, 'bash', o.v || '8.4'], { encoding: 'utf8', env: Object.assign({}, process.env, { PATH: bin + ':' + process.env.PATH, HP_APT_SOURCES: dir, HP_OS_RELEASE: rel, HP_T_LOG: log, HP_T_HAVE: o.have || '', HP_T_SURY: o.sury ? '1' : '0' }) });
    return { r, dir, calls: fs.readFileSync(log, 'utf8'), files: fs.readdirSync(dir) };
  };

  // Ubuntu 26.04 (the reported case): the broken PPA entry is removed, and with no source for this release nothing is added
  let x = run('resolute', { stale: true, sury: false });
  assert.equal(x.r.status, 1); assert.match(x.r.stdout, /No PHP 8\.4 package source exists for Ubuntu 'resolute'.*Nothing was changed/);
  assert.ok(!x.files.some((f) => f.startsWith('ondrej-')), 'stale ondrej entry removed so apt-get update works again'); assert.ok(!x.files.includes('sury-php.sources'));
  assert.ok(!/add-apt-repository|dpkg/.test(x.calls));
  // Ubuntu 26.04 with packages.sury.org available: signed source is added
  x = run('resolute', { stale: true, sury: true });
  assert.equal(x.r.status, 0, x.r.stdout + x.r.stderr); const src = fs.readFileSync(x.dir + '/sury-php.sources', 'utf8');
  assert.match(src, /URIs: https:\/\/packages\.sury\.org\/php\//); assert.match(src, /Suites: resolute/); assert.match(src, /Signed-By: \/usr\/share\/keyrings\/debsuryorg-archive-keyring\.gpg/);
  assert.ok(/dpkg -i \/tmp\/hp-sury-keyring\.deb/.test(x.calls) && !/add-apt-repository/.test(x.calls) && !x.files.some((f) => f.startsWith('ondrej-')));
  // the Ubuntu archive already has it (PHP 8.5 on 26.04): no extra source at all, leftover PPA still cleaned
  x = run('resolute', { stale: true, have: '8.5', v: '8.5', sury: false });
  assert.equal(x.r.status, 0); assert.match(x.r.stdout, /available from the Ubuntu repositories/); assert.ok(!x.files.includes('sury-php.sources') && !x.files.some((f) => f.startsWith('ondrej-')) && !/curl/.test(x.calls));
  // Ubuntu 24.04 / 22.04: the ondrej PPA is the right source and an existing entry is left alone
  for (const cn of ['noble', 'jammy']) {
    x = run(cn, { stale: true }); assert.equal(x.r.status, 0); assert.ok(/apt-get install -y software-properties-common/.test(x.calls) && /add-apt-repository -y ppa:ondrej\/php/.test(x.calls), cn);
    assert.ok(x.files.some((f) => f.startsWith('ondrej-')) && !x.files.includes('sury-php.sources'), cn + ' keeps the PPA');
  }
  console.log('PHP repository selection tests passed');
} catch (e) { console.error(e); process.exitCode = 1; } finally { fs.rmSync(T, { recursive: true, force: true }); }
