'use strict';
// HostPanel release updater: checks GitHub Releases of therealkiranda/hostpanel and installs a newer version.
//
// Trust model: the release must contain manifest.json {version, assetUrl, sha256, signature}. The signature is an
// Ed25519 signature made offline with the maintainer's private key (GitHub secret HOSTPANEL_SIGNING_KEY) and is checked
// against lib/release-key.pub, which ships with the panel. A hacked GitHub account or tampered download therefore
// cannot push code to servers. Without lib/release-key.pub the panel can still *check* for updates but never installs.
//
// Install steps (all in lib/updater.js order): download -> sha256 -> archive scan -> back up -> stage + npm ci ->
// swap items -> restart through a detached systemd unit that rolls back automatically if the new panel does not answer.
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const { verifyManifest, applyVerifiedUpdate, isNewer } = require('./updater');
const archive = require('./archive-check');

const REPO = 'therealkiranda/hostpanel';
const API_URL = 'https://api.github.com/repos/' + REPO + '/releases/latest';
const DL_PREFIX = 'https://github.com/' + REPO + '/releases/download/';
const ALLOWED_HOSTS = ['github.com', 'api.github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com'];
const ITEMS = ['server.js', 'cli.js', 'worker.js', 'package.json', 'package-lock.json', 'lib', 'public', 'node_modules'];
const REQUIRED = ['server.js', 'cli.js', 'worker.js', 'package.json', 'package-lock.json', 'lib/core.js', 'lib/sites.js', 'public/app.js'];
const MAX_DOWNLOAD = 100 * 1024 * 1024;

/* ---------- network (only HTTPS to GitHub hosts, redirects re-checked) ---------- */
function checkUrl(u, hosts) {
  let x; try { x = new URL(u); } catch (e) { throw new Error('Invalid URL'); }
  if (x.protocol !== 'https:' || x.username || x.password || (x.port && x.port !== '443') || !(hosts || ALLOWED_HOSTS).includes(x.hostname)) throw new Error('Blocked URL (not a GitHub release host): ' + x.hostname);
  return x;
}
function request(url, o, depth) {
  depth = depth || 0;
  return new Promise((resolve, reject) => {
    let x; try { x = checkUrl(url, o.hosts); } catch (e) { return reject(e); }
    const req = (o.https || https).get(x, { headers: { 'User-Agent': 'HostPanel-updater', Accept: o.accept || '*/*' }, timeout: 20000 }, (r) => {
      if ([301, 302, 303, 307, 308].includes(r.statusCode) && r.headers.location) {
        r.resume();
        if (depth >= 5) return reject(new Error('Too many redirects'));
        return resolve(request(new URL(r.headers.location, x).toString(), o, depth + 1));
      }
      resolve(r);
    });
    req.on('timeout', () => req.destroy(new Error('GitHub request timed out')));
    req.on('error', reject);
  });
}
async function fetchBuffer(url, o) {
  o = o || {};
  const r = await request(url, o);
  if (r.statusCode !== 200) { r.resume(); const e = new Error(r.statusCode === 404 ? 'Not found on GitHub (no release published yet?)' : 'GitHub answered HTTP ' + r.statusCode); e.status = r.statusCode; throw e; }
  const max = o.maxBytes || 1048576, chunks = []; let n = 0;
  for await (const c of r) { n += c.length; if (n > max) { r.destroy(); throw new Error('Response too large'); } chunks.push(c); }
  return Buffer.concat(chunks);
}
async function fetchToFile(url, dest, maxBytes, o) {
  const r = await request(url, o || {});
  if (r.statusCode !== 200) { r.resume(); throw new Error('Download failed: HTTP ' + r.statusCode); }
  const ws = fs.createWriteStream(dest, { flags: 'wx', mode: 0o600 });
  let n = 0;
  await new Promise((resolve, reject) => {
    r.on('data', (c) => { n += c.length; if (n > (maxBytes || MAX_DOWNLOAD)) { r.destroy(new Error('Download is larger than allowed')); } });
    r.on('error', (e) => { ws.destroy(); reject(e); });
    ws.on('error', reject); ws.on('finish', resolve);
    r.pipe(ws);
  });
}

/* ---------- helpers ---------- */
function loadKey(file) {
  try {
    const pem = fs.readFileSync(file, 'utf8');
    if (!/BEGIN PUBLIC KEY/.test(pem)) return null;
    const k = crypto.createPublicKey(pem);
    return k.asymmetricKeyType === 'ed25519' ? k : null;
  } catch (e) { return null; }
}
const exists = (p) => { try { fs.lstatSync(p); return true; } catch (e) { return false; } };
const stampNow = () => new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14) + crypto.randomBytes(2).toString('hex');
function sha256File(f) {
  return new Promise((resolve, reject) => { const h = crypto.createHash('sha256'); fs.createReadStream(f).on('data', (c) => h.update(c)).on('end', () => resolve(h.digest('hex'))).on('error', reject); });
}
function exec(cmd, args, o, log) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, Object.assign({ stdio: ['ignore', 'pipe', 'pipe'] }, o || {}));
    let out = '';
    const add = (b) => { out += b; if (out.length > 20000) out = out.slice(-10000); };
    p.stdout.on('data', add); p.stderr.on('data', add);
    const t = setTimeout(() => p.kill('SIGKILL'), (o && o.killAfter) || 300000);
    p.on('error', (e) => { clearTimeout(t); reject(e); });
    p.on('close', (code) => { clearTimeout(t); if (log && out.trim()) log(out.trim().split('\n').slice(-6).join('\n')); code === 0 ? resolve(out) : reject(new Error(cmd + ' failed (exit ' + code + '): ' + out.trim().slice(-300))); });
  });
}

/* ---------- the service ---------- */
function createService(o) {
  const BASE = o.base, PORT = o.port, VERSION = o.version, UNIT = o.unit || 'hostpanel';
  const UPD = BASE + '/updates';
  const HEALTH_SECONDS = Number.isInteger(o.healthSeconds) ? o.healthSeconds : 45, RESTART_DELAY = Number.isInteger(o.restartDelay) ? o.restartDelay : 2; // tests shorten these
  if (!/^\/[A-Za-z0-9_./-]+$/.test(BASE)) throw new Error('Unsafe base path');
  const publicKey = o.publicKey !== undefined ? o.publicKey : loadKey(path.join(__dirname, 'release-key.pub'));
  const getBuf = o.fetchBuffer || fetchBuffer, getFile = o.fetchToFile || fetchToFile;
  let last = null;

  async function check() {
    let rel;
    try { rel = JSON.parse((await getBuf(API_URL, { accept: 'application/vnd.github+json', maxBytes: 2097152 })).toString('utf8')); }
    catch (e) { last = { error: String(e.message || e), checkedAt: Date.now(), current: VERSION }; return last; }
    const tag = String(rel.tag_name || ''), m = /^v(\d+\.\d+\.\d+)$/.exec(tag);
    if (!m) { last = { error: 'Latest GitHub release has an unexpected tag: ' + tag.slice(0, 30), checkedAt: Date.now(), current: VERSION }; return last; }
    const res = { current: VERSION, latest: m[1], newer: isNewer(m[1], VERSION), checkedAt: Date.now(), keyConfigured: !!publicKey, verified: false, notes: String(rel.name || '').slice(0, 120) };
    if (!res.newer) { last = res; return res; }
    if (!publicKey) { res.error = 'A newer release exists, but this panel has no release signing key (lib/release-key.pub), so it will not install it.'; last = res; return res; }
    try {
      const asset = (rel.assets || []).find((a) => a && a.name === 'manifest.json');
      if (!asset || typeof asset.browser_download_url !== 'string' || !asset.browser_download_url.startsWith(DL_PREFIX)) throw new Error('The release has no signed manifest.json');
      const manifest = JSON.parse((await getBuf(asset.browser_download_url, { maxBytes: 16384 })).toString('utf8'));
      const v = verifyManifest(manifest, publicKey);
      if (v.version !== res.latest) throw new Error('Manifest version does not match the release tag');
      res.verified = true; res.manifest = manifest;
    } catch (e) { res.error = 'Release signature/manifest check failed: ' + String(e.message || e); }
    last = res; return res;
  }

  function lastResult() {
    try { const [t, status, ver] = fs.readFileSync(UPD + '/last-result', 'utf8').trim().split('|'); return { time: t, status, version: ver }; } catch (e) { return null; }
  }

  function writeWatchdog(stamp, oldDir, ver) {
    const safe = (s) => { if (!/^\/[A-Za-z0-9_./-]+$/.test(s)) throw new Error('Unsafe path for watchdog'); return s; };
    if (!/^\d{1,5}$/.test(String(PORT)) || !/^[a-z0-9_.-]+$/.test(UNIT)) throw new Error('Unsafe port or unit name');
    const script = [
      '#!/bin/sh', '# Generated by HostPanel update ' + stamp + '. Restarts the panel and rolls back if it does not answer.',
      'BASE=' + safe(BASE), 'OLD=' + safe(oldDir), 'RES=' + safe(UPD) + '/last-result', 'PORT=' + PORT, 'ITEMS="' + ITEMS.join(' ') + '"',
      'NEWV=' + (/^\d+\.\d+\.\d+$/.test(String(ver)) ? ver : 'unknown'),
      'sleep ' + RESTART_DELAY, 'systemctl restart ' + UNIT,
      'i=0', 'while [ "$i" -lt ' + HEALTH_SECONDS + ' ]; do',
      '  if curl -ksf -m 3 -o /dev/null "https://127.0.0.1:$PORT/login"; then echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)|ok|$NEWV" > "$RES"; exit 0; fi',
      '  i=$((i+1)); sleep 1', 'done',
      'for it in $ITEMS; do',
      '  if [ -e "$OLD/$it" ]; then rm -rf "$BASE/$it"; mv "$OLD/$it" "$BASE/$it"',
      '  elif [ -e "$OLD/.absent-$it" ]; then rm -rf "$BASE/$it"; fi',
      'done',
      'systemctl restart ' + UNIT,
      'echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)|rolled-back|$NEWV" > "$RES"', ''
    ].join('\n');
    const f = UPD + '/watchdog-' + stamp + '.sh';
    fs.writeFileSync(f, script, { mode: 0o700 });
    return f;
  }

  function makeAdapters(log, version) {
    const stamp = stampNow(), oldDir = UPD + '/old-' + stamp, stageDir = UPD + '/stage-' + stamp;
    let swapped = false; // true while the old files live only in oldDir
    const restoreItems = () => {
      for (const it of ITEMS) {
        const live = BASE + '/' + it, old = oldDir + '/' + it;
        if (exists(old)) { fs.rmSync(live, { recursive: true, force: true }); fs.renameSync(old, live); }
        else if (exists(oldDir + '/.absent-' + it)) fs.rmSync(live, { recursive: true, force: true });
      }
    };
    return {
      async download(url) {
        fs.mkdirSync(UPD, { recursive: true, mode: 0o700 });
        const f = UPD + '/dl-' + stamp + '.tar.gz';
        log('Downloading ' + url); await getFile(url, f, MAX_DOWNLOAD); return f;
      },
      async sha256(f) { return sha256File(f); },
      async validateArchive(f) {
        const r = archive.check(f, 'hostpanel', { maxBytes: 250 * 1024 * 1024, maxEntries: 20000 });
        for (const need of REQUIRED) if (!r.names.includes('hostpanel/' + need)) throw new Error('Release archive is missing ' + need);
        log('Archive scan passed (' + r.entries + ' entries, no links or unsafe paths)');
      },
      async backup() {
        fs.mkdirSync(oldDir, { recursive: true, mode: 0o700 });
        try { fs.copyFileSync(BASE + '/data/db.json', oldDir + '/db.json.bak'); fs.chmodSync(oldDir + '/db.json.bak', 0o600); } catch (e) {}
        log('Previous version will be kept in ' + oldDir); return oldDir;
      },
      async stage(f, ver) {
        fs.mkdirSync(stageDir, { recursive: true, mode: 0o700 });
        await exec('tar', ['-xzf', f, '-C', stageDir, '--strip-components=1', '--no-same-owner', '--no-same-permissions'], {}, log);
        const pkg = JSON.parse(fs.readFileSync(stageDir + '/package.json', 'utf8'));
        if (pkg.version !== ver) throw new Error('Package version ' + pkg.version + ' does not match the signed release ' + ver);
        const libJs = (dir) => fs.readdirSync(stageDir + '/' + dir, { withFileTypes: true }).reduce((acc, e) => acc.concat(e.isDirectory() ? libJs(dir + '/' + e.name) : (e.name.endsWith('.js') ? [dir + '/' + e.name] : [])), []);
        for (const js of ['server.js', 'cli.js', 'worker.js'].concat(libJs('lib'))) { // every .js under lib/, including lib/routes and lib/apps
          await exec(process.execPath, ['--check', stageDir + '/' + js], {}, null);
        }
        log('Installing exact locked dependencies (npm ci, install scripts disabled)');
        await exec('npm', ['ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', '--cache', stageDir + '/.npm-cache'], { cwd: stageDir, killAfter: 600000, env: { PATH: process.env.PATH, HOME: stageDir } }, log);
        if (!exists(stageDir + '/node_modules/express/package.json')) throw new Error('Dependencies were not installed');
        await exec('chmod', ['-R', 'u+rwX,go+rX,go-w', stageDir], {}, null);
        fs.chmodSync(stageDir + '/server.js', 0o600); fs.chmodSync(stageDir + '/cli.js', 0o600);
        return stageDir;
      },
      async atomicSwitch(stage) {
        swapped = true;
        for (const it of ITEMS) {
          const live = BASE + '/' + it, fresh = stage + '/' + it;
          if (!exists(fresh)) continue;
          if (exists(live)) fs.renameSync(live, oldDir + '/' + it); else fs.writeFileSync(oldDir + '/.absent-' + it, '');
          fs.renameSync(fresh, live);
        }
        log('New files are in place');
      },
      async healthCheck(ver) {
        // The panel cannot test itself while it is being replaced, so a separate systemd unit restarts it and
        // watches it for 45 seconds (default), rolling back by itself if it never answers.
        const script = writeWatchdog(stamp, oldDir, ver);
        const r = spawnSync('systemd-run', ['--no-block', '--collect', '--unit=hostpanel-update-' + stamp, '/bin/sh', script], { encoding: 'utf8', timeout: 15000 });
        if (r.error || r.status !== 0) throw new Error('Could not start the restart watchdog: ' + String((r.error && r.error.message) || r.stderr || '').slice(0, 200));
        log('Restarting HostPanel on version ' + ver + '. If it does not answer within ' + HEALTH_SECONDS + ' seconds it is rolled back automatically. Reload this page in a minute.');
        return true;
      },
      async rollback() { restoreItems(); swapped = false; log('Rolled back to the previous version'); },
      async cleanup({ artifact, staged, backup }) {
        // a backup folder is only worth keeping when it holds the previous version of a successful swap
        if (!swapped && backup && String(backup).startsWith(UPD + '/old-')) { try { fs.rmSync(backup, { recursive: true, force: true }); } catch (e) {} }
        for (const p of [artifact, staged, stageDir]) if (p) { try { fs.rmSync(p, { recursive: true, force: true }); } catch (e) {} }
        try {
          const olds = fs.readdirSync(UPD).filter((n) => /^old-\d+/.test(n)).sort();
          olds.slice(0, Math.max(0, olds.length - 2)).forEach((n) => fs.rmSync(UPD + '/' + n, { recursive: true, force: true }));
          fs.readdirSync(UPD).filter((n) => /^watchdog-.*\.sh$/.test(n)).sort().slice(0, -2).forEach((n) => fs.rmSync(UPD + '/' + n, { force: true }));
        } catch (e) {}
      }
    };
  }

  // Starts the update as a background job (see Tasks page). `runAsync` is core.runAsync.
  function startUpdate(runAsync) {
    if (!publicKey) throw new Error('This panel has no release signing key (lib/release-key.pub), so it cannot install updates.');
    if (o.checkDisk) o.checkDisk();
    return runAsync('Update HostPanel from GitHub', async (log) => {
      log('Checking GitHub release...');
      const st = await check();
      if (st.error) throw new Error(st.error);
      if (!st.newer || !st.verified) throw new Error('Already up to date (' + VERSION + ')');
      log('Verified signed release ' + st.latest);
      await applyVerifiedUpdate(st.manifest, publicKey, makeAdapters(log, st.latest), { currentVersion: VERSION });
    });
  }

  return { check, startUpdate, lastResult, getLast: () => last, hasKey: () => !!publicKey, makeAdapters, writeWatchdog };
}

module.exports = { createService, checkUrl, loadKey, ITEMS, REPO, API_URL, ALLOWED_HOSTS };
