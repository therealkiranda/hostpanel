'use strict';
// "Stable only": HostPanel never installs a beta, RC, alpha or development build of an application.
// The newest STABLE release is looked up from the official source (WordPress.org, Packagist) and pinned explicitly,
// and every version string is checked with isStable() before it is used. Lookups fail soft: when the network is down
// the installers fall back to their tool's default channel (WP-CLI and Composer both default to stable) and then
// verify the result again.
const https = require('https');

const STABLE_RE = /^\d+\.\d+(?:\.\d+)?$/;
const clean = (v) => String(v == null ? '' : v).trim().replace(/^v/i, '');
const isStable = (v) => STABLE_RE.test(clean(v));
const cmp = (a, b) => { const x = clean(a).split('.').map(Number), y = clean(b).split('.').map(Number); for (let i = 0; i < 3; i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d > 0 ? 1 : -1; } return 0; };
const newest = (list) => list.filter(isStable).map(clean).sort(cmp).pop() || null;

const HOSTS = ['api.wordpress.org', 'repo.packagist.org'];
function getJson(url, o) {
  o = o || {};
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(url); } catch (e) { return reject(new Error('Bad URL')); }
    if (u.protocol !== 'https:' || !(o.hosts || HOSTS).includes(u.hostname)) return reject(new Error('Blocked URL'));
    const req = (o.https || https).get(u, { headers: { 'User-Agent': 'HostPanel', Accept: 'application/json' }, timeout: o.timeoutMs || 6000 }, (r) => {
      if (r.statusCode !== 200) { r.resume(); return reject(new Error('HTTP ' + r.statusCode)); }
      const chunks = []; let n = 0;
      r.on('data', (c) => { n += c.length; if (n > 4 * 1048576) r.destroy(new Error('Response too large')); else chunks.push(c); });
      r.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(new Error('Bad JSON')); } });
      r.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('Timed out')));
    req.on('error', reject);
  });
}

// WordPress.org version-check: offers[] with a version for every channel; the beta/RC channel only appears when asked for.
async function latestWordPress(o) {
  const j = await ((o && o.getJson) || getJson)('https://api.wordpress.org/core/version-check/1.7/', o);
  const v = newest((j.offers || []).map((x) => x && x.version));
  return v ? { version: v, php: null } : null;
}

// Packagist metadata is "minified": each version only lists the keys that changed from the previous one.
function expandVersions(list) {
  const out = []; let prev = {};
  for (const e of list || []) { const m = Object.assign({}, prev, e); out.push(m); prev = m; }
  return out;
}
const minPhp = (req) => { const m = /(\d+\.\d+)/.exec(String(req || '')); return m ? m[1] : null; };
async function latestLaravel(o) {
  const j = await ((o && o.getJson) || getJson)('https://repo.packagist.org/p2/laravel/laravel.json', o);
  const all = expandVersions(j && j.packages && j.packages['laravel/laravel']).filter((x) => isStable(x.version));
  if (!all.length) return null;
  const best = newest(all.map((x) => x.version));
  const hit = all.find((x) => clean(x.version) === best);
  return { version: best, php: minPhp(hit && hit.require && hit.require.php) };
}
const phpAtLeast = (have, need) => { if (!need) return true; const a = String(have).split('.').map(Number), b = String(need).split('.').map(Number); return a[0] > b[0] || (a[0] === b[0] && (a[1] || 0) >= (b[1] || 0)); };

const cache = {};
async function latest(app, o) {
  if (process.env.HP_NO_NETWORK === '1' && !(o && o.getJson)) return null; // tests
  const hit = cache[app];
  if (hit && Date.now() - hit.t < 6 * 3600 * 1000 && !(o && o.noCache)) return hit.v;
  let v = null;
  try { v = app === 'wordpress' ? await latestWordPress(o) : app === 'laravel' ? await latestLaravel(o) : null; } catch (e) { v = null; }
  if (v) cache[app] = { t: Date.now(), v };
  return v;
}
const peek = (app) => (cache[app] && cache[app].v) || null;

module.exports = { isStable, clean, newest, latest, peek, latestWordPress, latestLaravel, expandVersions, phpAtLeast, minPhp, getJson };
