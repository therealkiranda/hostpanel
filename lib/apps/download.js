'use strict';
// Download a file over HTTPS and refuse it unless its SHA-256 matches a value we already trust (pinned in the code).
// Redirects are followed (GitHub release assets redirect to a CDN) but only over HTTPS, the size is capped, and the
// file only appears at its final path after the hash matched (written to a temp name, then renamed).
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');

function fetchVerified(url, sha256, dest, opts) {
  opts = opts || {};
  const client = opts.client || https;                       // tests inject a plain-HTTP client for a local server
  const maxBytes = opts.maxBytes || 32 * 1048576, maxRedirects = opts.maxRedirects === undefined ? 5 : opts.maxRedirects;
  const want = String(sha256 || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(want)) return Promise.reject(new Error('A SHA-256 checksum is required'));
  const tmp = dest + '.part-' + crypto.randomBytes(4).toString('hex');
  const get = (u, left) => new Promise((resolve, reject) => {
    let parsed; try { parsed = new URL(u); } catch (e) { return reject(new Error('Invalid download URL')); }
    if (parsed.protocol !== 'https:' && !opts.client) return reject(new Error('Downloads must use HTTPS'));
    const req = client.get(u, { timeout: opts.timeoutMs || 60000, headers: { 'User-Agent': 'HostPanel' } }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        if (left <= 0) return reject(new Error('Too many redirects'));
        return resolve(get(new URL(res.headers.location, u).toString(), left - 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error('Download failed: HTTP ' + res.statusCode)); }
      const hash = crypto.createHash('sha256'); let size = 0;
      const out = fs.createWriteStream(tmp, { mode: 0o644, flags: 'wx' });
      res.on('data', (chunk) => { size += chunk.length; if (size > maxBytes) { res.destroy(new Error('Download is larger than the allowed size')); } else hash.update(chunk); });
      res.on('error', (e) => { out.destroy(); reject(e); });
      res.pipe(out);
      out.on('error', reject);
      out.on('finish', () => resolve({ sha256: hash.digest('hex'), size }));
    });
    req.on('timeout', () => req.destroy(new Error('Download timed out')));
    req.on('error', reject);
  });
  return get(url, maxRedirects).then((r) => {
    if (r.sha256 !== want) throw new Error('Checksum mismatch: the download is not the file HostPanel expects, so it was discarded');
    fs.renameSync(tmp, dest);
    return { path: dest, size: r.size, sha256: r.sha256 };
  }).catch((e) => { try { fs.unlinkSync(tmp); } catch (x) {} throw e; });
}

const sha256File = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

module.exports = { fetchVerified, sha256File };
