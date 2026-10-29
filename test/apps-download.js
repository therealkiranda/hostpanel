'use strict';
// Checksum-pinned downloads (used for WP-CLI): a wrong, oversized, redirected-to-nowhere or truncated file is never kept.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { fetchVerified, sha256File } = require('../lib/apps/download');
const { ensureWpCli, WPCLI } = require('../lib/apps/wpcli');

const T = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-dl-'));
const body = Buffer.from('<?php echo "pretend phar";\n' + 'x'.repeat(5000));
const good = crypto.createHash('sha256').update(body).digest('hex');
let hits = 0;
const server = http.createServer((req, res) => {
  hits++;
  if (req.url === '/file') { res.writeHead(200); return res.end(body); }
  if (req.url === '/evil') { res.writeHead(200); return res.end('tampered'); }
  if (req.url === '/redir') { res.writeHead(302, { Location: '/file' }); return res.end(); }
  if (req.url === '/loop') { res.writeHead(302, { Location: '/loop' }); return res.end(); }
  if (req.url === '/big') { res.writeHead(200); res.write(Buffer.alloc(2 * 1048576)); return res.end(Buffer.alloc(2 * 1048576)); }
  if (req.url === '/slow') { res.writeHead(200); res.write('a'); return; }
  res.writeHead(404); res.end('no');
});
server.listen(0, '127.0.0.1', async () => {
  const base = 'http://127.0.0.1:' + server.address().port, client = http, leftovers = () => fs.readdirSync(T).filter((n) => n.includes('.part-'));
  try {
    const dest = path.join(T, 'out.bin');
    let r = await fetchVerified(base + '/file', good, dest, { client }); assert.equal(r.sha256, good); assert.ok(fs.readFileSync(dest).equals(body));
    fs.unlinkSync(dest);
    r = await fetchVerified(base + '/redir', good, dest, { client }); assert.ok(fs.readFileSync(dest).equals(body), 'redirects are followed'); fs.unlinkSync(dest);
    fs.writeFileSync(dest, 'precious'); // an existing file is only replaced when the NEW one verified
    await assert.rejects(() => fetchVerified(base + '/evil', good, dest, { client }), /Checksum mismatch/); assert.equal(fs.readFileSync(dest, 'utf8'), 'precious'); assert.deepEqual(leftovers(), []);
    await assert.rejects(() => fetchVerified(base + '/missing', good, path.join(T, 'x'), { client }), /HTTP 404/);
    await assert.rejects(() => fetchVerified(base + '/loop', good, path.join(T, 'x'), { client, maxRedirects: 3 }), /Too many redirects/);
    await assert.rejects(() => fetchVerified(base + '/big', good, path.join(T, 'x'), { client, maxBytes: 1048576 }), /larger than the allowed size/); assert.deepEqual(leftovers(), [], 'partial files are removed');
    await assert.rejects(() => fetchVerified(base + '/slow', good, path.join(T, 'x'), { client, timeoutMs: 300 }), /timed out|socket hang up|aborted/); assert.deepEqual(leftovers(), []);
    await assert.rejects(() => fetchVerified(base + '/file', 'not-a-hash', dest, { client }), /SHA-256/);
    await assert.rejects(() => fetchVerified('http://example.com/x', good, dest, {}), /HTTPS/, 'plain http is refused in production');
    await assert.rejects(() => fetchVerified('ftp://example.com/x', good, dest, {}), /HTTPS/);

    /* ---- WP-CLI: pinned values look right; verified file is reused; a tampered copy is replaced ---- */
    assert.match(WPCLI.sha256, /^[a-f0-9]{64}$/); assert.match(WPCLI.url, /^https:\/\/github\.com\/wp-cli\/wp-cli\/releases\/download\/v[\d.]+\/wp-cli-[\d.]+\.phar$/); assert.ok(WPCLI.url.includes(WPCLI.version));
    const pin = { version: 't', url: base + '/file', sha256: good };
    hits = 0; const logs = [];
    let f = await ensureWpCli(T, (m) => logs.push(m), { pin, fetch: { client } });
    assert.equal(f, path.join(T, 'bin', 'wp-cli.phar')); assert.equal(sha256File(f), good); assert.equal(fs.statSync(f).mode & 0o777, 0o644); assert.equal(fs.statSync(path.join(T, 'bin')).mode & 0o777, 0o755); assert.equal(hits, 1); assert.ok(logs.length === 1);
    f = await ensureWpCli(T, null, { pin, fetch: { client } }); assert.equal(hits, 1, 'a verified copy is not downloaded again');
    fs.writeFileSync(f, 'tampered by someone'); await ensureWpCli(T, null, { pin, fetch: { client } }); assert.equal(sha256File(f), good); assert.equal(hits, 2, 'a modified copy is replaced');
    const bad = { version: 't', url: base + '/evil', sha256: good };
    fs.unlinkSync(f); await assert.rejects(() => ensureWpCli(T, null, { pin: bad, fetch: { client } }), /Checksum mismatch/); assert.ok(!fs.existsSync(f), 'no unverified phar is ever left in place');
    console.log('app installer download tests passed');
  } catch (e) { console.error(e); process.exitCode = 1; } finally { server.close(); server.closeAllConnections && server.closeAllConnections(); fs.rmSync(T, { recursive: true, force: true }); }
});
