'use strict';
// Safety scan for .tar.gz files that root is about to extract (site restore and panel release updates).
// It lists the archive with `tar -tv` and rejects anything that could write outside the intended folder:
// absolute paths, ".." parts, hard links, device/fifo entries, wrong top-level folder, and any entry that
// lives *under* a symlink stored in the same archive. Nothing is extracted by this module.
const { spawnSync } = require('child_process');

const LINE = /^(.)[rwxsStT-]{9}\s+\S+\s+(\d+)\s+\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})? (.*)$/;

function check(file, top, opts) {
  opts = opts || {};
  const maxBytes = opts.maxBytes || 2 * 1024 * 1024 * 1024 * 1024; // effectively unlimited unless set
  const maxEntries = opts.maxEntries || 500000;
  const r = spawnSync('tar', ['--quoting-style=escape', '-tvzf', file], { encoding: 'utf8', maxBuffer: 256 * 1048576, timeout: 300000 });
  if (r.status !== 0) throw new Error('Archive cannot be read: ' + String(r.stderr || '').trim().slice(0, 200));
  const lines = r.stdout.split('\n').filter(Boolean);
  if (!lines.length) throw new Error('Archive is empty');
  if (lines.length > maxEntries) throw new Error('Archive has too many entries');
  const symlinks = [];
  let total = 0;
  const seen = [];
  for (const line of lines) {
    const m = LINE.exec(line);
    if (!m) throw new Error('Unrecognised archive entry: ' + line.slice(0, 80));
    const type = m[1], size = parseInt(m[2], 10);
    let name = m[3];
    if (type === 'l') name = name.split(' -> ')[0];
    if (type === 'h' || !['-', 'd', 'l'].includes(type)) throw new Error('Archive contains a forbidden entry type (' + type + '): ' + name.slice(0, 80));
    if (type === 'l' && !opts.allowSymlinks) throw new Error('Archive contains a symlink: ' + name.slice(0, 80));
    if (name.startsWith('/') || name.split('/').includes('..')) throw new Error('Archive entry escapes its folder: ' + name.slice(0, 80));
    const clean = name.replace(/\/+$/, '');
    if (clean !== top && !clean.startsWith(top + '/')) throw new Error('Archive entry is outside "' + top + '/": ' + name.slice(0, 80));
    if (type === 'l') symlinks.push(clean);
    total += size;
    if (total > maxBytes) throw new Error('Archive is larger than the allowed size');
    seen.push(clean);
  }
  for (const link of symlinks) {
    if (seen.some((n) => n.startsWith(link + '/'))) throw new Error('Archive writes through a symlink: ' + link.slice(0, 80));
  }
  return { entries: lines.length, bytes: total, names: seen };
}

module.exports = { check };

if (require.main === module) {
  const [, , file, top, flag] = process.argv;
  try {
    if (!file || !top) throw new Error('usage: archive-check.js <file.tar.gz> <top-folder> [--allow-symlinks]');
    const r = check(file, top, { allowSymlinks: flag === '--allow-symlinks' });
    console.log('Archive looks safe: ' + r.entries + ' entries');
  } catch (e) { console.error('ARCHIVE REJECTED: ' + e.message); process.exit(1); }
}
