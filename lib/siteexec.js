'use strict';
// Run things AS a website's Linux user (never as root): the file-manager worker, and arbitrary commands
// for the app installer. Shared by server.js (file manager) and lib/apps (installer) so both use one hardened path.
const path = require('path');
const { spawn } = require('child_process');
const c = require('./core');
const { IS_ROOT, sh } = c;

const WORKER = path.join(__dirname, '..', 'worker.js');
const idCache = {};

// uid/gid of the site user (only looked up when the panel runs as root; unprivileged test runs use the current user).
function idsOf(user) {
  if (!idCache[user]) idCache[user] = { uid: parseInt(sh('id', ['-u', user]), 10), gid: parseInt(sh('id', ['-g', user]), 10) };
  return idCache[user];
}
function fmOpts(s, extraEnv) {
  const o = { cwd: s.home, env: Object.assign({ PATH: '/usr/bin:/bin', HOME: s.home, LANG: 'C.UTF-8' }, extraEnv || {}) };
  if (IS_ROOT) { const ids = idsOf(s.user); o.uid = ids.uid; o.gid = ids.gid; }
  return o;
}

// Runs worker.js as the site user WITHOUT blocking the panel (a big unzip or delete used to freeze every request).
const worker = (s, op, rel, arg, input) => new Promise((resolve, reject) => {
  const p = spawn(process.execPath, [WORKER, op, s.home, rel || '/', arg || ''], Object.assign({ stdio: ['pipe', 'pipe', 'pipe'] }, fmOpts(s)));
  const out = [], err = []; let size = 0, tooBig = false;
  const timer = setTimeout(() => p.kill('SIGKILL'), 300000);
  p.stdout.on('data', (x) => { size += x.length; if (size > 16 * 1048576) { tooBig = true; p.kill('SIGKILL'); } else out.push(x); });
  p.stderr.on('data', (x) => { if (err.length < 50) err.push(x); });
  p.stdin.on('error', () => {});
  p.on('error', (e) => { clearTimeout(timer); reject(e); });
  p.on('close', (code) => {
    clearTimeout(timer);
    if (code === 0 && !tooBig) return resolve(Buffer.concat(out).toString('utf8'));
    reject(new Error(tooBig ? 'Output too large' : (Buffer.concat(err).toString('utf8').trim().slice(0, 800) || 'File operation failed')));
  });
  p.stdin.end(input === undefined ? '' : input);
});

// Runs a command as the site user and streams its output line by line to opts.onLine.
// Secrets must go through opts.input (stdin) or opts.env, never through args: args are visible in `ps`.
// Resolves with the tail of the output; rejects (with that tail in the message) on a non-zero exit or timeout.
function runAs(s, cmd, args, opts) {
  opts = opts || {};
  return new Promise((resolve, reject) => {
    const o = fmOpts(s, opts.env);
    if (opts.cwd) o.cwd = opts.cwd;
    let p;
    try { p = spawn(cmd, args, Object.assign({ stdio: ['pipe', 'pipe', 'pipe'] }, o)); } catch (e) { return reject(e); }
    let tail = '', partial = '', done = false;
    const feed = (chunk) => {
      const text = chunk.toString('utf8');
      tail = (tail + text).slice(-4000);
      if (!opts.onLine) return;
      partial += text;
      const lines = partial.split('\n'); partial = lines.pop();
      lines.forEach((l) => { if (l.trim()) opts.onLine(l.replace(/\r/g, '').slice(0, 500)); });
    };
    const timer = setTimeout(() => { try { p.kill('SIGKILL'); } catch (e) {} }, opts.timeoutMs || 600000);
    const finish = (fn, v) => { if (done) return; done = true; clearTimeout(timer); if (opts.onLine && partial.trim()) opts.onLine(partial.slice(0, 500)); fn(v); };
    p.stdout.on('data', feed); p.stderr.on('data', feed);
    p.stdin.on('error', () => {});
    p.on('error', (e) => finish(reject, e));
    p.on('close', (code, sig) => {
      if (code === 0) return finish(resolve, tail);
      finish(reject, new Error((sig ? 'Killed (' + sig + ', timed out?)' : 'Exit code ' + code) + (tail.trim() ? ': ' + tail.trim().split('\n').slice(-6).join(' | ').slice(0, 600) : '')));
    });
    p.stdin.end(opts.input === undefined ? '' : opts.input);
  });
}

module.exports = { WORKER, fmOpts, worker, runAs };
