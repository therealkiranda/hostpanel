'use strict';
// File-manager worker. Always executed AS the site's Linux user, never as root.
// Usage: worker.js <op> <home> <relative-path> [arg]
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
process.umask(0o027); // new files 640, new dirs 750 (group www-data can read, other sites cannot)
const [, , op, home, rel0, arg] = process.argv;
const fail = (m) => { process.stderr.write(String(m) + '\n'); process.exit(1); };
const out = (o) => process.stdout.write(JSON.stringify(o));
if (process.getuid() === 0) fail('Refusing to run as root');
try { if (process.getgroups().includes(0)) fail('Refusing to run with root group'); } catch (e) {}
if (!home || !path.isAbsolute(home)) fail('Bad home');
let realHome;
try { realHome = fs.realpathSync(home); } catch (e) { fail('Home not found'); }

// Lexical check first, then a realpath check on the deepest existing parent so a symlink inside the
// site cannot point the file manager at another place (defence in depth; filesystem permissions still apply).
const inside = (p) => p === realHome || p.startsWith(realHome + '/');
const res = (rel, followFinal) => {
  const full = path.resolve(home, '.' + path.posix.normalize('/' + String(rel || '')));
  if (full !== home && !full.startsWith(home + '/')) fail('Path outside home');
  let probe = followFinal ? full : path.dirname(full);
  for (;;) {
    try { const rp = fs.realpathSync(probe); if (!inside(rp)) fail('Path escapes the site folder (symlink)'); break; }
    catch (e) { if (e.code !== 'ENOENT' && e.code !== 'ENOTDIR') fail(e.message); const up = path.dirname(probe); if (up === probe) break; probe = up; }
  }
  return full;
};
const MAXREAD = 1024 * 1024;
const full = res(rel0, op !== 'rm' && op !== 'rename');
const NOFOLLOW = fs.constants.O_NOFOLLOW || 0;
try {
  switch (op) {
    case 'ls': {
      if (!fs.statSync(full).isDirectory()) fail('Not a directory');
      const items = fs.readdirSync(full, { withFileTypes: true }).slice(0, 3000).map((e) => {
        let s; try { s = fs.lstatSync(path.join(full, e.name)); } catch (x) { return null; }
        return { n: e.name, t: s.isDirectory() ? 'd' : (s.isSymbolicLink() ? 'l' : 'f'), s: s.size, m: Math.floor(s.mtimeMs / 1000), p: (s.mode & 0o777).toString(8) };
      }).filter(Boolean);
      out(items); break;
    }
    case 'stat': { const s = fs.statSync(full); out({ t: s.isDirectory() ? 'd' : (s.isFile() ? 'f' : 'o'), s: s.size }); break; }
    case 'read': {
      const s = fs.statSync(full);
      if (!s.isFile()) fail('Not a file');
      if (s.size > MAXREAD) fail('File too large to edit (max 1 MB) - download it instead');
      const b = fs.readFileSync(full);
      if (b.includes(0)) fail('Binary file - download it instead');
      out({ c: b.toString('utf8') }); break;
    }
    case 'put': {
      if (!/^\.hp-up-[a-f0-9]+$/.test(arg || '')) fail('Bad temp name');
      try { if (fs.statSync(full).isDirectory()) fail('Target is a directory'); } catch (e) { if (e.code !== 'ENOENT') fail(e.message); }
      const tmp = path.join(path.dirname(full), arg);
      res(path.relative(home, tmp), false);
      let keepMode = null; try { keepMode = fs.statSync(full).mode & 0o777; } catch (e) {}
      const ws = fs.createWriteStream(tmp, { flags: fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, mode: 0o640 });
      ws.on('error', (e) => fail(e.message));
      process.stdin.on('error', (e) => { try { fs.unlinkSync(tmp); } catch (x) {} fail(e.message); });
      ws.on('finish', () => {
        try { if (keepMode !== null) fs.chmodSync(tmp, keepMode); fs.renameSync(tmp, full); out({ ok: 1 }); } catch (e) { try { fs.unlinkSync(tmp); } catch (x) {} fail(e.message); }
      });
      process.stdin.pipe(ws);
      break;
    }
    case 'cat': {
      if (!fs.statSync(full).isFile()) fail('Not a file');
      const rs = fs.createReadStream(full);
      rs.on('error', (e) => fail(e.message));
      rs.pipe(process.stdout);
      break;
    }
    case 'mkdir': { if (fs.existsSync(full)) fail('Already exists'); fs.mkdirSync(full, { mode: 0o750 }); out({ ok: 1 }); break; }
    case 'touch': { fs.closeSync(fs.openSync(full, 'wx', 0o640)); out({ ok: 1 }); break; }
    case 'rename': {
      const dest = res(arg, false);
      if (full === home) fail('Refusing');
      if (fs.existsSync(dest)) fail('Target already exists');
      fs.renameSync(full, dest); out({ ok: 1 }); break;
    }
    case 'rm': {
      if (full === home) fail('Refusing to delete home');
      if (['/public_html', '/tmp', '/logs'].some((x) => full === path.join(home, x))) fail('Refusing to delete a core folder');
      fs.rmSync(full, { recursive: true, force: true }); out({ ok: 1 }); break;
    }
    case 'chmod': {
      if (!/^0?[0-7]{3}$/.test(arg || '')) fail('Mode must be 3 octal digits, e.g. 644');
      fs.chmodSync(full, parseInt(arg, 8)); out({ ok: 1 }); break;
    }
    case 'unzip': {
      if (!fs.statSync(full).isFile()) fail('Not a file');
      // -: never extract absolute paths or ".." (unzip already strips them); -n would skip, -o overwrites as before
      cp.execFileSync('unzip', ['-o', '-q', full, '-d', path.dirname(full)], { stdio: 'pipe', timeout: 300000 });
      // remove any symlinks the archive planted
      const strip = (dir, depth) => {
        if (depth > 12) return;
        for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
          const p = path.join(dir, e.name);
          if (e.isSymbolicLink()) { const t = (() => { try { return fs.realpathSync(p); } catch (x) { return ''; } })(); if (!t || !inside(t)) fs.unlinkSync(p); }
          else if (e.isDirectory()) strip(p, depth + 1);
        }
      };
      strip(path.dirname(full), 0);
      out({ ok: 1 }); break;
    }
    default: fail('Unknown operation');
  }
} catch (e) { fail(e.stderr ? String(e.stderr).trim() : e.message); }
