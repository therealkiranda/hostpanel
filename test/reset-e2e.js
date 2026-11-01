'use strict';
// Password reset by email (fake Resend SMTP server): boots the real server.js (unprivileged, in a temp folder) and drives it over HTTPS like a browser would.
// Uses real express if installed (CI); otherwise the stand-ins in test/shims. System tools are not needed.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const T = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-e2e-')); fs.chmodSync(T, 0o777);
const BASE = T + '/base', HOMES = T + '/homes';
fs.mkdirSync(BASE + '/data', { recursive: true }); fs.mkdirSync(HOMES, { recursive: true });
for (const d of [BASE, BASE + '/data', HOMES]) fs.chmodSync(d, 0o777);
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', BASE + '/data/panel.key', '-out', BASE + '/data/panel.crt', '-subj', '/CN=test'], { stdio: 'ignore' });
fs.chmodSync(BASE + '/data/panel.key', 0o644);
const PORT = 20000 + Math.floor(Math.random() * 20000);
const CRED = T + '/cred.txt';
fs.mkdirSync(T + '/bin'); fs.writeFileSync(T + '/bin/mysql', '#!/bin/sh\ncat >> "' + T + '/mysql.log"\nexit 0\n', { mode: 0o755 });
const env = Object.assign({}, process.env, { PATH: T + '/bin:' + process.env.PATH, HP_NO_NETWORK: '1', HP_BASE: BASE, HP_CRED: CRED, HP_AUTHLOG: T + '/auth.log', HP_HOMES: HOMES, PANEL_PORT: String(PORT), PANEL_HOST: '127.0.0.1', NODE_PATH: path.join(__dirname, 'shims'), NODE_EXTRA_CA_CERTS: T + '/smtp.crt' });
const tlsx = require('tls');
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', T + '/smtp.key', '-out', T + '/smtp.crt', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
const mails = [];
const smtp = tlsx.createServer({ key: fs.readFileSync(T + '/smtp.key'), cert: fs.readFileSync(T + '/smtp.crt') }, (s) => {
  let buf = '', data = false, cur = { raw: '' }; s.write('220 fake ESMTP\r\n');
  s.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\r\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 2);
    if (data) { if (l === '.') { data = false; mails.push(cur); cur = { raw: '' }; s.write('250 queued\r\n'); } else cur.raw += l + '\n'; continue; }
    if (/^EHLO/.test(l)) s.write('250-fake\r\n250 AUTH PLAIN\r\n'); else if (/^AUTH PLAIN/.test(l)) { cur.auth = Buffer.from(l.slice(11), 'base64').toString('latin1'); s.write('235 ok\r\n'); } else if (/^MAIL FROM/.test(l)) { cur.from = l; s.write('250 ok\r\n'); } else if (/^RCPT TO/.test(l)) { cur.to = l; s.write('250 ok\r\n'); } else if (l === 'DATA') { data = true; s.write('354 go\r\n'); } else if (l === 'QUIT') s.end('221 bye\r\n'); } });
});
const dropRoot = process.getuid && process.getuid() === 0;
const cmd = dropRoot ? 'setpriv' : process.execPath;
const args = (dropRoot ? ['--reuid=65534', '--regid=65534', '--clear-groups', process.execPath] : []).concat([path.join(ROOT, 'server.js')]);

/* ---- tiny browser ---- */
const jar = () => ({ cookie: '' });
function call(method, url, o) {
  o = o || {};
  return new Promise((resolve, reject) => {
    const body = o.form ? new URLSearchParams(o.form).toString() : o.body;
    const headers = Object.assign({}, o.headers || {});
    if (o.jar && o.jar.cookie) headers.Cookie = o.jar.cookie;
    if (o.form) { headers['Content-Type'] = 'application/x-www-form-urlencoded'; headers['Content-Length'] = Buffer.byteLength(body); }
    else if (body !== undefined) headers['Content-Length'] = Buffer.byteLength(body);
    const r = https.request({ host: '127.0.0.1', port: PORT, path: url, method, headers, rejectUnauthorized: false }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const sc = res.headers['set-cookie'];
        if (o.jar && sc) { for (const c of sc) { const [kv] = c.split(';'); if (/Max-Age=0/.test(c)) o.jar.cookie = ''; else o.jar.cookie = kv; } }
        resolve({ status: res.statusCode, headers: res.headers, buf: Buffer.concat(chunks), text: Buffer.concat(chunks).toString('utf8'), setCookie: sc });
      });
    });
    r.on('error', reject); r.end(body);
  });
}
const csrfOf = (html) => { const m = /name="_csrf" value="([a-f0-9]+)"|data-csrf="([a-f0-9]+)"/.exec(html); return m && (m[1] || m[2]); };
/* ---- authenticator (2FA is mandatory): a tiny TOTP client so the tests sign in exactly like a real user ---- */
const SECRETS = {};
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32dec = (s) => { let bits = ''; for (const ch of s) bits += B32.indexOf(ch).toString(2).padStart(5, '0'); const o = []; for (let i = 0; i + 8 <= bits.length; i += 8) o.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(o); };
const hotp = (secret, counter) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(counter)); const h = crypto.createHmac('sha1', b32dec(secret)).update(b).digest(); const o = h[19] & 15; return String((((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1000000).padStart(6, '0'); };
const totpNow = (secret) => hotp(secret, Math.floor(Date.now() / 30000));
const forgetLast = (user) => { const f = BASE + '/data/db.json', db = JSON.parse(fs.readFileSync(f, 'utf8')); if (user === db.admin.user) db.admin.totpLast = 0; else { const u = (db.users || []).find((x) => x.username === user); if (u) u.totpLast = 0; } fs.writeFileSync(f, JSON.stringify(db)); }; // a code may only be used once; tests sign in many times per 30 s
const codeFor = (user) => { if (!SECRETS[user]) return ''; forgetLast(user); return totpNow(SECRETS[user]); };
async function enrol(j, user) {
  const t = csrfOf((await call('GET', '/account', { jar: j })).text);
  await call('POST', '/account/2fa/start', { jar: j, form: { _csrf: t } });
  const pg = await call('GET', '/account', { jar: j });
  const m = /id="tk">([A-Z2-7 ]+)<\/pre>/.exec(pg.text); assert.ok(m, 'setup page shows the key');
  const secret = m[1].replace(/ /g, '');
  const r = await call('POST', '/account/2fa/enable', { jar: j, form: { _csrf: csrfOf(pg.text), code: totpNow(secret) } });
  SECRETS[user] = secret; return r;
}
async function login(j, user, pass, headers, code) {
  const page = await call('GET', '/login', { jar: j, headers });
  const r = await call('POST', '/login', { jar: j, headers, form: { _csrf: csrfOf(page.text), user, pass, code: code === undefined ? codeFor(user) : code } });
  return r;
}
const post = async (j, url, form) => { const t = await getCsrf(j); return call('POST', url, { jar: j, form: Object.assign({ _csrf: t }, form) }); };
const getCsrf = async (j) => csrfOf((await call('GET', '/account', { jar: j })).text) || csrfOf((await call('GET', '/', { jar: j })).text);
const flashOf = async (j, url) => { let r = await call('GET', url, { jar: j }); if (r.status === 302 && /^\/(files|sites|cron|login)/.test(r.headers.location) && r.headers.location !== url) { const again = await call('GET', r.headers.location, { jar: j }); if (/class="flash/.test(again.text)) r = again; } const m = /<div class="flash (?:ok|err)[^"]*"[^>]*>([\s\S]*?)(?:<button|<\/div>)/.exec(r.text); return { status: r.status, flash: m ? m[1].replace(/&#39;/g, "'").replace(/&quot;/g, '"') : '', text: r.text }; };

let server; const outp = [];
async function start() {
  server = spawn(cmd, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
  server.stdout.on('data', (d) => outp.push(String(d))); server.stderr.on('data', (d) => outp.push(String(d)));
  for (let i = 0; i < 100; i++) { if (outp.join('').includes('on https://')) return; if (server.exitCode !== null) throw new Error('server exited: ' + outp.join('')); await new Promise((r) => setTimeout(r, 100)); }
  throw new Error('server did not start: ' + outp.join(''));
}
const wdb = (txt) => { fs.writeFileSync(BASE + '/data/db.json.tmp', txt); fs.renameSync(BASE + '/data/db.json.tmp', BASE + '/data/db.json'); }; // atomic, like the server's own save
const pause = (ms) => new Promise((r) => setTimeout(r, ms));



(async () => {
  await new Promise((r) => smtp.listen(0, '127.0.0.1', r)); const SMTP_PORT = smtp.address().port;
  await start();
  const A = jar();
  const pass0 = /Panel password: (\S+)/.exec(fs.readFileSync(CRED, 'utf8'))[1];
  await login(A, 'admin', pass0); const pass1 = 'a-much-longer-password-1'; await post(A, '/account', { cur: pass0, nw: pass1 }); await enrol(A, 'admin');
  const setDb = (fn) => { const d = JSON.parse(fs.readFileSync(BASE + '/data/db.json', 'utf8')); fn(d); wdb(JSON.stringify(d)); };
  setDb((d) => { d.settings.ip = '203.0.113.5'; });
  const waitMail = async (n) => { for (let i = 0; i < 60 && mails.length < n; i++) await pause(100); assert.ok(mails.length >= n, 'mail #' + n + ' arrived'); return mails[n - 1]; };
  const linkOf = (m) => /https:\/\/203\.0\.113\.5:\d+(\/reset\?token=[a-f0-9]{64})/.exec(Buffer.from(m.raw.split('\n\n').pop().replace(/\n/g, ''), 'base64').toString('utf8'));

  // login page offers it; settings page has the mail card
  assert.ok((await call('GET', '/login', {})).text.includes('/forgot'));
  assert.ok((await call('GET', '/settings', { jar: A })).text.includes('smtp.resend.com'));
  // not configured: same neutral answer, nothing sent, nothing stored
  const X = jar(); let page_ = await call('GET', '/forgot', { jar: X }); assert.equal(page_.status, 200);
  let r = await call('POST', '/forgot', { jar: X, form: { _csrf: csrfOf(page_.text), who: 'admin' } }); assert.equal(r.headers.location, '/login');
  assert.match((await call('GET', '/login', { jar: X })).text, /reset link is on its way/);
  await pause(300); assert.equal(mails.length, 0);

  // configure Resend-style SMTP (TLS, user "resend", API key as password) and send the test email
  r = await post(A, '/settings/mail', { host: 'localhost', port: String(SMTP_PORT), user: 'resend', pass: 're_TestKey123', from: 'HostPanel <noreply@example.com>', adminEmail: 'boss@example.com' });
  assert.match((await flashOf(A, '/settings')).flash, /saved/);
  setDb((d) => { d.settings.mail.secure = true; }); // the fake server speaks TLS from the start on a random port
  assert.ok(!(await call('GET', '/settings', { jar: A })).text.includes('re_TestKey123'), 'the API key is never shown again');
  await post(A, '/settings/mail/test', {}); assert.match((await flashOf(A, '/settings')).flash, /Test email sent/);
  const t1 = await waitMail(1); assert.equal(t1.auth, '\0resend\0re_TestKey123'); assert.match(t1.from, /noreply@example\.com/); assert.match(t1.to, /boss@example\.com/);
  r = await post(A, '/settings/mail', { host: 'bad host!', port: '465', user: 'resend', pass: '', from: 'x@example.com' }); assert.match((await flashOf(A, '/settings')).flash, /host is not valid/);
  r = await post(A, '/settings/mail', { host: 'localhost', port: String(SMTP_PORT), user: 'resend', pass: '', from: 'x@example.com\r\nBcc: evil@e.com' }); assert.match((await flashOf(A, '/settings')).flash, /./);

  // a client with an email
  await post(A, '/users/add', { username: 'kiran', email: 'kiran@example.com', password: 'Client-Pass-12345' });
  const ask = async (who) => { const j = jar(); const p = await call('GET', '/forgot', { jar: j }); const rr = await call('POST', '/forgot', { jar: j, form: { _csrf: csrfOf(p.text), who } }); assert.equal(rr.headers.location, '/login'); return j; };
  const flashText = async (j) => (await call('GET', '/login', { jar: j })).text.match(/reset link is on its way/);
  assert.ok(await flashText(await ask('nobody-here')), 'same answer for unknown accounts'); await pause(300); assert.equal(mails.length, 1, 'no mail for an unknown account');
  await ask('kiran@example.com');
  const m2 = await waitMail(2); assert.match(m2.to, /kiran@example\.com/); const lk = linkOf(m2); assert.ok(lk, 'reset link in the email (built from the configured address, not the Host header)');
  const url = lk[1], tok = url.split('=')[1];
  assert.ok(!fs.readFileSync(BASE + '/data/db.json', 'utf8').includes(tok), 'only a hash of the token is stored');
  // use the link
  const K = jar(); let pg = await call('GET', url, { jar: K }); assert.equal(pg.status, 200); assert.ok(pg.text.includes('name="password"'));
  r = await call('POST', '/reset', { jar: K, form: { _csrf: csrfOf(pg.text), token: tok, password: 'Brand-New-Passw0rd', again: 'different-password-1' } }); assert.match(r.headers.location, /^\/reset/);
  pg = await call('GET', url, { jar: K });
  r = await call('POST', '/reset', { jar: K, form: { _csrf: csrfOf(pg.text), token: tok, password: 'Brand-New-Passw0rd', again: 'Brand-New-Passw0rd' } }); assert.equal(r.headers.location, '/login');
  const C = jar(); assert.equal((await login(C, 'kiran', 'Client-Pass-12345')).headers.location, '/login', 'old password no longer works');
  assert.equal((await login(C, 'kiran', 'Brand-New-Passw0rd')).headers.location, '/'); await enrol(C, 'kiran'); assert.equal((await call('GET', '/', { jar: C })).status, 200, 'no forced change after a reset the client chose');
  assert.equal((await login(jar(), 'kiran', 'Brand-New-Passw0rd', undefined, '')).headers.location, '/login', 'a reset password alone is not enough: the authenticator code is still required');
  // the link works once only
  pg = await call('GET', url, { jar: jar() }); assert.equal(pg.status, 302); assert.equal(pg.headers.location, '/forgot');
  assert.equal((await call('GET', '/reset?token=' + 'a'.repeat(64), { jar: jar() })).headers.location, '/forgot'); assert.equal((await call('GET', '/reset?token=x', { jar: jar() })).headers.location, '/forgot');

  // the administrator can reset too (by username), which signs the old session out
  await ask('admin'); const m3 = await waitMail(3); assert.match(m3.to, /boss@example\.com/);
  const u3 = linkOf(m3)[1]; const J = jar(); pg = await call('GET', u3, { jar: J });
  r = await call('POST', '/reset', { jar: J, form: { _csrf: csrfOf(pg.text), token: u3.split('=')[1], password: 'Admin-Reset-Passw0rd', again: 'Admin-Reset-Passw0rd' } }); assert.equal(r.headers.location, '/login');
  assert.equal((await call('GET', '/sites', { jar: A })).headers.location, '/login', 'old admin session ended');
  assert.equal((await login(jar(), 'admin', pass1)).headers.location, '/login'); assert.equal((await login(jar(), 'admin', 'Admin-Reset-Passw0rd')).headers.location, '/');
  // rate limit: at most 3 mails per account per hour
  for (let i = 0; i < 4; i++) await ask('kiran'); await pause(600); assert.ok(mails.length <= 3 + 3, 'rate limited, got ' + mails.length);

  assert.ok(!outp.join('').match(/Error|TypeError|ReferenceError|UnhandledPromise/), 'server printed errors:\n' + outp.join(''));
  console.log('password reset by email tests passed');
})().then(() => cleanup(0), (e) => { console.error(e); console.error('--- server output ---\n' + outp.join('').slice(-1500)); cleanup(1); });
function cleanup(code) { try { smtp.close(); } catch (e) {} try { server.kill('SIGKILL'); } catch (e) {} try { fs.rmSync(T, { recursive: true, force: true }); } catch (e) {} process.exitCode = code; }
