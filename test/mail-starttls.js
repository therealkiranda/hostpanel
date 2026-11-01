'use strict';
// SMTP client: STARTTLS upgrade (Resend port 587), refusal to send the password without TLS, header-injection guards.
const assert = require('assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const tls = require('tls');
const { execFileSync } = require('child_process');
const mail = require('../lib/mail');
const T = fs.mkdtempSync(os.tmpdir() + '/hp-mail-');
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', T + '/k', '-out', T + '/c', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
const cert = { key: fs.readFileSync(T + '/k'), cert: fs.readFileSync(T + '/c') };
function server(offerStartTls, seen) {
  return net.createServer((raw) => {
    let s = raw, buf = '', data = false; s.write('220 hi\r\n');
    const onData = (d) => { buf += d; let i; while ((i = buf.indexOf('\r\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 2);
      if (data) { if (l === '.') { data = false; seen.sent = true; s.write('250 ok\r\n'); } continue; }
      if (/^EHLO/.test(l)) s.write(offerStartTls && !s.encrypted ? '250-x\r\n250 STARTTLS\r\n' : '250-x\r\n250 AUTH PLAIN\r\n');
      else if (l === 'STARTTLS') { s.write('220 go\r\n'); s.removeAllListeners('data'); s = new tls.TLSSocket(raw, Object.assign({ isServer: true }, cert)); s.on('data', onData); s.on('error', () => {}); buf = ''; }
      else if (/^AUTH PLAIN/.test(l)) { seen.auth = true; s.write('235 ok\r\n'); } else if (/^(MAIL|RCPT)/.test(l)) s.write('250 ok\r\n'); else if (l === 'DATA') { data = true; s.write('354 go\r\n'); } else if (l === 'QUIT') s.end('221 bye\r\n'); } };
    s.on('data', onData); s.on('error', () => {});
  });
}
const base = { host: 'localhost', user: 'resend', pass: 're_x', from: 'HostPanel <noreply@example.com>', to: 'a@example.com', subject: 'Hi', text: 'Hello', timeoutMs: 4000, tlsOptions: { ca: cert.cert } };
(async () => {
  let seen = {}, srv = server(true, seen); await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  await mail.send(Object.assign({}, base, { port: srv.address().port })); assert.ok(seen.auth && seen.sent, 'STARTTLS upgrade, login and delivery'); srv.close();
  seen = {}; srv = server(false, seen); await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  await assert.rejects(mail.send(Object.assign({}, base, { port: srv.address().port })), /does not offer STARTTLS/); assert.ok(!seen.auth, 'the password is never sent in clear text'); srv.close();
  for (const bad of [{ to: 'a@example.com\r\nBcc: x@y.co' }, { subject: 'x\nBcc: a@b.co' }, { from: 'a@b.co\r\nX: y' }, { to: 'not-an-address' }, { host: 'bad host' }]) await assert.rejects(mail.send(Object.assign({}, base, { port: 587 }, bad)), /./, JSON.stringify(bad));
  const b = mail.build({ from: 'Host Panel <n@example.com>', to: 'a@example.com', subject: 'Zażółć', text: 'Zażółć\n.dot first' });
  assert.ok(/Subject: =\?UTF-8\?B\?/.test(b.data) && !/\n\.dot/.test(b.data), 'non-ASCII subject encoded; body base64 so no dot-stuffing issue');
  console.log('mail client tests passed');
})().then(() => { fs.rmSync(T, { recursive: true, force: true }); process.exit(0); }, (e) => { console.error(e); fs.rmSync(T, { recursive: true, force: true }); process.exit(1); });
