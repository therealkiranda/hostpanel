'use strict';
// Minimal SMTP client (no dependencies) for Resend (smtp.resend.com) or any SMTP server.
// Port 465 = TLS from the start, port 587/2587 = STARTTLS. Login is AUTH LOGIN/PLAIN with the configured user
// (Resend: user "resend", password = your API key). Header values are checked for line breaks (no header injection).
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');

const ADDR_RE = /^[^\s@<>"',;]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
const noLines = (v, what) => { v = String(v == null ? '' : v); if (/[\r\n\0]/.test(v)) throw new Error('Invalid ' + what); return v; };
function parseFrom(from) {
  from = noLines(from, 'sender');
  const m = /^\s*(?:"?([^"<]*?)"?\s*)?<([^<>]+)>\s*$/.exec(from);
  const addr = (m ? m[2] : from).trim();
  if (!ADDR_RE.test(addr)) throw new Error('Sender address is not valid');
  return { addr, name: m && m[1] ? m[1].trim() : '' };
}
const enc = (s) => (/^[\x20-\x7e]*$/.test(s) ? s : '=?UTF-8?B?' + Buffer.from(s, 'utf8').toString('base64') + '?=');
const wrap76 = (b) => b.replace(/(.{76})/g, '$1\r\n');

function build(o) {
  const f = parseFrom(o.from), to = noLines(o.to, 'recipient');
  if (!ADDR_RE.test(to)) throw new Error('Recipient address is not valid');
  const dom = f.addr.split('@')[1];
  const head = ['From: ' + (f.name ? enc(f.name.replace(/[^\x20-\x7e]/g, '')) + ' ' : '') + '<' + f.addr + '>', 'To: <' + to + '>', 'Subject: ' + enc(noLines(o.subject, 'subject')), 'Date: ' + new Date().toUTCString().replace('GMT', '+0000'),
    'Message-ID: <' + crypto.randomBytes(12).toString('hex') + '@' + dom + '>', 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: base64', 'Auto-Submitted: auto-generated'];
  return { from: f.addr, to, data: head.join('\r\n') + '\r\n\r\n' + wrap76(Buffer.from(String(o.text), 'utf8').toString('base64')) + '\r\n' };
}

// o: { host, port, user, pass, from, to, subject, text, timeoutMs, tlsOptions (tests) }
function send(o) {
  return new Promise((resolve, reject) => {
    let msg;
    try { if (!HOST_RE.test(String(o.host || ''))) throw new Error('SMTP host is not valid'); msg = build(o); } catch (e) { return reject(e); }
    const port = parseInt(o.port, 10), implicit = o.secure === true || port === 465 || port === 2465, tlsOpts = Object.assign({ host: o.host, servername: o.host, minVersion: 'TLSv1.2' }, o.tlsOptions || {});
    let sock = implicit ? tls.connect(Object.assign({ port }, tlsOpts)) : net.connect({ host: o.host, port });
    let buf = '', step = 0, done = false, wait = null, secured = implicit;
    const fin = (err) => { if (done) return; done = true; clearTimeout(timer); try { sock.destroy(); } catch (e) {} err ? reject(err instanceof Error ? err : new Error(String(err))) : resolve(); };
    const timer = setTimeout(() => fin(new Error('SMTP server did not answer in time')), o.timeoutMs || 20000);
    const say = (l) => sock.write(l + '\r\n');
    const onData = (d) => {
      buf += d.toString('utf8');
      for (;;) { // a reply ends with a line "NNN text" (no dash after the code)
        const m = /(?:^|\r?\n)(\d{3}) [^\r\n]*\r?\n/.exec(buf); if (!m) return;
        const code = parseInt(m[1], 10), reply = buf.slice(0, m.index + m[0].length); buf = buf.slice(m.index + m[0].length);
        handle(code, reply);
      }
    };
    const expect = (code, reply, ok) => { if (code !== ok) { fin(new Error('SMTP error ' + code + ': ' + reply.replace(/\s+/g, ' ').trim().slice(0, 120))); return false; } return true; };
    function handle(code, reply) {
      if (done) return;
      switch (step) {
        case 0: if (!expect(code, reply, 220)) return; say('EHLO hostpanel.local'); step = 1; break;
        case 1:
          if (!expect(code, reply, 250)) return;
          if (!implicit && !secured) { if (!/STARTTLS/i.test(reply)) return fin(new Error('The SMTP server does not offer STARTTLS - refusing to send the password unencrypted')); say('STARTTLS'); step = 2; break; }
          say('AUTH PLAIN ' + Buffer.from('\0' + o.user + '\0' + o.pass, 'utf8').toString('base64')); step = 4; break;
        case 2: // STARTTLS accepted: upgrade, then say EHLO again
          if (!expect(code, reply, 220)) return;
          sock.removeAllListeners('data');
          sock = tls.connect(Object.assign({ socket: sock }, tlsOpts), () => { secured = true; buf = ''; sock.on('data', onData); say('EHLO hostpanel.local'); step = 1; });
          sock.on('error', fin); break;
        case 4: if (!expect(code, reply, 235)) return; say('MAIL FROM:<' + msg.from + '>'); step = 5; break;
        case 5: if (!expect(code, reply, 250)) return; say('RCPT TO:<' + msg.to + '>'); step = 6; break;
        case 6: if (!expect(code, reply, 250)) return; say('DATA'); step = 7; break;
        case 7: if (!expect(code, reply, 354)) return; sock.write(msg.data + '.\r\n'); step = 8; break;
        case 8: if (!expect(code, reply, 250)) return; say('QUIT'); step = 9; fin(); break;
        default: break;
      }
    }
    sock.on('data', onData); sock.on('error', fin); sock.on('close', () => fin(new Error('SMTP connection closed unexpectedly')));
  });
}
module.exports = { send, build, parseFrom, ADDR_RE };
