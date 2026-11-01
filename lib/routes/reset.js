'use strict';
// Password reset by email for everyone (administrator and clients) + the mail settings (Resend SMTP).
// The reset link holds a random token; only its SHA-256 hash is stored, it works once for 30 minutes, and the answer to
// "forgot password" is always the same so nobody can find out which usernames or emails exist.
const crypto = require('crypto');
const mail = require('../mail');
const U = require('../users');

module.exports = function registerReset(d0) {
  const { app, auth, page, csrf, esc, field, c, load, save, bcrypt, audit } = d0;
  const sha = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');
  const TTL = 30 * 60 * 1000;
  const mailReady = (d) => { const m = d.settings.mail; return !!(m && m.host && m.port && m.user && m.pass && m.from); };
  // The link must never be built from the request's Host header (a forged Host would send the token to an attacker).
  const baseUrl = (d) => (d.settings.panelSsl && d.settings.panelDomain ? 'https://' + d.settings.panelDomain : d.settings.ip ? 'https://' + d.settings.ip + ':' + c.PORT : null);
  const hits = new Map();
  const limited = (key, max) => { const now = Date.now(), a = (hits.get(key) || []).filter((t) => now - t < 3600000); a.push(now); hits.set(key, a); return a.length > max; };
  c.every(600000, () => { const now = Date.now(); for (const [k, v] of hits) if (!v.some((t) => now - t < 3600000)) hits.delete(k); });

  const find = (d, id) => {
    const x = String(id || '').trim().toLowerCase(); if (!x || x.length > 254) return null;
    if (x === String(d.admin.user).toLowerCase() || (d.admin.email && x === String(d.admin.email).toLowerCase())) return d.admin.email ? { kind: 'admin', uid: 'admin', email: d.admin.email, name: d.admin.user } : null;
    const u = d.users.find((y) => y.active !== false && (y.username.toLowerCase() === x || String(y.email).toLowerCase() === x));
    return u ? { kind: 'client', uid: u.id, email: u.email, name: u.username } : null;
  };

  app.get('/forgot', (req, res) => {
    if (req.session.user) return res.redirect('/');
    page(req, res, 'Forgot password', '<div class="login"><div class="logo">' + d0.ui.svg('logo') + '</div><h1>Reset password</h1><p class="sub">Enter your username or email. If it matches an account we send a reset link.</p><form method="post" action="/forgot" data-nolock>' + csrf(req) +
      field('Username or email', '<input name="who" autocomplete="username" required autofocus maxlength="254">') + '<button>Send reset link</button></form><p class="sub"><a href="/login">Back to sign in</a></p></div>', { bare: true });
  });
  app.post('/forgot', (req, res) => {
    const ip = c.cleanIp(req), d = load();
    req.session.flash = { t: 'ok', m: 'If that matches an account with an email address, a reset link is on its way. It is valid for 30 minutes.' };
    if (!limited('ip:' + ip, 8)) {
      const acct = find(d, req.body.who);
      if (acct && !limited('acct:' + acct.uid, 3)) {
        if (!mailReady(d) || !baseUrl(d)) c.auditSys('RESET_NOT_SENT', 'mail is not configured or the panel address is unknown');
        else {
          const tok = crypto.randomBytes(32).toString('hex'), now = Date.now();
          d.resets = d.resets.filter((r) => r.exp > now && r.uid !== acct.uid).slice(-50); d.resets.push({ h: sha(tok), kind: acct.kind, uid: acct.uid, exp: now + TTL }); save(d);
          const m = d.settings.mail;
          mail.send({ host: m.host, port: m.port, secure: m.secure, user: m.user, pass: m.pass, from: m.from, to: acct.email, subject: 'Reset your HostPanel password',
            text: 'Hello ' + acct.name + ',\n\nSomeone asked to reset the password of your HostPanel login. Open this link within 30 minutes to choose a new password:\n\n' + baseUrl(d) + '/reset?token=' + tok + '\n\nIf you did not ask for this, ignore this email - your password stays as it is.\n' })
            .then(() => c.auditSys('RESET_MAIL_SENT', acct.kind + ' ' + acct.name), (e) => c.auditSys('RESET_MAIL_FAILED', acct.name + ': ' + c.errMsg(e).slice(0, 150)));
        }
      }
    }
    res.redirect('/login');
  });

  const valid = (d, tok) => { const h = sha(tok), now = Date.now(); return /^[a-f0-9]{64}$/.test(String(tok)) ? d.resets.find((r) => r.exp > now && crypto.timingSafeEqual(Buffer.from(r.h), Buffer.from(h))) || null : null; };
  app.get('/reset', (req, res) => {
    const tok = String(req.query.token || ''), r = valid(load(), tok);
    if (!r) { req.session.flash = { t: 'err', m: 'This reset link is invalid or has expired. Request a new one.' }; return res.redirect('/forgot'); }
    res.set('Referrer-Policy', 'no-referrer');
    page(req, res, 'Choose a new password', '<div class="login"><div class="logo">' + d0.ui.svg('logo') + '</div><h1>New password</h1><form method="post" action="/reset" data-nolock>' + csrf(req) + '<input type="hidden" name="token" value="' + esc(tok) + '">' +
      field('New password', '<input type="password" name="password" minlength="12" maxlength="200" autocomplete="new-password" required autofocus>', 'At least 12 characters.') + field('Repeat password', '<input type="password" name="again" minlength="12" maxlength="200" autocomplete="new-password" required>') + '<button>Set password</button></form></div>', { bare: true });
  });
  app.post('/reset', (req, res) => {
    const tok = String(req.body.token || ''), d = load(), r = valid(d, tok);
    try {
      if (!r) throw new Error('This reset link is invalid or has expired. Request a new one.');
      const pw = String(req.body.password || '');
      if (pw !== String(req.body.again || '')) throw new Error('The passwords do not match');
      if (pw.length < 12 || pw.length > 200) throw new Error('Password must be 12-200 characters');
      if (r.kind === 'admin') { d.admin.hash = bcrypt.hashSync(pw, 12); d.admin.sv = (d.admin.sv || 1) + 1; d.admin.mustChange = false; d.resets = d.resets.filter((x) => x.uid !== r.uid); save(d); }
      else { d.resets = d.resets.filter((x) => x.uid !== r.uid); save(d); U.setPassword(r.uid, pw, false); }
      c.auditSys('PASSWORD_RESET', r.kind + ' ' + r.uid.slice(0, 8));
      req.session.flash = { t: 'ok', m: 'Password changed. You can sign in now.' }; return res.redirect('/login');
    } catch (e) {
      req.session.flash = { t: 'err', m: c.errMsg(e) }; return res.redirect(r ? '/reset?token=' + encodeURIComponent(tok) : '/forgot');
    }
  });

  /* ---------- administrator: mail settings ---------- */
  const mailCard = (req, d) => {
    const m = d.settings.mail || {};
    return '<div class="card"><h2>Email (password reset)</h2><p class="muted">Used to send password-reset links to you and your clients. With <b>Resend</b>: host <span class="mono">smtp.resend.com</span>, port 465, user <span class="mono">resend</span>, password = your Resend API key, and a From address on a domain you verified in Resend.</p>' +
      '<p>' + (mailReady(d) ? '<span class="badge ok">Configured</span>' : '<span class="badge warn">Not configured</span>') + '</p><form method="post" action="/settings/mail" data-nolock>' + csrf(req) + '<div class="fgrid">' +
      field('SMTP host', '<input name="host" value="' + esc(m.host || 'smtp.resend.com') + '" required>') + field('Port', '<input name="port" type="number" value="' + esc(m.port || 465) + '" required>', '465 or 2465 = TLS, 587 or 2587 = STARTTLS') +
      field('SMTP user', '<input name="user" value="' + esc(m.user || 'resend') + '" required>') + field('Password / API key', '<input name="pass" type="password" autocomplete="new-password" placeholder="' + (m.pass ? 'saved - leave empty to keep' : 're_...') + '">') +
      field('From address', '<input name="from" value="' + esc(m.from || '') + '" placeholder="HostPanel &lt;noreply@yourdomain.com&gt;" required>') + field('Your email (administrator)', '<input name="adminEmail" type="email" value="' + esc(d.admin.email || '') + '" placeholder="you@example.com">', 'Needed so you can reset your own password.') + '</div><button>Save email settings</button></form>' +
      '<form class="row" method="post" action="/settings/mail/test" data-nolock>' + csrf(req) + '<button class="g">Send a test email to me</button></form></div>';
  };
  app.post('/settings/mail', auth, (req, res) => {
    let ok = true;
    try {
      const d = load(), b = req.body, old = d.settings.mail || {};
      const adminEmail = String(b.adminEmail || '').trim();
      if (adminEmail && !mail.ADDR_RE.test(adminEmail)) throw new Error('Your email address is not valid');
      const m = { secure: old.secure === true, host: String(b.host || '').trim(), port: parseInt(b.port, 10), user: String(b.user || '').trim(), pass: String(b.pass || '') || old.pass || '', from: String(b.from || '').trim() };
      if (!/^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(m.host)) throw new Error('SMTP host is not valid');
      if (!(m.port >= 1 && m.port <= 65535)) throw new Error('Port is not valid');
      if (!m.user || /[\r\n\0]/.test(m.user + m.pass) || m.user.length > 200 || m.pass.length > 500) throw new Error('SMTP user / password are not valid');
      mail.parseFrom(m.from);
      d.settings.mail = m; d.admin.email = adminEmail; save(d);
      req.session.flash = { t: 'ok', m: 'Email settings saved. Press "Send a test email" to check them.' };
    } catch (e) { ok = false; req.session.flash = { t: 'err', m: c.errMsg(e) }; }
    audit(req, 'MAIL_SETTINGS' + (ok ? '' : ' FAILED'), ''); res.redirect('/settings');
  });
  app.post('/settings/mail/test', auth, async (req, res) => {
    let ok = true; const d = load();
    try {
      if (!mailReady(d)) throw new Error('Save the email settings first');
      if (!d.admin.email) throw new Error('Enter your own email address and save, then test');
      const m = d.settings.mail;
      await mail.send({ host: m.host, port: m.port, secure: m.secure, user: m.user, pass: m.pass, from: m.from, to: d.admin.email, subject: 'HostPanel test email', text: 'This is a test email from HostPanel. Password reset emails will arrive like this.\n' });
      req.session.flash = { t: 'ok', m: 'Test email sent to ' + d.admin.email + '. Check your inbox (and spam).' };
    } catch (e) { ok = false; req.session.flash = { t: 'err', m: 'Could not send: ' + c.errMsg(e) }; }
    audit(req, 'MAIL_TEST' + (ok ? '' : ' FAILED'), ''); res.redirect('/settings');
  });
  return { mailCard };
};
