'use strict';
// Account and authentication-factor routes. Dependencies are injected to keep route behavior testable.
const crypto = require('crypto');
const fs = require('fs');
const USERNAME_RE = /^[A-Za-z][A-Za-z0-9_.-]{2,31}$/;
module.exports = function registerAccountRoutes({ app, auth, page, csrf, esc, badge, fbtn, field, rand, c, sys, load, save, bcrypt, wrap, audit, tf }) {
app.get('/account', auth, (req, res) => {
  const d = load();
  page(req, res, 'Account', (d.admin.mustChange ? '<div class="flash err">You must change the default password before using the panel.</div>' : '') + '<div class="grid two"><div class="card"><h2>Administrator username</h2><p class="muted">Use a unique username instead of the default admin name. Your password and 2FA settings will be preserved.</p><form method="post" action="/account/username" data-nolock>' + csrf(req) +
    field('New username', '<input name="username" value="' + esc(d.admin.user) + '" minlength="3" maxlength="32" pattern="[A-Za-z][A-Za-z0-9_.-]{2,31}" autocomplete="username" required>', '3-32 characters; start with a letter, then letters, numbers, dots, underscores or hyphens.') + field('Current password', '<input name="pass" type="password" autocomplete="current-password" required>') + (d.admin.totp ? field('Authenticator code', '<input name="code" inputmode="numeric" maxlength="6" required>') : '') + '<button>Change username</button></form></div>' +
    '<div class="card"><h2>Change password</h2><form method="post" action="/account" data-nolock>' + csrf(req) +
    field('Current password', '<input name="cur" type="password" autocomplete="current-password" required>') + field('New password', '<input name="nw" type="password" autocomplete="new-password" minlength="12" required>', 'At least 12 characters.') + '<button>Update password</button></form></div>' +
    tf.card(req, d) + '</div>');
});
app.post('/account/username', auth, (req, res) => {
  const d = load();
  const username = String(req.body.username || '').trim();
  if (!USERNAME_RE.test(username)) { req.session.flash = { t: 'err', m: 'Username must be 3-32 characters, start with a letter, and contain only letters, numbers, dots, underscores or hyphens.' }; return res.redirect('/account'); }
  if (!bcrypt.compareSync(String(req.body.pass || ''), d.admin.hash)) { req.session.flash = { t: 'err', m: 'Current password is incorrect.' }; audit(req, 'ADMIN_USERNAME_CHANGE FAILED', ''); return res.redirect('/account'); }
  if (d.admin.totp && !c.totpCheck(d.admin.totp, req.body.code, d.admin)) { req.session.flash = { t: 'err', m: 'The 2FA code is incorrect or already used.' }; audit(req, 'ADMIN_USERNAME_CHANGE FAILED', ''); return res.redirect('/account'); }
  const old = d.admin.user;
  if (username === old) { req.session.flash = { t: 'err', m: 'That is already your username.' }; return res.redirect('/account'); }
  d.admin.user = username; const sv = c.bumpSessions(d); c.save(d); c.auditSys('ADMIN_USERNAME_CHANGED', old + ' -> ' + username); sys.clearSecCache();
  req.session.regenerate((e) => { if (e) return res.status(500).send('Username changed, but session refresh failed. Sign in again.'); req.session.user = username; req.session.sv = sv; req.session.csrf = rand(16); req.session.flash = { t: 'ok', m: 'Administrator username changed successfully.' }; res.redirect('/account'); });
});
app.post('/account', auth, wrap((req) => {
  const d = load();
  if (!bcrypt.compareSync(String(req.body.cur || ''), d.admin.hash)) throw new Error('Current password is wrong');
  const nw = String(req.body.nw || '');
  if (nw.length < 12 || nw.length > 200) throw new Error('New password must be 12-200 characters');
  d.admin.hash = bcrypt.hashSync(nw, 12); d.admin.mustChange = false; req.session.sv = c.bumpSessions(d); save(d); // all other sessions are signed out
  try { fs.unlinkSync(c.P.CRED_FILE); } catch (e) {}
  sys.clearSecCache(); return 'Password updated';
}, '/account', 'PASSWORD'));


};
module.exports.validateUsername = (value) => USERNAME_RE.test(String(value || '').trim());
