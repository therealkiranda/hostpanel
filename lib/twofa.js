'use strict';
// Mandatory two-factor authentication (authenticator app, TOTP) for EVERY panel login: the administrator and every client.
// A login that has no authenticator yet may only open the Account page (to set one up) and sign out; everything else
// redirects there until it is done. There is no "turn 2FA off" button. Recovery is by the administrator (clients) or by
// `sudo hostpanel-cli reset-2fa` on the server (administrator), which only clears the secret so setup is forced again.
const crypto = require('crypto');
const c = require('./core');
const ui = require('./ui');
const { esc } = c;

const isClient = (req) => !!(req.session && req.session.role === 'customer');
const recOf = (d, req) => (isClient(req) ? d.users.find((u) => u.id === req.session.uid) : d.admin) || null;
const secretOf = (rec, client) => (!rec ? null : client ? rec.totpSecret || null : rec.totp || null);
const setSecret = (rec, client, secret) => { if (client) rec.totpSecret = secret; else rec.totp = secret; rec.totpLast = secret ? Math.floor(Date.now() / 30000) : 0; };
// true when the signed-in login still has to set up its authenticator
const pending = (req, d) => { const rec = recOf(d, req); return !secretOf(rec, isClient(req)); };
const pendingAllowed = (req) => req.path === '/account' || req.path.startsWith('/account/') || req.path === '/logout';

// A signed-in session must not be able to guess codes: 5 wrong codes per login in 15 minutes locks these actions.
const bad = new Map();
const key = (req) => (isClient(req) ? 'u:' + req.session.uid : 'admin');
const locked = (req) => { const t = Date.now(), a = (bad.get(key(req)) || []).filter((x) => t - x < 900000); bad.set(key(req), a); return a.length >= 5; };
const miss = (req) => { const a = bad.get(key(req)) || []; a.push(Date.now()); bad.set(key(req), a); };

const group = (s) => String(s).replace(/(.{4})/g, '$1 ').trim();
function otpauth(req, user, secret) {
  const h = String(req.headers.host || '').replace(/:\d+$/, '');
  const issuer = /^[A-Za-z0-9.\-]{1,100}$/.test(h) ? 'HostPanel (' + h + ')' : 'HostPanel';
  return 'otpauth://totp/' + encodeURIComponent(issuer) + ':' + encodeURIComponent(user) + '?secret=' + secret + '&issuer=' + encodeURIComponent(issuer) + '&algorithm=SHA1&digits=6&period=30';
}

function card(req, d) {
  const client = isClient(req), rec = recOf(d, req), sec = secretOf(rec, client), user = client ? rec.username : d.admin.user;
  let body;
  if (req.session.pendingTotp) {
    const ps = req.session.pendingTotp;
    body = '<p>' + ui.badge(sec ? 'Replacing your authenticator' : 'Required', 'warn') + ' Open your authenticator app (Google Authenticator, Microsoft Authenticator, Aegis, Authy, 2FAS...) and add an account with this key. On a phone you can tap the button.</p>' +
      '<p><a class="btn" href="' + esc(otpauth(req, user, ps)) + '">Open in my authenticator app</a></p>' +
      '<p class="muted">Or type the key by hand (time-based, 6 digits):</p><pre class="log mono" id="tk">' + esc(group(ps)) + '</pre>' +
      '<form class="row" method="post" action="/account/2fa/enable" data-nolock>' + ui.csrf(req) + '<input name="code" placeholder="6-digit code from the app" inputmode="numeric" autocomplete="one-time-code" maxlength="8" required><button>Confirm &amp; ' + (sec ? 'replace' : 'turn on') + '</button></form>' +
      '<form class="row" method="post" action="/account/2fa/cancel">' + ui.csrf(req) + '<button class="g s">Cancel</button></form>';
  } else if (sec) {
    body = '<p>' + ui.badge('Authenticator app is on', 'ok') + ' Every sign-in needs the 6-digit code.</p><details><summary>Replace my authenticator (new phone)</summary>' +
      '<form class="row" method="post" action="/account/2fa/start" data-nolock>' + ui.csrf(req) + '<input name="pass" type="password" placeholder="Password" autocomplete="current-password" required><input name="code" placeholder="Current 6-digit code" inputmode="numeric" autocomplete="one-time-code" maxlength="8" required><button class="g">Continue</button></form></details>' +
      '<p class="muted">Lost your phone? ' + (client ? 'Ask your administrator to reset your two-factor authentication.' : 'Run <span class="mono">sudo hostpanel-cli reset-2fa</span> on the server.') + '</p>';
  } else {
    body = '<div class="flash err">Two-factor authentication is required. Set up an authenticator app to continue.</div><form method="post" action="/account/2fa/start">' + ui.csrf(req) + '<button>Set up authenticator app</button></form>';
  }
  return '<div class="card"><h2>Two-factor authentication</h2>' + body + '</div>';
}

function register({ app, auth, load, save, audit, bcrypt, sys, errMsg }) {
  const done = (req, res, ok, msg) => { req.session.flash = { t: ok ? 'ok' : 'err', m: msg }; res.redirect('/account'); };
  app.post('/account/2fa/start', auth, (req, res) => {
    const client = isClient(req), d = load(), rec = recOf(d, req), sec = secretOf(rec, client);
    if (sec) { // replacing an authenticator needs the password AND a current code
      if (locked(req)) return done(req, res, false, 'Too many wrong codes. Try again in 15 minutes.');
      const pw = client ? rec.passwordHash : d.admin.hash;
      if (!bcrypt.compareSync(String(req.body.pass || ''), pw) || !c.totpCheck(sec, req.body.code, rec)) { miss(req); audit(req, '2FA_REPLACE FAILED', ''); return done(req, res, false, 'Wrong password or code.'); }
      save(d);
    }
    req.session.pendingTotp = c.b32enc(crypto.randomBytes(20));
    res.redirect('/account');
  });
  app.post('/account/2fa/enable', auth, (req, res) => {
    const client = isClient(req), ps = req.session.pendingTotp;
    if (!ps) return done(req, res, false, 'Start the setup first.');
    if (locked(req)) return done(req, res, false, 'Too many wrong codes. Try again in 15 minutes.');
    if (!c.totpCheck(ps, req.body.code, null)) { miss(req); audit(req, '2FA_ENABLE FAILED', ''); return done(req, res, false, 'That code is wrong. Check the time on your phone and try again.'); }
    const d = load(), rec = recOf(d, req), had = !!secretOf(rec, client);
    setSecret(rec, client, ps);
    if (had) { // a replaced authenticator signs every other session out
      if (client) { rec.sv = (rec.sv || 1) + 1; req.session.sv = rec.sv; } else req.session.sv = c.bumpSessions(d);
    }
    save(d); delete req.session.pendingTotp; try { sys.clearSecCache(); } catch (e) {}
    audit(req, had ? '2FA_REPLACED' : '2FA_ENABLED', '');
    done(req, res, true, 'Two-factor authentication is on.');
  });
  app.post('/account/2fa/cancel', auth, (req, res) => { delete req.session.pendingTotp; res.redirect('/account'); });
}
module.exports = { register, card, pending, pendingAllowed, recOf, secretOf, isClient };
