'use strict';
// Administrator: client logins. A client signs in on the normal login page and only sees the websites assigned here.
const U = require('../users');

module.exports = function registerUsers(d0) {
  const { app, auth, page, csrf, esc, badge, field, table, q, fbtn, c, load, S, wrap } = d0;
  const list = (v) => [].concat(v === undefined ? [] : v).map(String).filter(Boolean);
  const gen = (id) => '<button type="button" class="g s" data-gen="#' + id + '">Generate</button>';
  const siteChecks = (d, id, name) => d.sites.length ? '<div class="checks">' + d.sites.map((s, i) => {
    const mine = s.ownerId === id, other = s.ownerId !== 'system' && !mine && s.ownerId;
    const who = other ? ((d.users.find((u) => u.id === s.ownerId) || {}).username || 'another client') : '';
    return '<div class="check"><input type="checkbox" id="' + name + i + '" name="sites" value="' + esc(s.domain) + '"' + (mine ? ' checked' : '') + (other ? ' disabled' : '') + '><label for="' + name + i + '">' + esc(s.domain) + (other ? ' <span class="muted">(assigned to ' + esc(who) + ')</span>' : '') + '</label></div>';
  }).join('') + '</div>' : '<p class="muted">No websites yet.</p>';

  app.get('/users', auth, (req, res) => {
    const d = load();
    const rows = d.users.map((u) => { const own = U.sitesOf(d, u.id); return '<tr><td><a href="/users/manage?' + q({ id: u.id }) + '"><b>' + esc(u.username) + '</b></a></td><td>' + esc(u.email) + '</td><td>' + (own.map((s) => '<a href="/sites/manage?' + q({ domain: s.domain }) + '">' + esc(s.domain) + '</a>').join(', ') || '<span class="muted">none</span>') +
      '</td><td>' + (u.active === false ? badge('Disabled', 'err') : badge('Active', 'ok')) + '</td><td>' + esc(String(u.lastLogin || '').slice(0, 16).replace('T', ' ') || 'never') + '</td><td class="acts"><a class="btn g s" href="/users/manage?' + q({ id: u.id }) + '">Manage</a></td></tr>'; });
    const form = '<div class="card section"><h2>Create a client login</h2><p class="muted">The client signs in at the same address as you, with their own username and password, and can only manage the websites you assign (files, databases, backups, cron, SSL, PHP settings).</p>' +
      '<form method="post" action="/users/add" data-nolock>' + csrf(req) + '<div class="fgrid">' + field('Username', '<input name="username" pattern="[A-Za-z][A-Za-z0-9_.-]{2,31}" required autocomplete="off">', '3-32 characters, e.g. the client\'s name.') + field('Email', '<input name="email" type="email" required autocomplete="off">') +
      field('Password', '<div class="row"><input id="cpw" name="password" class="mono" required minlength="12" autocomplete="off" spellcheck="false">' + gen('cpw') + '</div>', 'At least 12 characters. The client must change it at the first login.') + '</div>' +
      '<h3>Websites this client may manage</h3>' + siteChecks(d, '', 'ns') + '<button>Create client</button></form></div>';
    page(req, res, 'Clients', form + '<div class="sec-h"><h2>Clients</h2></div>' + table(['Username', 'Email', 'Websites', 'Status', 'Last login', 'Actions'], rows, 'No client logins yet.'));
  });
  app.post('/users/add', auth, wrap((req) => {
    const u = U.add({ username: req.body.username, email: req.body.email, password: req.body.password });
    const sites = list(req.body.sites); sites.forEach((dom) => { const s = S.getSite(load(), dom); if (s.ownerId && s.ownerId !== 'system') throw new Error(dom + ' already belongs to another client'); });
    sites.forEach((dom) => S.setOwner(dom, u.id));
    return 'Client created: ' + u.username + '\nPassword: ' + req.body.password + '\n(Give these to your client. Password is shown only once - they must change it at the first login.)';
  }, '/users', 'USER_ADD'));

  app.get('/users/manage', auth, (req, res) => {
    const d = load(), u = U.byId(d, String(req.query.id || ''));
    if (!u) { req.session.flash = { t: 'err', m: 'Client not found' }; return res.redirect('/users'); }
    const hid = '<input type="hidden" name="id" value="' + esc(u.id) + '">';
    page(req, res, 'Client: ' + u.username, '<p><a href="/users">&larr; All clients</a></p><div class="grid two">' +
      '<div class="card"><h2>Websites</h2><form method="post" action="/users/sites" data-nolock>' + csrf(req) + hid + siteChecks(d, u.id, 'ws') + '<button>Save websites</button></form></div>' +
      '<div class="card"><h2>Account</h2><dl class="kv"><dt>Username</dt><dd class="mono">' + esc(u.username) + '</dd><dt>Email</dt><dd>' + esc(u.email) + '</dd><dt>Status</dt><dd>' + (u.active === false ? 'Disabled' : 'Active') + '</dd><dt>Created</dt><dd>' + esc(String(u.createdAt).slice(0, 10)) + '</dd></dl>' +
      '<form class="row" method="post" action="/users/email" data-nolock>' + csrf(req) + hid + '<input name="email" type="email" value="' + esc(u.email) + '" required><button class="g">Change email</button></form>' +
      '<div class="row-acts">' + fbtn(req, '/users/toggle', { id: u.id, on: u.active === false ? '1' : '0' }, u.active === false ? 'Enable login' : 'Disable login', u.active === false ? '' : 'd', u.active === false ? '' : 'data-confirm="Disable this login? The client is signed out immediately."') + '</div></div>' +
      '<div class="card"><h2>Reset password</h2><form method="post" action="/users/password" data-nolock>' + csrf(req) + hid + field('New password', '<div class="row"><input id="rpw" name="password" class="mono" required minlength="12" autocomplete="off">' + gen('rpw') + '</div>', 'The client is signed out and must choose a new password at the next login.') + '<button>Reset password</button></form></div>' +
      '<div class="card"><h2>Delete login</h2><p class="muted">Their websites and databases stay on the server and become administrator-only.</p><form class="row" method="post" action="/users/delete" data-typeconfirm="' + esc(u.username) + '">' + csrf(req) + hid + '<input type="hidden" name="confirm" value=""><button class="d">Delete ' + esc(u.username) + '</button></form></div></div>');
  });
  const back = (req) => '/users/manage?' + q({ id: String(req.body.id || '') });
  app.post('/users/sites', auth, wrap((req) => {
    const d = load(), u = U.byId(d, String(req.body.id)); if (!u) throw new Error('Client not found');
    const want = new Set(list(req.body.sites));
    for (const s of d.sites) {
      if (want.has(s.domain) && s.ownerId !== u.id) { if (s.ownerId && s.ownerId !== 'system') throw new Error(s.domain + ' belongs to another client'); S.setOwner(s.domain, u.id); }
      else if (!want.has(s.domain) && s.ownerId === u.id) S.setOwner(s.domain, 'system');
    }
    return 'Websites saved';
  }, back, 'USER_SITES'));
  app.post('/users/password', auth, wrap((req) => { U.setPassword(String(req.body.id), req.body.password, true); return 'Password reset. Give the client: ' + req.body.password + '\n(shown only once)'; }, back, 'USER_PASSWORD'));
  app.post('/users/email', auth, wrap((req) => { U.setEmail(String(req.body.id), String(req.body.email || '').trim()); return 'Email saved'; }, back, 'USER_EMAIL'));
  app.post('/users/toggle', auth, wrap((req) => { U.setActive(String(req.body.id), req.body.on === '1'); return req.body.on === '1' ? 'Login enabled' : 'Login disabled'; }, back, 'USER_TOGGLE'));
  app.post('/users/delete', auth, wrap((req) => {
    const u = U.byId(load(), String(req.body.id)); if (!u) throw new Error('Client not found');
    if (String(req.body.confirm) !== u.username) throw new Error('Confirmation did not match - nothing was deleted');
    U.remove(u.id); return 'Login deleted: ' + u.username;
  }, '/users', 'USER_DELETE'));
};
