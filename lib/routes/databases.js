'use strict';
// Database manager: database, user and password are separate things. Per-website phpMyAdmin sign-in.
const tenancy = require('../tenancy');
const dbs = require('../dbs');
const pma = require('../pma');
const U = require('../users');

module.exports = function registerDatabases(d0) {
  const { app, auth, page, csrf, esc, badge, field, sel, table, q, fbtn, c, load, S, wrap } = d0;
  const actorOf = U.actorOf;
  const isCustomer = (req) => req.session.role === 'customer';
  const siteOwned = (req, d, domain) => { const s = S.getSite(d, String(domain)); tenancy.assertOwns(actorOf(req), s, 'Website'); return s; };
  // a database is reachable when its website belongs to the signed-in client (administrator-only databases have no website)
  const visible = (req, d) => d.dbs.filter((x) => !isCustomer(req) || (x.site && d.sites.some((s) => s.domain === x.site && tenancy.owns(actorOf(req), s))));
  const dbOf = (req, name) => {
    const d = load(), x = d.dbs.find((y) => y.name === String(name || ''));
    if (!x || !visible(req, d).some((y) => y.name === x.name)) { const e = new Error('Database not found'); e.status = 404; throw e; }
    return x;
  };
  const gen = (id) => '<button type="button" class="g s" data-gen="#' + id + '">Generate</button>';
  const pmaBtn = (req, domain, label) => fbtn(req, '/databases/pma', { domain }, label || 'phpMyAdmin', '');

  app.get('/databases', auth, (req, res) => {
    const d = load(), list = visible(req, d), actor = actorOf(req), mine = d.sites.filter((s) => tenancy.owns(actor, s));
    const rows = list.map((x) => '<tr><td><a href="/databases/manage?' + q({ name: x.name }) + '"><b class="mono">' + esc(x.name) + '</b></a></td><td>' + (x.site ? '<a href="/sites/manage?' + q({ domain: x.site }) + '">' + esc(x.site) + '</a>' : '<span class="muted">administrator only</span>') +
      '</td><td class="mono">' + esc((x.users || []).join(', ') || '-') + '</td><td>' + esc(String(x.created).slice(0, 10)) + '</td><td class="acts"><a class="btn g s" href="/databases/manage?' + q({ name: x.name }) + '">Manage</a>' + (x.site ? pmaBtn(req, x.site) : '') + fbtn(req, '/databases/backup', { name: x.name }, 'Backup', 'g') + '</td></tr>');
    let sites = (isCustomer(req) ? [] : [['', 'None (administrator only)']]).concat(mine.map((s) => [s.domain, s.domain]));
    const create = (isCustomer(req) && !mine.length) ? '' : '<div class="card section"><h2>Create database</h2><form method="post" action="/databases/add" data-nolock>' + csrf(req) + '<div class="fgrid">' +
      field('Website', sel('site', sites, String(req.query.site || ''))) + field('Database name', '<input name="name" placeholder="my_database" pattern="[a-z][a-z0-9_]{2,31}" required autocomplete="off">', 'a-z, 0-9 and _ (3-32).') +
      field('Database username', '<input name="user" placeholder="my_user" pattern="[a-z][a-z0-9_]{2,31}" required autocomplete="off">', 'A separate login for this database. Reuse one of the website\'s existing users to share it (leave the password empty).') +
      field('Database password', '<div class="row"><input id="dbpw" name="password" class="mono" autocomplete="off" spellcheck="false" placeholder="leave empty to generate">' + gen('dbpw') + '</div>', '12-64 characters: letters, numbers and ! @ # % ^ * _ + = . , : ; ~ -') + '</div><button>Create database</button></form>' +
      '<p class="muted">Connect with host <span class="mono">localhost</span>. Manage the data with phpMyAdmin - it only shows the databases of the selected website.</p></div>';
    let pmaCard = '';
    if (!pma.ready()) pmaCard = '<div class="card section"><h2>phpMyAdmin</h2><p>' + badge('Not enabled', 'warn') + ' ' + (isCustomer(req) ? 'Ask your administrator to enable phpMyAdmin.' : 'Install it once and every website gets its own sign-in that only shows that website\'s databases.') + '</p>' +
      (isCustomer(req) ? '' : '<div class="row-acts">' + fbtn(req, '/tools/install', { id: 'phpmyadmin' }, 'Install and enable phpMyAdmin', '', 'data-confirm="Install phpMyAdmin with apt now? It opens port ' + pma.PORT + ' in the firewall."') + '</div>') + '</div>';
    else if (!isCustomer(req)) pmaCard = '<div class="card section"><h2>phpMyAdmin</h2><p>' + badge('Enabled', 'ok') + ' <span class="muted">Port ' + pma.PORT + ' (open it in your cloud firewall too). Each website signs in with its own account.</span></p><div class="row-acts">' + pmaBtn(req, dbs.ADMIN_PMA, 'Open phpMyAdmin (all databases)') + '</div></div>';
    page(req, res, 'Databases', pmaCard + create + '<div class="sec-h"><h2>' + (isCustomer(req) ? 'Your databases' : 'Databases') + '</h2></div>' + table(['Database', 'Website', 'Users', 'Created', 'Actions'], rows, 'No databases yet.'));
  });

  app.post('/databases/add', auth, wrap((req) => {
    const d = load(), actor = actorOf(req), site = String(req.body.site || '').trim();
    let ownerId = 'system';
    if (site) { const s = siteOwned(req, d, site); ownerId = s.ownerId || 'system'; } else if (isCustomer(req)) throw new Error('Choose a website');
    if (isCustomer(req) && d.dbs.filter((x) => x.site === site).length >= dbs.MAX_DBS_CUSTOMER) throw new Error('This website already has the maximum number of databases (' + dbs.MAX_DBS_CUSTOMER + ')');
    const r = dbs.create({ name: req.body.name, user: req.body.user, password: String(req.body.password || ''), site, ownerId });
    return 'Database created\nDB name: ' + r.name + '\nDB user: ' + r.user + '\n' + (r.password ? 'Password: ' + r.password + '\n' : 'Password: (unchanged - existing user)\n') + 'Host: localhost\n' + (r.password ? '(Password is shown only once)' : '');
  }, '/databases', 'DB_ADD'));

  app.get('/databases/manage', auth, (req, res) => {
    let x; try { x = dbOf(req, req.query.name); } catch (e) { req.session.flash = { t: 'err', m: c.errMsg(e) }; return res.redirect('/databases'); }
    const d = load(), name = x.name;
    const urows = (x.users || []).map((u) => '<tr><td><b class="mono">' + esc(u) + '</b></td><td class="acts"><form class="row" method="post" action="/databases/user/password" data-nolock>' + csrf(req) + '<input type="hidden" name="name" value="' + esc(name) + '"><input type="hidden" name="user" value="' + esc(u) + '"><input name="password" class="mono" placeholder="new password (empty = generate)" autocomplete="off"><button class="g s">Set password</button></form>' +
      fbtn(req, '/databases/user/remove', { name, user: u }, 'Remove access', 'd', 'data-confirm="Remove ' + esc(u) + ' from ' + esc(name) + '? The user is deleted when it has no other database."') + '</td></tr>');
    const add = '<div class="card"><h2>Add a database user</h2><form method="post" action="/databases/user/add" data-nolock>' + csrf(req) + '<input type="hidden" name="name" value="' + esc(name) + '"><div class="fgrid">' + field('Username', '<input name="user" pattern="[a-z][a-z0-9_]{2,31}" required autocomplete="off">', 'A new user, or an existing user of this website.') +
      field('Password', '<div class="row"><input id="nupw" name="password" class="mono" autocomplete="off" placeholder="empty = generate">' + gen('nupw') + '</div>') + '</div><button>Add user</button></form></div>';
    const assign = isCustomer(req) ? '' : '<div class="card"><h2>Website</h2><form class="row" method="post" action="/databases/assign" data-nolock>' + csrf(req) + '<input type="hidden" name="name" value="' + esc(name) + '">' + sel('site', [['', 'None (administrator only)']].concat(d.sites.map((s) => [s.domain, s.domain])), x.site) + '<button class="g">Save</button></form><p class="muted">Decides who may see this database and which phpMyAdmin sign-in includes it.</p></div>';
    const tools = '<div class="card"><h2>Tools</h2><div class="row-acts">' + (x.site ? pmaBtn(req, x.site, 'Open phpMyAdmin') : (isCustomer(req) ? '' : pmaBtn(req, dbs.ADMIN_PMA, 'Open phpMyAdmin (all)'))) + fbtn(req, '/databases/backup', { name }, 'Backup now', 'g') + '</div>' +
      '<form class="row" method="post" action="/databases/delete" data-typeconfirm="' + esc(name) + '">' + csrf(req) + '<input type="hidden" name="name" value="' + esc(name) + '"><input type="hidden" name="confirm" value=""><button class="d">Delete database</button></form><p class="muted">A final dump is taken first.</p></div>';
    page(req, res, 'Database: ' + name, '<p><a href="/databases">&larr; All databases</a></p><div class="card section"><dl class="kv"><dt>Database</dt><dd class="mono">' + esc(name) + '</dd><dt>Website</dt><dd>' + (x.site ? esc(x.site) : '<span class="muted">administrator only</span>') + '</dd><dt>Host</dt><dd class="mono">localhost</dd><dt>Created</dt><dd>' + esc(String(x.created).slice(0, 10)) + '</dd></dl></div>' +
      '<div class="sec-h"><h2>Users</h2></div>' + table(['User', 'Actions'], urows, 'No users') + '<div class="grid two">' + add + assign + tools + '</div>');
  });

  const back = (req) => '/databases/manage?' + q({ name: String(req.body.name || '') });
  app.post('/databases/delete', auth, wrap((req) => { dbOf(req, req.body.name); return S.deleteDb(String(req.body.name), false, String(req.body.confirm || '')); }, (req) => (c.jobRunning() ? '/tasks' : '/databases'), 'DB_DELETE'));
  app.post('/databases/backup', auth, wrap((req) => { dbOf(req, req.body.name); return S.backupDb(String(req.body.name)); }, '/tasks', 'DB_BACKUP'));
  app.post('/databases/user/add', auth, wrap((req) => {
    dbOf(req, req.body.name);
    const r = dbs.addUser(String(req.body.name), { user: req.body.user, password: String(req.body.password || '') });
    return 'User added: ' + r.user + (r.password ? '\nPassword: ' + r.password + '\n(Password is shown only once)' : ' (existing user, password unchanged)');
  }, back, 'DB_USER_ADD'));
  app.post('/databases/user/remove', auth, wrap((req) => { const x = dbOf(req, req.body.name); const dropped = dbs.removeUser(x.name, String(req.body.user)); return dropped ? 'User removed and deleted' : 'Access removed'; }, back, 'DB_USER_REMOVE'));
  app.post('/databases/user/password', auth, wrap((req) => {
    const x = dbOf(req, req.body.name), u = String(req.body.user);
    if (!x.users.includes(u)) throw new Error('That user has no access to this database');
    return 'New password for ' + u + ': ' + dbs.setPassword(u, String(req.body.password || '')) + '\n(shown only once)';
  }, back, 'DB_USER_PASSWORD'));
  app.post('/databases/assign', auth, wrap((req) => {
    if (isCustomer(req)) throw new Error('Not allowed');
    const x = dbOf(req, req.body.name), site = String(req.body.site || '');
    const owner = site ? (S.getSite(load(), site).ownerId || 'system') : 'system';
    dbs.assignSite(x.name, site, owner); return 'Saved';
  }, back, 'DB_ASSIGN'));

  /* ---------- phpMyAdmin (one-time sign-in ticket) ---------- */
  app.post('/databases/pma', auth, (req, res) => {
    let ok = true;
    try {
      const domain = String(req.body.domain || '');
      if (domain === dbs.ADMIN_PMA) { if (isCustomer(req)) throw new Error('Not allowed'); } else siteOwned(req, load(), domain);
      const url = pma.urlFor(req.headers.host, pma.ticket(domain));
      d0.audit(req, 'PMA_OPEN', domain);
      return page(req, res, 'phpMyAdmin', '<div class="card section"><h2>phpMyAdmin is ready</h2><p>' + (domain === dbs.ADMIN_PMA ? 'All databases.' : 'Showing only the databases of <b>' + esc(domain) + '</b>.') + ' This sign-in link works once and expires in one minute.</p>' +
        '<p><a class="btn" href="' + esc(url) + '" target="_blank" rel="noopener">Open phpMyAdmin</a></p><p class="muted">If the page does not load, port ' + pma.PORT + ' must be open in your firewall / cloud security group. The browser may warn about the certificate until a panel domain with SSL is set up.</p></div>');
    } catch (e) { ok = false; req.session.flash = { t: 'err', m: c.errMsg(e) }; d0.audit(req, 'PMA_OPEN FAILED', String(req.body.domain || '')); res.redirect('/databases'); }
  });
  app.post('/tools/install', auth, wrap((req) => require('../tools').install(String(req.body.id)), '/tasks', 'TOOL_INSTALL'));
};
