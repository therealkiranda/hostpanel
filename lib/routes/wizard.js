'use strict';
// "New website": one place for everything. The administrator picks WordPress, Laravel, Node.js, PHP, Static HTML, Python
// or Reverse Proxy and gets the wizard for exactly that kind of website. Clients can open the WordPress / Laravel wizards
// for a website that already belongs to them (they cannot create new websites).
const tenancy = require('../tenancy');
const stable = require('../apps/stable');
const runtime = require('../runtime');
const tools = require('../tools');
const U = require('../users');
const { cleanDbSpec } = require('../apps/dbspec');

const TYPES = [
  { id: 'wordpress', name: 'WordPress', tag: 'WP', summary: 'Blog, business site or shop. Installs the latest stable WordPress with its database and first administrator.', app: true },
  { id: 'laravel', name: 'Laravel', tag: 'Lv', summary: 'PHP framework. Installs the latest stable Laravel with Composer, connects the database and migrates it.', app: true },
  { id: 'node', name: 'Node.js', tag: 'JS', summary: 'Node.js application on its own port, kept running as a service under the website\'s own user.' },
  { id: 'php', name: 'PHP', tag: 'PHP', summary: 'Empty PHP website with its own PHP-FPM pool. Upload your own code over SFTP or the File Manager.' },
  { id: 'static', name: 'Static HTML', tag: '</>', summary: 'HTML, CSS and JavaScript files only. No PHP, nothing to keep running.' },
  { id: 'python', name: 'Python', tag: 'Py', summary: 'Python application (Flask, Django, FastAPI...) with its own virtual environment, kept running as a service.' },
  { id: 'proxy', name: 'Reverse Proxy', tag: '\u21c4', summary: 'Send a domain to an application that already listens on a local port.' }
];
const typeOf = (id) => TYPES.find((t) => t.id === id) || null;

module.exports = function registerWizard(d0) {
  const { app, auth, page, csrf, esc, badge, field, sel, q, c, load, audit, apps, sys, S } = d0;
  const NEW = apps.NEW;

  const gen = (id) => '<button type="button" class="g s" data-gen="#' + id + '">Generate</button>';
  const pwField = (name, label, value, hint) => field(label, '<div class="row"><input id="' + name + '" name="' + name + '" type="text" class="mono" value="' + esc(value) + '" autocomplete="off" spellcheck="false" required>' + gen(name) + '</div>', hint);
  const text = (name, label, value, hint, extra) => field(label, '<input name="' + name + '" value="' + esc(value || '') + '" autocomplete="off" spellcheck="false"' + (extra || '') + '>', hint);

  /* ---------- 1. the picker ---------- */
  app.get('/sites/new', auth, (req, res) => {
    const cards = TYPES.map((t) => '<a class="card tcard" href="/sites/new/' + t.id + '"><div class="ticon t-' + t.id + '">' + esc(t.tag) + '</div><div><b>' + esc(t.name) + '</b><p>' + esc(t.summary) + '</p></div><span class="btn g s">Create a ' + esc(t.name) + ' site</span></a>').join('');
    page(req, res, 'New website', '<p><a href="/sites">&larr; All websites</a></p><h2 class="center">What kind of website would you like to create?</h2><div class="grid tgrid">' + cards + '</div>' +
      '<p class="muted">Installing an application (WordPress, Laravel) also creates its database. Applications are always installed from the latest <b>stable</b> release - never a beta or release candidate.</p>');
  });
  app.get('/apps', auth, (req, res) => res.redirect('/sites/new'));
  app.get('/apps/install', auth, (req, res) => res.redirect('/sites/new/' + encodeURIComponent(String(req.query.app || '')) + (req.query.site ? '?' + q({ site: String(req.query.site) }) : '')));

  /* ---------- 2. the wizard form ---------- */
  const rnd = (n) => c.rand(n);
  app.get('/sites/new/:type', auth, (req, res) => {
    const t = typeOf(req.params.type);
    if (!t) { req.session.flash = { t: 'err', m: 'Unknown website type' }; return res.redirect('/sites/new'); }
    const isCustomer = req.session.role === 'customer', actor = U.actorOf(req);
    if (isCustomer && !t.app) return res.status(403).send('Not allowed');
    const d = load(), php = sys.phpVersions(), prev = req.session.wizForm || {}; delete req.session.wizForm;
    let main = '', note = '';
    const a = t.app ? apps.get(t.id) : null;
    if (a) {
      const sites = apps.eligibleSites(a, d, actor), want = String(req.query.site || prev.target || '');
      const cur = sites.some((s) => s.domain === want) ? want : (isCustomer ? (sites[0] ? sites[0].domain : '') : NEW);
      if (isCustomer && !sites.length) return page(req, res, 'Install ' + t.name, '<p><a href="/sites">&larr; Websites</a></p><div class="card empty">You have no ' + esc(a.siteTypes.join('/')) + ' website to install ' + esc(t.name) + ' on. Ask your administrator.</div>');
      const opts = (isCustomer ? [] : [[NEW, 'A new website (domain below)']]).concat(sites.map((s) => [s.domain, s.domain + ' (existing)']));
      stable.latest(a.id).catch(() => null); // warm the cache for the next page view
      const st = stable.peek(a.id);
      note = '<p>' + badge('Stable only', 'ok') + ' <span class="muted">' + (st ? 'Latest stable release: <b>' + esc(a.name + ' ' + st.version) + '</b>. ' : '') + 'Beta and release-candidate versions are never installed.</span></p>';
      main += '<h3>Website</h3><div class="fgrid">' + field('Install on', sel('target', opts, cur), isCustomer ? 'The folder must be empty (only the default "site is ready" page is replaced).' : 'Existing websites must have an empty folder (only the default "site is ready" page is replaced).') +
        (isCustomer ? '' : field('Domain (for a new website)', '<input name="domain" value="' + esc(prev.domain || '') + '" placeholder="example.com" autocomplete="off">', 'Create A records for the domain and www pointing to ' + esc(d.settings.ip || 'this server') + '.') +
          field('PHP version (new website)', sel('php', php.map((v) => [v, 'PHP ' + v]), prev.php || php[php.length - 1]))) +
        (a.subfolder ? field('Folder', '<input name="path" value="' + esc(prev.path || '') + '" placeholder="leave empty for the site root" pattern="[a-z0-9][a-z0-9_-]{0,30}" autocomplete="off">', 'Optional: install into a sub-folder such as <span class="mono">blog</span>.') : '') + '</div>';
      const env = { email: prev.adminEmail || d.email || '', password: c.genPassword(20) };
      const flds = a.handler.fields(env).map((f) => Object.assign({}, f, prev[f.name] !== undefined && f.name !== 'adminPassword' ? { value: prev[f.name] } : {}));
      main += '<h3>' + esc(t.name) + '</h3><div class="fgrid">' + flds.map((f) => f.name === 'adminPassword' ? pwField('adminPassword', f.label, f.value, esc(f.hint || '')) :
        field(esc(f.label), f.type === 'select' ? sel(f.name, f.options, f.value) : '<input name="' + esc(f.name) + '" type="' + esc(f.type || 'text') + '" value="' + esc(f.value || '') + '"' + (f.placeholder ? ' placeholder="' + esc(f.placeholder) + '"' : '') + (f.required ? ' required' : '') + (f.pattern ? ' pattern="' + esc(f.pattern) + '"' : '') + ' autocomplete="off" spellcheck="false">', f.hint ? esc(f.hint) : '')).join('') + '</div>';
      const pfx = a.dbPrefix || a.id;
      main += '<h3>Database</h3><div class="fgrid">' + text('dbName', 'Database name', prev.dbName || pfx + '_' + rnd(3), 'Letters, numbers and _ (3-32), starting with a letter.', ' pattern="[a-z][a-z0-9_]{2,31}" required') +
        text('dbUser', 'Database username', prev.dbUser || pfx + 'u_' + rnd(3), 'A separate login for this database.', ' pattern="[a-z][a-z0-9_]{2,31}" required') +
        pwField('dbPassword', 'Database password', c.genPassword(20), '12-64 characters: letters, numbers and ! @ # % ^ * _ + = . , : ; ~ -') +
        (t.id === 'wordpress' ? text('tablePrefix', 'Table prefix', prev.tablePrefix || 'wp' + rnd(2) + '_', 'A random prefix is safer than the default wp_.', ' pattern="[A-Za-z][A-Za-z0-9]{0,15}_"') : '') + '</div>' +
        '<div class="check"><input type="checkbox" id="https" name="https" value="1"' + (prev.https === '1' ? ' checked' : '') + '><label for="https">Use https:// addresses for this site</label></div>' +
        '<p class="muted">No certificate is requested here. Afterwards open the website\'s <b>Manage &rarr; SSL certificate</b> and press <b>Issue certificate</b> (the domain must point to this server; with Cloudflare use the grey cloud until it is issued).</p>';
    } else {
      main += '<h3>Website</h3><div class="fgrid">' + field('Domain', '<input name="domain" value="' + esc(prev.domain || '') + '" placeholder="example.com" autocomplete="off" required>', 'Create A records for the domain and www pointing to ' + esc(d.settings.ip || 'this server') + '.');
      if (t.id === 'php') main += field('PHP version', sel('php', php.map((v) => [v, 'PHP ' + v]), prev.php || php[php.length - 1]));
      if (t.id === 'proxy') main += field('Application port', '<input name="port" type="number" min="1024" max="65535" value="' + esc(prev.port || '') + '" placeholder="3000" required>', 'The domain is sent to 127.0.0.1 on this port.');
      if (t.id === 'node' || t.id === 'python') {
        const k = runtime.KINDS[t.id];
        main += field('Application port', '<input name="port" type="number" min="1024" max="65535" value="' + esc(prev.port || runtime.nextPort(d)) + '" required>', 'Your app must listen on this port (it is also passed as the PORT variable).') +
          field('Start command', '<input name="cmd" class="mono" value="' + esc(prev.cmd || k.defaultCmd) + '" autocomplete="off" spellcheck="false">', 'Run inside public_html. Use {PORT} for the port. A sample app is created so the site answers right away.');
        if (t.id === 'node') note = '<p class="muted">Runs with the server\'s Node.js ' + esc(String(require('../core').soft('node', ['-v']).trim() || 'installed')) + '. After uploading your code use <b>Manage &rarr; Application &rarr; Install dependencies</b> (npm).</p>';
        else if (!tools.TOOLS.python.ready()) note = '<div class="flash err">Python 3 with venv is not installed on this server. ' + (req.session.role === 'customer' ? '' : 'Install it from <a href="/settings">Settings &rarr; Server tools</a> first.') + '</div>';
        else note = '<p class="muted">A virtual environment (<span class="mono">venv</span>) is created for the site. After uploading your code use <b>Manage &rarr; Application &rarr; Install dependencies</b> (pip).</p>';
      }
      main += '</div>';
    }
    if (!isCustomer) {
      const clients = d.users.filter((u) => u.active !== false);
      main += '<h3>Client access (optional)</h3><div class="fgrid">' + field('Give this website to a client', sel('ownerId', [['system', 'Nobody - administrator only']].concat(clients.map((u) => [u.id, u.username + ' (' + u.email + ')'])), prev.ownerId || 'system'),
        clients.length ? 'The client signs in with their own login and only sees this website.' : 'No clients yet: create logins under <a href="/users">Clients</a>, then assign websites there.') + '</div>';
    }
    page(req, res, (a ? 'Install ' : 'New ') + t.name, '<p><a href="' + (isCustomer ? '/sites' : '/sites/new') + '">&larr; ' + (isCustomer ? 'Websites' : 'All website types') + '</a></p><div class="card section"><div class="wiz-h"><div class="ticon t-' + t.id + '">' + esc(t.tag) + '</div><div><h2>' + (a ? 'Install ' : 'Create a ') + esc(t.name) + (a ? '' : ' website') + '</h2><p class="muted">' + esc(t.summary) + '</p></div></div>' + note +
      '<form method="post" action="/sites/new/' + t.id + '" data-nolock>' + csrf(req) + main + '<button>' + (a ? 'Install ' + esc(t.name) : 'Create website') + '</button></form></div>');
  });

  /* ---------- 3. create ---------- */
  app.post('/sites/new/:type', auth, async (req, res) => {
    const t = typeOf(req.params.type), actor = U.actorOf(req), isCustomer = actor.role === 'customer';
    let ok = true, back = '/tasks';
    try {
      if (!t) throw new Error('Unknown website type');
      if (isCustomer && !t.app) throw new Error('Not allowed');
      const f = req.body;
      const ownerId = isCustomer ? actor.tenantId : String(f.ownerId || 'system');
      if (t.app) {
        const flash = await apps.start(Object.assign({}, f, { app: t.id, ownerId }), actor);
        req.session.flash = { t: 'ok', m: flash };
      } else {
        if (c.jobRunning() && (t.id === 'python')) throw new Error('Another task is running (see Tasks page). Try again when it has finished.');
        if (t.id === 'python' && !tools.TOOLS.python.ready()) throw new Error('Python 3 with venv is not installed. Install it from Settings -> Server tools first.');
        const msg = S.createSite({ domain: f.domain, type: t.id, php: f.php, port: f.port, cmd: f.cmd, ownerId });
        const domain = String(f.domain || '').trim().toLowerCase().replace(/^www\./, '');
        let extra = '';
        if (t.id === 'python') {
          const s = S.getSite(load(), domain);
          c.runAsync('Set up Python site ' + domain, (log) => runtime.bootstrap(s, log)); c.setJobOwner('system');
          extra = '\n\nCreating the virtual environment and starting the application - see the Tasks page.';
        }
        req.session.flash = { t: 'ok', m: msg + extra }; back = '/sites/manage?' + q({ domain });
      }
    } catch (e) {
      ok = false; back = '/sites/new/' + encodeURIComponent(req.params.type); // the chosen website is restored from the saved form
      req.session.flash = { t: 'err', m: c.errMsg(e) };
      const keep = Object.assign({}, req.body); ['adminPassword', 'dbPassword', '_csrf'].forEach((k) => delete keep[k]); req.session.wizForm = keep;
    }
    audit(req, 'SITE_NEW' + (ok ? '' : ' FAILED'), String(req.body.target && req.body.target !== NEW ? req.body.target : req.body.domain || '') + ' ' + req.params.type);
    res.redirect(back);
  });
};
module.exports.TYPES = TYPES;
