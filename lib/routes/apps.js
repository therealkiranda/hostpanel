'use strict';
// App installer pages: the catalog, the install form and the list of installed applications.
// Dependencies are injected (same pattern as routes/account.js) so the module stays testable.
module.exports = function registerAppRoutes({ app, auth, page, csrf, esc, badge, field, sel, table, q, c, load, audit, apps, sys }) {
  const NEW = apps.NEW;

  const fieldInput = (f) => {
    if (f.type === 'select') return sel(f.name, f.options, f.value);
    return '<input name="' + esc(f.name) + '" type="' + esc(f.type || 'text') + '" value="' + esc(f.value || '') + '"' + (f.placeholder ? ' placeholder="' + esc(f.placeholder) + '"' : '') +
      (f.required ? ' required' : '') + (f.pattern ? ' pattern="' + esc(f.pattern) + '"' : '') + (f.mono ? ' class="mono"' : '') + ' autocomplete="off" spellcheck="false">';
  };

  app.get('/apps', auth, (req, res) => {
    const site = String(req.query.site || '');
    const cards = apps.list().map((a) => '<a class="card appcard" href="/apps/install?' + q(site ? { app: a.id, site } : { app: a.id }) + '"><div class="appicon">' + esc(a.name.slice(0, 1)) + '</div>' +
      '<div><b>' + esc(a.name) + '</b> ' + (a.status === 'beta' ? badge('Beta', 'warn') : '') + '<small>' + esc(a.category) + '</small><p>' + esc(a.summary) + '</p></div></a>');
    const rows = apps.installed().map((a) => {
      const link = a.url ? '<a href="' + esc(a.url) + '" target="_blank" rel="noopener">' + esc(a.url) + '</a>' : esc(a.domain + (a.path ? '/' + a.path : ''));
      return '<tr><td><b>' + esc(a.name) + '</b>' + (a.version ? ' <span class="muted">' + esc(a.version) + '</span>' : '') + '</td><td>' + link + '</td><td><a href="/sites/manage?' + q({ domain: a.domain }) + '">' + esc(a.domain) + '</a></td><td class="mono">' + esc(a.db || '-') + '</td><td>' + esc(String(a.installedAt || '').slice(0, 10)) + '</td><td class="acts">' +
        (a.adminUrl ? '<a class="btn g s" href="' + esc(a.adminUrl) + '" target="_blank" rel="noopener">Admin</a>' : '') + '</td></tr>';
    });
    page(req, res, 'App Installer', '<p class="muted">Pick an application. HostPanel creates the website (or uses one you already have), the database, the configuration and the first administrator, then shows the progress on the Tasks page.</p>' +
      '<div class="grid appgrid">' + cards.join('') + '</div>' +
      '<div class="sec-h"><h2>Installed applications</h2></div>' + table(['Application', 'Address', 'Website', 'Database', 'Installed', 'Actions'], rows, 'Nothing installed through the App Installer yet.') +
      '<p class="muted">Just need an empty website, a static site or a reverse proxy (Node.js, Python, Go)? Use <a href="/sites">Websites &rarr; Add a website</a>.</p>');
  });

  app.get('/apps/install', auth, (req, res) => {
    const a = apps.get(req.query.app);
    if (!a) { req.session.flash = { t: 'err', m: 'Unknown application' }; return res.redirect('/apps'); }
    const d = load(), php = sys.phpVersions(), prev = req.session.appForm || {}; delete req.session.appForm;
    const sites = apps.eligibleSites(a, d), want = String(req.query.site || prev.target || '');
    const cur = sites.some((s) => s.domain === want) ? want : NEW;
    const env = { email: prev.adminEmail || d.email || '', password: c.rand(12) };
    const flds = a.handler.fields(env).map((f) => { const v = prev[f.name]; return Object.assign({}, f, v !== undefined && f.name !== 'adminPassword' ? { value: v } : {}); });
    const httpsOn = prev.https !== undefined ? prev.https === '1' : true;
    const main = '<div class="fgrid">' +
      field('Install on', sel('target', [[NEW, 'A new website (domain below)']].concat(sites.map((s) => [s.domain, s.domain + ' (existing)'])), cur), sites.length ? 'Existing websites must have an empty folder (only the default "site is ready" page is replaced).' : 'No existing ' + esc(a.siteTypes.join('/')) + ' websites - a new one will be created.') +
      field('Domain (for a new website)', '<input name="domain" value="' + esc(prev.domain || '') + '" placeholder="example.com" autocomplete="off">', 'Create A records for the domain and www pointing to ' + esc(d.settings.ip || 'this server') + '.') +
      field('PHP version (new website)', sel('php', php.map((v) => [v, 'PHP ' + v]), prev.php || php[php.length - 1])) +
      (a.subfolder ? field('Folder', '<input name="path" value="' + esc(prev.path || '') + '" placeholder="leave empty for the site root" pattern="[a-z0-9][a-z0-9_-]{0,30}" autocomplete="off">', 'Optional: install into a sub-folder such as <span class="mono">blog</span>.') : '') +
      '</div><div class="fgrid">' + flds.map((f) => field(esc(f.label), fieldInput(f), f.hint ? esc(f.hint) : '')).join('') + '</div>' +
      '<div class="fgrid">' + field('Let\'s Encrypt email', '<input name="email" type="email" value="' + esc(prev.email || d.email || '') + '" placeholder="you@example.com">', 'Used for the free SSL certificate.') + '</div>' +
      '<div class="check"><input type="checkbox" id="https" name="https" value="1"' + (httpsOn ? ' checked' : '') + '><label for="https">Use https:// and get a free Let\'s Encrypt certificate automatically (needs DNS pointing to this server)</label></div>';
    page(req, res, 'Install ' + a.name, '<p><a href="/apps">&larr; All applications</a></p><div class="card section"><h2>Install ' + esc(a.name) + (a.status === 'beta' ? ' ' + badge('Beta', 'warn') : '') + '</h2><p class="muted">' + esc(a.summary) + '</p>' +
      '<form method="post" action="/apps/install">' + csrf(req) + '<input type="hidden" name="app" value="' + esc(a.id) + '">' + main + '<button>Install ' + esc(a.name) + '</button></form></div>');
  });

  // Same flash + audit behaviour as the other POST routes, but a failure returns to the form (keeping what was typed).
  app.post('/apps/install', auth, async (req, res) => {
    const appId = String(req.body.app || ''); let ok = true, back = '/tasks';
    try { req.session.flash = { t: 'ok', m: await apps.start(req.body) }; } catch (e) {
      ok = false; back = '/apps/install?' + q({ app: appId });
      req.session.flash = { t: 'err', m: c.errMsg(e) };
      const keep = Object.assign({}, req.body); delete keep.adminPassword; delete keep._csrf;
      req.session.appForm = keep;
    }
    audit(req, 'APP_INSTALL' + (ok ? '' : ' FAILED'), String(req.body.target && req.body.target !== NEW ? req.body.target : req.body.domain || '') + ' ' + appId);
    res.redirect(back);
  });
};
