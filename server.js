'use strict';
// HostPanel 1.0.4 - web server and pages.
const express = require('express');
const session = require('express-session');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const c = require('./lib/core');
const sys = require('./lib/sys');
const S = require('./lib/sites');
const { createApps } = require('./lib/apps');
const siteexec = require('./lib/siteexec');
const tenancy = require('./lib/tenancy');
const access = require('./lib/access');
const U = require('./lib/users');
const runtime = require('./lib/runtime');
const pma = require('./lib/pma');
const tools = require('./lib/tools');
const ui = require('./lib/ui');
const { createService } = require('./lib/update-service');
const { P, PORT, IS_ROOT, VERSION, rand, esc, sh, errMsg, safeEq, fmtSize, fmtDate, bcrypt, audit, load, save } = c;
const { layout, csrf, q, fbtn, badge, meter, stat, field, sel, table } = ui;

const BASE = P.BASE;
const MAX_UPLOAD = 1024 * 1024 * 1024;
let updater = null;
try { updater = createService({ base: BASE, port: PORT, version: VERSION, checkDisk: () => sys.requireDisk(BASE, 90, 'the update') }); } catch (e) { console.error('[hostpanel] release updater disabled: ' + errMsg(e)); }
const DB0 = c.init();
if (IS_ROOT) S.ensureBase();
sys.discoverIp();

/* ================= file-manager plumbing (runs worker.js as the site user; shared with the app installer) ================= */
const { fmOpts, worker: fm, WORKER } = require('./lib/siteexec');
const normRel = (p) => path.posix.normalize('/' + String(p || '')).replace(/\/+$/, '') || '/';
const okName = (n) => { n = String(n || ''); if (!n || n === '.' || n === '..' || /[\/\0]/.test(n) || n.length > 255 || /^\.hp-up-/.test(n)) throw new Error('Invalid name'); return n; };
const tmpName = () => '.hp-up-' + rand(6);
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 12);

/* ================= app + security middleware ================= */
const app = express();
app.disable('x-powered-by');
const ASSET = {};
['app.css:text/css', 'app.js:application/javascript'].forEach((x) => { const [n, t] = x.split(':'); ASSET['/' + n] = { t, b: fs.readFileSync(path.join(__dirname, 'public', n)) }; });
ASSET['/favicon.svg'] = { t: 'image/svg+xml', b: Buffer.from(ui.FAVICON) };

const hits = new Map();
c.every(60000, () => { const t = Date.now(); for (const [k, v] of hits) if (v.r < t) hits.delete(k); });
app.use((req, res, next) => {
  res.set({
    'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
    'Strict-Transport-Security': 'max-age=31536000', 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    // No inline scripts and no inline styles anywhere: meters are drawn from data- attributes by app.js.
    'Content-Security-Policy': "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
  });
  const k = c.cleanIp(req), t = Date.now();
  let h = hits.get(k);
  if (!h || h.r < t) { h = { n: 0, r: t + 60000 }; hits.set(k, h); }
  if (hits.size > 20000) hits.clear();
  if (++h.n > 600) return res.status(429).send('Too many requests');
  next();
});
app.use((req, res, next) => {
  const a = ASSET[req.path];
  if (!a || req.method !== 'GET') return next();
  res.set('Cache-Control', 'public, max-age=3600').type(a.t).send(a.b);
});

const store = new c.PruneStore();
app.use(session({
  name: '__Host-hp.sid', secret: DB0.secret, store, resave: false, saveUninitialized: false, rolling: true,
  cookie: { httpOnly: true, secure: true, sameSite: 'strict', path: '/', maxAge: 30 * 60 * 1000 }
}));
// A password/username change (or hostpanel-cli reset) bumps admin.sv, which signs out every older session.
app.use((req, res, next) => {
  if (req.session && req.session.user) {
    let valid = false;
    try {
      const d = load();
      if (req.session.role === 'customer') { const u = d.users.find((x) => x.id === req.session.uid); valid = !!u && u.active !== false && u.sv === req.session.sv; } else valid = req.session.sv === d.admin.sv;
    } catch (e) {}
    if (!valid) { delete req.session.user; delete req.session.sv; delete req.session.csrf; delete req.session.pendingTotp; delete req.session.role; delete req.session.uid; }
  }
  next();
});
const smallBody = express.urlencoded({ extended: false, limit: '20kb' });
const bigBody = express.urlencoded({ extended: false, limit: '4mb' });
app.use((req, res, next) => {
  if (req.path === '/files/upload') { req.body = {}; return next(); }
  if (req.path === '/files/save') return req.session.user ? bigBody(req, res, next) : res.status(401).send('Login required');
  smallBody(req, res, next);
});
// CSRF. Sessions are only ever created for the login page and for signed-in admins, so scanners
// hitting random URLs cannot grow memory (v2 created a session for every request).
app.use((req, res, next) => {
  const authed = !!req.session.user;
  if (req.method === 'GET' || req.method === 'HEAD') {
    if (authed || req.path === '/login') { if (!req.session.csrf) req.session.csrf = rand(16); }
    return next();
  }
  if (!authed && req.path !== '/login') { if (req.method === 'PUT') req.resume(); return res.status(401).send('Login required'); }
  const tok = (req.body && req.body._csrf) || req.get('x-csrf-token') || '';
  if (!req.session.csrf || !safeEq(tok, req.session.csrf)) { if (req.method === 'PUT') req.resume(); return res.status(403).send('Bad CSRF token'); }
  next();
});
const actorOf = U.actorOf, isClient = access.isCustomer;
const forbidden = (req, res) => { if (req.method === 'PUT') req.resume(); res.status(403); if (req.method === 'GET') return page(req, res, 'Not allowed', '<div class="card empty"><h2>Not allowed</h2><p>Your login cannot open this page.</p><a class="btn" href="/">Back to dashboard</a></div>'); return res.send('Not allowed'); };
const auth = (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  const d = load();
  if (isClient(req)) {
    // client logins: default deny. The page must be on the allowlist AND any website named in the request must be theirs.
    if (!access.customerAllowed(req.method, req.path)) return forbidden(req, res);
    const me = d.users.find((x) => x.id === req.session.uid);
    if (me && me.mustChange && req.path !== '/account' && req.path !== '/logout') { req.session.flash = { t: 'err', m: 'Please choose a new password first.' }; return res.redirect('/account'); }
    const actor = actorOf(req);
    for (const dom of access.domainsIn(req)) { const s = d.sites.find((x) => x.domain === dom); if (!s || !tenancy.owns(actor, s)) { if (req.method === 'PUT') req.resume(); return res.status(404).send('Not found'); } }
    return next();
  }
  if (d.admin.mustChange && !req.path.startsWith('/account') && req.path !== '/logout') { req.session.flash = { t: 'err', m: 'Please change the default password first.' }; return res.redirect('/account'); }
  next();
};
// A job started by a client belongs to that client (only they and the administrator can read its log).
const jobTag = (req) => (isClient(req) ? actorOf(req).tenantId : 'system');
const track = (req, fn) => { const before = c.getJob(); const r = fn(); const after = c.getJob(); if (after && after !== before && !after.end) c.setJobOwner(jobTag(req)); return r; };
const wrap = (fn, back, action) => (req, res) => {
  let ok = true;
  try { const m = track(req, () => fn(req, res)); if (m) req.session.flash = { t: 'ok', m }; } catch (e) { ok = false; req.session.flash = { t: 'err', m: errMsg(e) }; }
  audit(req, (action || req.path) + (ok ? '' : ' FAILED'), req.body.domain || req.body.name || req.body.site || '');
  res.redirect(typeof back === 'function' ? back(req) : back);
};
const awrap = (fn, back, action) => async (req, res) => {
  let ok = true;
  try { const m = await fn(req, res); if (m) req.session.flash = { t: 'ok', m }; } catch (e) { ok = false; req.session.flash = { t: 'err', m: errMsg(e) }; }
  audit(req, (action || req.path) + (ok ? '' : ' FAILED'), req.body.domain || req.body.name || req.body.site || '');
  res.redirect(typeof back === 'function' ? back(req) : back);
};
// the website, if it exists and belongs to the signed-in user (administrators own everything)
const mySite = (req, d, dom) => { const s = S.getSite(d, String(dom || '')); tenancy.assertOwns(actorOf(req), s, 'Site'); return s; };
const mySites = (req, d) => d.sites.filter((s) => tenancy.owns(actorOf(req), s));
const page = (req, res, title, body, opts) => res.send(layout(req, title, body, opts));
const siteBack = (req) => '/sites/manage?' + q({ domain: String(req.body.domain || '') });
const viaDomain = (req) => !!(req.headers['x-hp-proxy'] && safeEq(req.headers['x-hp-proxy'], c.getProxySecret()));

/* ================= login ================= */
const fails = new Map(); let gfails = [];
c.every(300000, () => { const t = Date.now(); for (const [k, v] of fails) { const f = v.filter((x) => t - x < 900000); if (f.length) fails.set(k, f); else fails.delete(k); } });
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  page(req, res, 'Sign in', '<div class="login"><div class="logo">' + ui.svg('logo') + '</div><h1>HostPanel</h1><p class="sub">Sign in to manage your server or website</p><form method="post" action="/login" data-nolock>' + csrf(req) +
    field('Username', '<input name="user" autocomplete="username" required autofocus>') + field('Password', '<input name="pass" type="password" autocomplete="current-password" required>') +
    field('2FA code', '<input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="8" placeholder="Only if 2FA is enabled">') + '<button>Sign in</button></form></div>', { bare: true });
});
app.post('/login', (req, res) => {
  const ipa = c.cleanIp(req), now = Date.now();
  const rec = (fails.get(ipa) || []).filter((t) => now - t < 900000); fails.set(ipa, rec);
  gfails = gfails.filter((t) => now - t < 900000);
  const d = load();
  // The all-visitors lockout (25 failures) must not let strangers lock the real admin out: addresses that have
  // signed in successfully before are exempt from it (they still have the per-address limit of 5).
  const known = d.admin.knownIps.includes(ipa);
  if (rec.length >= 5 || (gfails.length >= 25 && !known)) { req.session.flash = { t: 'err', m: 'Too many failed attempts. Try again in 15 minutes.' }; return res.redirect('/login'); }
  const name = String(req.body.user || '');
  const isAdmin = safeEq(name, d.admin.user);
  let ok, client = null;
  if (isAdmin) {
    ok = bcrypt.compareSync(String(req.body.pass || ''), d.admin.hash);
    if (ok && d.admin.totp) ok = c.totpCheck(d.admin.totp, req.body.code, d);
  } else { client = U.authenticate(name, req.body.pass); ok = !!client; }
  if (!ok) {
    rec.push(now); gfails.push(now); c.authFail(req, req.body.user); audit(req, 'LOGIN_FAIL', '');
    req.session.flash = { t: 'err', m: 'Invalid credentials' }; return res.redirect('/login');
  }
  fails.delete(ipa);
  if (isAdmin) { d.admin.knownIps = [ipa].concat(d.admin.knownIps.filter((x) => x !== ipa)).slice(0, 20); save(d); }
  else U.touchLogin(client.id);
  req.session.regenerate(() => {
    if (isAdmin) { req.session.user = d.admin.user; req.session.role = 'admin'; req.session.sv = d.admin.sv; }
    else { req.session.user = client.username; req.session.role = 'customer'; req.session.uid = client.id; req.session.sv = client.sv; }
    req.session.csrf = rand(16); audit(req, 'LOGIN', ''); res.redirect('/');
  });
});
app.post('/logout', (req, res) => { audit(req, 'LOGOUT', ''); req.session.destroy(() => res.redirect('/login')); });

/* ================= dashboard ================= */
const warmCaches = () => { try { sys.pendingUpdates(true); sys.securityChecks(true); } catch (e) {} };
setTimeout(warmCaches, 8000).unref();
c.every(600000, warmCaches);
const sslBadge = (s) => {
  if (!s.ssl) return s.autoSsl ? badge('SSL pending', 'info') : badge('No SSL', 'warn');
  const dd = sys.certDays(s.domain);
  return badge('SSL' + (dd === null ? '' : ' - ' + dd + 'd'), dd !== null && dd < 14 ? 'err' : 'ok');
};
const typeBadge = (s) => badge(s.type === 'proxy' ? 'Proxy :' + s.port : s.type === 'static' ? 'Static HTML' : s.type === 'laravel' ? 'Laravel' : s.type === 'node' ? 'Node.js :' + s.port : s.type === 'python' ? 'Python :' + s.port : 'PHP ' + s.php);
app.get('/', auth, (req, res) => {
  const d = load();
  if (isClient(req)) {
    const mine = mySites(req, d), myDbs = d.dbs.filter((x) => mine.some((s) => s.domain === x.site));
    const cards = mine.map((s) => '<a class="card" href="/sites/manage?' + q({ domain: s.domain }) + '"><small>' + esc(s.domain) + '</small><div class="big">' + typeBadge(s) + '</div><p>' + sslBadge(s) + '</p></a>').join('');
    return page(req, res, 'Dashboard', '<div class="hero"><h2>Welcome, ' + esc(req.session.user) + '</h2><p>You manage ' + mine.length + ' website' + (mine.length === 1 ? '' : 's') + ' and ' + myDbs.length + ' database' + (myDbs.length === 1 ? '' : 's') + '.</p></div>' +
      (mine.length ? '<div class="grid">' + cards + '</div>' : '<div class="card empty">No website is assigned to your login yet. Please contact your administrator.</div>'));
  }
  const st = sys.stats(), sv = sys.svcStates(), up = sys.updatesPeek(), sec = sys.securityPeek();
  const cpu = Math.min(100, Math.round((parseFloat(st.load) / st.cores) * 100));
  const panelUrl = d.settings.panelSsl && d.settings.panelDomain ? 'https://' + d.settings.panelDomain : 'https://' + (d.settings.ip || 'SERVER-IP') + ':' + PORT;
  const svcs = sys.serviceDefs().map((x) => '<span class="badge ' + (sv[x.n] ? 'ok' : 'err') + '"><i class="dot"></i>' + esc(x.n.replace('.timer', '')) + '</span>').join(' ');
  const score = sec ? Math.round((sec.filter((x) => x.ok).length / sec.length) * 100) : null;
  const hero = '<div class="hero"><h2>Welcome back, ' + esc(d.admin.user) + '</h2><p>Panel address: <span class="mono">' + esc(panelUrl) + '</span>' + (viaDomain(req) ? ' &middot; secured with Let\'s Encrypt' : '') + '</p></div>';
  page(req, res, 'Dashboard', hero +
    '<div class="grid">' + meter('CPU load (' + st.cores + ' cores)', st.load.split(' / ')[0] + ' now', cpu) + meter('Memory', st.ram, st.ramPct) + meter('Disk', st.disk, st.diskPct) + stat('Uptime', st.uptime) + '</div>' +
    '<div class="grid">' + '<a class="card" href="/sites"><small>Websites</small><div class="big">' + d.sites.length + '</div></a><a class="card" href="/databases"><small>Databases</small><div class="big">' + d.dbs.length + '</div></a>' +
    '<a class="card" href="/updates"><small>Updates</small><div class="big ' + (up && up.count ? 'warn' : 'on') + '">' + (up ? (up.count ? up.count + ' pending' : 'Up to date') : 'Checking...') + '</div></a>' +
    '<a class="card" href="/security"><small>Security score</small><div class="big ' + (score === null ? '' : score >= 80 ? 'on' : 'warn') + '">' + (score === null ? 'Checking...' : score + '%') + '</div></a></div>' +
    '<div class="card"><h2>Services</h2><p>' + svcs + '</p></div>');
});

/* ================= websites ================= */
app.get('/sites', auth, (req, res) => {
  const d = load(), list = mySites(req, d);
  const owner = (s) => (s.ownerId && s.ownerId !== 'system' ? (d.users.find((u) => u.id === s.ownerId) || {}).username || '?' : '');
  const rows = list.map((s) => '<tr><td><a href="/sites/manage?' + q({ domain: s.domain }) + '"><b>' + esc(s.domain) + '</b></a></td><td>' + typeBadge(s) + '</td><td>' + sslBadge(s) + '</td>' + (isClient(req) ? '' : '<td>' + (owner(s) ? esc(owner(s)) : '<span class="muted">-</span>') + '</td>') + '<td class="acts">' +
    '<a class="btn g s" href="/sites/manage?' + q({ domain: s.domain }) + '">Manage</a><a class="btn g s" href="/files?' + q({ site: s.domain, p: '/public_html' }) + '">Files</a></td></tr>');
  const head = isClient(req) ? '' : '<div class="sec-h"><h2>Websites</h2><a class="btn" href="/sites/new">New website</a></div>';
  page(req, res, 'Websites', head + (isClient(req) ? '<div class="sec-h"><h2>Your websites</h2></div>' : '') + table(isClient(req) ? ['Domain', 'Type', 'SSL', 'Actions'] : ['Domain', 'Type', 'SSL', 'Client', 'Actions'], rows, isClient(req) ? 'No website is assigned to your login yet.' : 'No websites yet. Press "New website" to create the first one.'));
});
app.post('/sites/delete', auth, wrap((req) => { if (isClient(req)) throw new Error('Not allowed'); return S.deleteSite(String(req.body.domain), req.body.skipBackup === '1', String(req.body.confirm || '')); }, (req) => (c.jobRunning() ? '/tasks' : '/sites'), 'SITE_DELETE'));
app.post('/sites/ssl', auth, wrap((req) => { mySite(req, load(), req.body.domain); return S.queueSsl(String(req.body.domain), String(req.body.email || '').trim(), req.body.force === '1'); }, '/tasks', 'SSL_ISSUE'));
app.post('/sites/ssl/off', auth, wrap((req) => { mySite(req, load(), req.body.domain); return S.sslOff(String(req.body.domain)); }, siteBack, 'SSL_OFF'));
app.post('/sites/php', auth, wrap((req) => { mySite(req, load(), req.body.domain); return S.updatePhp(String(req.body.domain), Object.assign({}, req.body, { basedir: req.body.basedir === '1' })); }, siteBack, 'PHP_UPDATE'));
app.post('/sites/keys', auth, wrap((req) => { mySite(req, load(), req.body.domain); return S.saveKeys(String(req.body.domain), req.body.keys); }, siteBack, 'SFTP_KEYS'));
app.post('/sites/sftp-reset', auth, wrap((req) => { mySite(req, load(), req.body.domain); return S.resetSftpPassword(String(req.body.domain)); }, siteBack, 'SFTP_RESET'));
app.post('/sites/autossl', auth, wrap((req) => { const d = load(), s = mySite(req, d, req.body.domain); s.autoSsl = req.body.on === '1'; if (s.autoSsl) s.sslTry = null; save(d); return 'Auto-SSL ' + (s.autoSsl ? 'on' : 'off'); }, siteBack, 'AUTOSSL'));
app.post('/sites/owner', auth, wrap((req) => { if (isClient(req)) throw new Error('Not allowed'); S.setOwner(String(req.body.domain), String(req.body.ownerId || 'system')); return 'Client access saved'; }, siteBack, 'SITE_OWNER'));
// Node.js / Python applications: start, stop, restart, install dependencies, change the start command
app.post('/sites/app', auth, wrap((req) => {
  const d = load(), s = mySite(req, d, req.body.domain), op = String(req.body.op || '');
  if (!runtime.KINDS[s.type]) throw new Error('This website has no managed application');
  if (op === 'deps') { if (c.jobRunning()) throw new Error('Another task is running (see Tasks page). Try again when it has finished.'); c.runAsync('Install dependencies for ' + s.domain, (log) => runtime.installDeps(s, log)); return 'Installing dependencies - see the Tasks page.'; }
  if (op === 'cmd') { s.cmd = runtime.cleanCmd(req.body.cmd, s.type); save(d); runtime.install(s); return runtime.action(s, 'restart') + ' with the new start command'; }
  return runtime.action(s, op);
}, siteBack, 'SITE_APP'));

app.get('/sites/manage', auth, async (req, res) => {
  const d = load(), dom = String(req.query.domain || '');
  let s; try { s = mySite(req, d, dom); } catch (e) { req.session.flash = { t: 'err', m: errMsg(e) }; return res.redirect('/sites'); }
  const dd = s.ssl ? sys.certDays(dom) : null, php = sys.phpVersions(), cfg = Object.assign(S.defCfg(), s.cfg || {}), client = isClient(req);
  let dnsHtml = '';
  if (req.query.dns === '1') {
    const r = await S.dnsCheck(dom), ip = d.settings.ip, good = ip && r.a.includes(ip);
    dnsHtml = '<div class="flash ' + (good ? 'ok' : 'err') + '">' + (good ? 'DNS is correct: ' + esc(dom) + ' points to this server (' + esc(ip) + ').' :
      'DNS does not point here yet. ' + esc(dom) + ' A record: ' + (esc(r.a.join(', ')) || 'none') + (r.err ? ' (' + esc(r.err) + ')' : '') + '. This server: ' + esc(ip || 'unknown') + '.') +
      (r.www.length ? '' : ' www.' + esc(dom) + ' has no record (the certificate will then cover the main domain only).') + '</div>';
  }
  const isApp = !!runtime.KINDS[s.type];
  const overview = '<div class="card"><h2>Overview</h2><dl class="kv"><dt>Domain</dt><dd><a href="http' + (s.ssl ? 's' : '') + '://' + esc(dom) + '" target="_blank" rel="noopener">' + esc(dom) + '</a></dd><dt>Type</dt><dd>' + esc(s.type === 'proxy' ? 'Reverse proxy to 127.0.0.1:' + s.port : isApp ? runtime.KINDS[s.type].label + ' application on port ' + s.port : s.type) + '</dd>' +
    (s.php ? '<dt>PHP</dt><dd>' + esc(s.php) + '</dd>' : '') + '<dt>Web root</dt><dd class="mono">' + esc((s.docroot || s.root).replace(s.home, '')) + '</dd><dt>Linux user</dt><dd class="mono">' + esc(s.user) + '</dd><dt>Created</dt><dd>' + esc(String(s.created).slice(0, 10)) + '</dd></dl>' +
    '<p></p><div class="row-acts"><a class="btn g s" href="/files?' + q({ site: dom, p: '/public_html' }) + '">File manager</a> <a class="btn g s" href="/databases?' + q({ site: dom }) + '">Databases</a> <a class="btn g s" href="/cron?' + q({ site: dom }) + '">Cron jobs</a> <a class="btn g s" href="/logs?' + q({ site: dom, type: isApp ? 'app' : 'error' }) + '">Logs</a> ' + fbtn(req, '/backups/site', { domain: dom }, 'Backup now', 'g') + ' ' + fbtn(req, '/databases/pma', { domain: dom }, 'phpMyAdmin', 'g') + '</div></div>';
  const ssl = '<div class="card"><h2>SSL certificate (Let\'s Encrypt)</h2><p>' + (s.ssl ? badge('Active' + (dd !== null ? ' - expires in ' + dd + ' days' : ''), dd !== null && dd < 14 ? 'err' : 'ok') + ' Renews automatically (certbot timer).' : badge('Not installed', 'warn') + (s.autoSsl ? ' Auto-SSL is waiting for DNS.' : ' Point the domain to this server (grey cloud if you use Cloudflare), then press Issue certificate.')) + '</p>' +
    '<form class="row" method="post" action="/sites/ssl" data-nolock>' + csrf(req) + '<input type="hidden" name="domain" value="' + esc(dom) + '"><input type="email" name="email" value="' + esc(client ? '' : d.email) + '" placeholder="Email for Let\'s Encrypt" required>' + (s.ssl ? '<input type="hidden" name="force" value="1">' : '') + '<button>' + (s.ssl ? 'Renew now' : 'Issue certificate') + '</button></form>' +
    '<div class="row-acts"><a class="btn g s" href="/sites/manage?' + q({ domain: dom, dns: '1' }) + '">Check DNS</a> ' + fbtn(req, '/sites/autossl', { domain: dom, on: s.autoSsl ? '0' : '1' }, s.autoSsl ? 'Stop auto-retry' : 'Auto-retry hourly', 'g') +
    (s.ssl ? ' ' + fbtn(req, '/sites/ssl/off', { domain: dom }, 'Remove SSL', 'd', 'data-confirm="Remove the certificate? The site will only work over http."') : '') + '</div></div>';
  const phpCard = !S.hasPhp(s.type) ? '' : '<div class="card"><h2>PHP settings</h2><form method="post" action="/sites/php" data-nolock>' + csrf(req) + '<input type="hidden" name="domain" value="' + esc(dom) + '"><div class="fgrid">' +
    field('PHP version', sel('php', php.map((v) => [v, 'PHP ' + v]), s.php)) + field('Memory limit', '<input name="memory" value="' + esc(cfg.memory) + '">') + field('Upload / post limit', '<input name="upload" value="' + esc(cfg.upload) + '">') +
    field('Max execution (sec)', '<input name="exec" type="number" value="' + cfg.exec + '">') + field('Max PHP workers', '<input name="children" type="number" value="' + cfg.children + '">') + '</div>' +
    '<div class="check"><input type="checkbox" id="bd" name="basedir" value="1"' + (cfg.basedir ? ' checked' : '') + '><label for="bd">Restrict PHP to this site\'s folder (open_basedir) - recommended</label></div><button>Save PHP settings</button></form></div>';
  let appCard = '';
  if (isApp) {
    const on = runtime.active(s), hid = (op) => ({ domain: dom, op });
    appCard = '<div class="card"><h2>' + esc(runtime.KINDS[s.type].label) + ' application</h2><p>' + (on ? badge('Running', 'ok') : badge('Stopped', 'err')) + ' <span class="muted">port ' + s.port + ', runs as <span class="mono">' + esc(s.user) + '</span></span></p><div class="row-acts">' +
      fbtn(req, '/sites/app', hid('start'), 'Start', 'g') + fbtn(req, '/sites/app', hid('stop'), 'Stop', 'g') + fbtn(req, '/sites/app', hid('restart'), 'Restart', 'g') + fbtn(req, '/sites/app', hid('deps'), s.type === 'node' ? 'Install dependencies (npm)' : 'Install dependencies (pip)', 'g') + '</div>' +
      '<form class="row" method="post" action="/sites/app" data-nolock>' + csrf(req) + '<input type="hidden" name="domain" value="' + esc(dom) + '"><input type="hidden" name="op" value="cmd"><input name="cmd" class="mono" value="' + esc(s.cmd || '') + '" required><button class="g">Save start command</button></form><p class="muted">Use {PORT} for the port. Output is under Logs.</p></div>';
  }
  const keys = S.getKeys(s);
  const sftp = '<div class="card"><h2>SFTP access</h2><p class="muted">Host: this server &middot; Port 22 &middot; User: <b class="mono">' + esc(s.user) + '</b> &middot; SFTP only (no shell), locked to this site\'s folder.</p>' +
    '<div class="row-acts">' + fbtn(req, '/sites/sftp-reset', { domain: dom }, 'Reset SFTP password', 'g', 'data-confirm="Create a new SFTP password?"') + '</div>' +
    '<form method="post" action="/sites/keys" data-nolock>' + csrf(req) + '<input type="hidden" name="domain" value="' + esc(dom) + '">' + field('Authorized SSH public keys (one per line)', '<textarea name="keys" rows="3" class="mono" placeholder="ssh-ed25519 AAAA... me@laptop">' + esc(keys) + '</textarea>', 'Keys let you use SFTP without a password. Works even when password login is disabled in Settings.') + '<button class="g">Save keys</button></form></div>';
  const clientCard = client ? '' : '<div class="card"><h2>Client access</h2><form class="row" method="post" action="/sites/owner" data-nolock>' + csrf(req) + '<input type="hidden" name="domain" value="' + esc(dom) + '">' +
    sel('ownerId', [['system', 'Nobody - administrator only']].concat(d.users.filter((u) => u.active !== false || u.id === s.ownerId).map((u) => [u.id, u.username + ' (' + u.email + ')'])), s.ownerId || 'system') + '<button class="g">Save</button></form><p class="muted">The client signs in with their own login and can only manage this website. Create logins under <a href="/users">Clients</a>.</p></div>';
  const danger = client ? '' : '<div class="card"><h2>Delete website</h2><p class="muted">Removes the site, its Linux user, PHP pool, nginx config and certificate. A final backup is taken first unless you skip it. Databases are kept.</p>' +
    '<form class="row" method="post" action="/sites/delete" data-typeconfirm="' + esc(dom) + '">' + csrf(req) + '<input type="hidden" name="domain" value="' + esc(dom) + '"><input type="hidden" name="confirm" value=""><div class="check"><input type="checkbox" id="sk" name="skipBackup" value="1"><label for="sk">Skip the final backup</label></div><button class="d">Delete ' + esc(dom) + '</button></form></div>';
  const appRows = (s.apps || []).map((a) => '<li><b>' + esc(a.name) + '</b>' + (a.version ? ' ' + esc(a.version) : '') + ' &middot; ' + (a.url ? '<a href="' + esc(a.url) + '" target="_blank" rel="noopener">' + esc(a.url) + '</a>' : esc(a.path || '/')) + (a.adminUrl ? ' &middot; <a href="' + esc(a.adminUrl) + '" target="_blank" rel="noopener">Admin</a>' : '') + (a.db ? ' &middot; database <span class="mono">' + esc(a.db) + '</span>' : '') + '</li>').join('');
  const installBtns = S.hasPhp(s.type) ? ['wordpress', 'laravel'].filter((a) => (a === 'laravel') === (s.type === 'laravel')).map((a) => '<a class="btn g s" href="/sites/new/' + a + '?' + q({ site: dom }) + '">Install ' + (a === 'laravel' ? 'Laravel' : 'WordPress') + '</a>').join(' ') : '';
  const appsCard = !S.hasPhp(s.type) ? '' : '<div class="card"><h2>Applications</h2>' + (appRows ? '<ul class="plain">' + appRows + '</ul>' : '<p class="muted">No application was installed here with HostPanel.</p>') + '<div class="row-acts">' + installBtns + '</div></div>';
  page(req, res, dom, dnsHtml + '<p><a href="/sites">&larr; All websites</a></p><div class="grid two">' + overview + ssl + appCard + appsCard + phpCard + sftp + clientCard + '</div>' + danger);
});

/* logs */
app.get('/logs', auth, (req, res) => {
  const dom = String(req.query.site || ''), type = ['access', 'php', 'app'].includes(req.query.type) ? req.query.type : 'error';
  try {
    const s = mySite(req, load(), dom);
    const kinds = ['error', 'access'].concat(S.hasPhp(s.type) ? ['php'] : [], runtime.KINDS[s.type] ? ['app'] : []);
    const tabs = '<div class="tabs">' + kinds.map((t) => '<a class="' + (t === type ? 'active' : '') + '" href="/logs?' + q({ site: dom, type: t }) + '">' + t + ' log</a>').join('') + '</div>';
    page(req, res, 'Logs: ' + dom, '<p><a href="/sites/manage?' + q({ domain: dom }) + '">&larr; ' + esc(dom) + '</a></p>' + tabs + '<pre class="log">' + esc(S.tailLog(dom, kinds.includes(type) ? type : 'error')) + '</pre>');
  } catch (e) { req.session.flash = { t: 'err', m: errMsg(e) }; res.redirect('/sites'); }
});

/* ================= backups ================= */
const bkAllowed = (req, d, f) => {
  if (!isClient(req)) return true;
  const m = /^(site|db)-(.+)-\d{14}\.(?:tar\.gz|sql\.gz)$/.exec(f); if (!m) return false;
  const actor = actorOf(req), mine = (dom) => d.sites.some((s) => s.domain === dom && tenancy.owns(actor, s));
  return m[1] === 'site' ? mine(m[2]) : d.dbs.some((x) => x.name === m[2] && x.site && mine(x.site));
};
app.get('/backups', auth, (req, res) => {
  const d = load(), b = d.settings.backup, list = S.listBackups().filter((x) => bkAllowed(req, d, x.f));
  const rows = list.map((x) => '<tr><td class="mono">' + esc(x.f) + '</td><td>' + fmtSize(x.s.size) + '</td><td>' + fmtDate(Math.floor(x.s.mtimeMs / 1000)) + '</td><td class="acts"><a class="btn g s" href="/backups/download?' + q({ f: x.f }) + '">Download</a>' +
    '<form class="in" method="post" action="/backups/restore" data-typeconfirm="' + esc(x.f.replace(/^(site|db)-/, '').replace(/-\d{14}\.(tar\.gz|sql\.gz)$/, '')) + '">' + csrf(req) + '<input type="hidden" name="f" value="' + esc(x.f) + '"><input type="hidden" name="confirm" value=""><button class="s g">Restore</button></form>' +
    fbtn(req, '/backups/delete', { f: x.f }, 'Delete', 'd', 'data-confirm="Delete this backup file?"') + '</td></tr>');
  const sched0 = '<div class="card section"><h2>Scheduled backups</h2><form method="post" action="/backups/schedule" data-nolock>' + csrf(req) + '<div class="fgrid">' +
    field('Enabled', sel('enabled', [['1', 'On'], ['0', 'Off']], b.enabled ? '1' : '0')) + field('Daily at (server hour)', '<input name="hour" type="number" min="0" max="23" value="' + b.hour + '">') + field('Copies to keep', '<input name="keep" type="number" min="1" max="60" value="' + b.keep + '">') +
    field('Off-server copy (rclone)', '<input name="remote" value="' + esc(b.remote) + '" placeholder="r2:my-bucket/hostpanel">', S.hasRclone() ? 'rclone is installed.' : 'Optional. Install rclone and run <span class="mono">rclone config</span> to use S3, Cloudflare R2, Google Drive...') + '</div><button>Save schedule</button> ' +
    '</form><p></p><div class="row-acts">' + fbtn(req, '/backups/all', {}, 'Back up everything now', 'g') + '</div></div>';
  const sched = isClient(req) ? '<p class="muted">Press <b>Backup now</b> on your website or database page to create a backup. Backups are kept for you here.</p>' : sched0;
  page(req, res, 'Backups', sched + '<div class="sec-h"><h2>Backup files</h2><span class="muted">' + list.length + ' file(s) in ' + esc(P.BACKUPS) + '</span></div>' + table(['File', 'Size', 'Created (UTC)', 'Actions'], rows, 'No backups yet.'));
});
app.post('/backups/site', auth, wrap((req) => { mySite(req, load(), req.body.domain); return S.backupSite(String(req.body.domain)); }, '/tasks', 'SITE_BACKUP'));
app.post('/backups/all', auth, wrap((req) => { if (isClient(req)) throw new Error('Not allowed'); return S.backupAll(); }, '/tasks', 'BACKUP_ALL'));
app.post('/backups/schedule', auth, wrap((req) => { if (isClient(req)) throw new Error('Not allowed'); return S.saveBackupSchedule(req.body); }, '/backups', 'BACKUP_SCHEDULE'));
app.post('/backups/restore', auth, wrap((req) => { if (!bkAllowed(req, load(), String(req.body.f))) throw new Error('Backup not found'); return S.restoreBackup(String(req.body.f), String(req.body.confirm || '')); }, '/tasks', 'BACKUP_RESTORE'));
app.post('/backups/delete', auth, wrap((req) => { const f = String(req.body.f); if (!S.BK_RE.test(f) || !bkAllowed(req, load(), f)) throw new Error('Bad file'); fs.unlinkSync(P.BACKUPS + '/' + f); return 'Deleted ' + f; }, '/backups', 'BACKUP_DELETE'));
app.get('/backups/download', auth, (req, res) => {
  const f = String(req.query.f || '');
  if (!S.BK_RE.test(f) || !bkAllowed(req, load(), f) || !fs.existsSync(P.BACKUPS + '/' + f)) return res.status(404).send('Not found');
  audit(req, 'BACKUP_DOWNLOAD', f);
  res.download(P.BACKUPS + '/' + f, f);
});

/* ================= file manager ================= */
const filesUrl = (dom, p) => '/files?' + q({ site: dom, p });
app.get('/files', auth, async (req, res) => {
  const d = load(), dom = String(req.query.site || '');
  if (!dom) return page(req, res, 'File Manager', '<div class="grid">' + (mySites(req, d).map((s) => '<a class="card" href="' + filesUrl(s.domain, '/public_html') + '"><small>Open files</small><div class="big">' + esc(s.domain) + '</div></a>').join('') || '<div class="card empty">No websites yet.</div>') + '</div>');
  let s, rel = normRel(req.query.p), items;
  try { s = mySite(req, d, dom); items = JSON.parse(await fm(s, 'ls', rel)); } catch (e) { req.session.flash = { t: 'err', m: errMsg(e) }; return res.redirect(s && rel !== '/' ? filesUrl(dom, '/') : '/files'); }
  items.sort((a, b) => ((a.t === 'd') !== (b.t === 'd') ? (a.t === 'd' ? -1 : 1) : a.n.toLowerCase().localeCompare(b.n.toLowerCase())));
  const parts = rel.split('/').filter(Boolean);
  const crumbs = '<a href="' + filesUrl(dom, '/') + '">home</a>' + parts.map((x, i) => '<span>/</span><a href="' + filesUrl(dom, '/' + parts.slice(0, i + 1).join('/')) + '">' + esc(x) + '</a>').join('');
  const rows = items.map((it) => {
    const p = path.posix.join(rel, it.n), base = { site: dom, p: rel, name: it.n };
    const nameCell = it.t === 'd' ? '<a href="' + filesUrl(dom, p) + '"><b>' + esc(it.n) + '/</b></a>' : (it.t === 'f' && it.s <= 1048576 ? '<a href="/files/edit?' + q({ site: dom, p }) + '">' + esc(it.n) + '</a>' : esc(it.n) + (it.t === 'l' ? ' &rarr;' : ''));
    const acts = (it.t === 'f' ? '<a class="btn g s" href="/files/download?' + q({ site: dom, p }) + '">Download</a>' : '') +
      (it.t === 'f' && /\.zip$/i.test(it.n) ? fbtn(req, '/files/unzip', base, 'Extract', 'g', 'data-confirm="Extract here (overwrites existing files)?"') : '') +
      fbtn(req, '/files/rename', Object.assign({ to: '' }, base), 'Rename', 'g', 'data-prompt="New name" data-field="to" data-default="' + esc(it.n) + '"') +
      fbtn(req, '/files/chmod', Object.assign({ mode: '' }, base), 'Chmod', 'g', 'data-prompt="Mode (e.g. 644 or 755)" data-field="mode" data-default="' + esc(it.p) + '"') +
      fbtn(req, '/files/delete', base, 'Delete', 'd', 'data-confirm="Delete ' + esc(it.n) + '? This cannot be undone."');
    return '<tr><td>' + nameCell + '</td><td>' + (it.t === 'd' ? '-' : fmtSize(it.s)) + '</td><td>' + fmtDate(it.m) + '</td><td class="mono">' + esc(it.p) + '</td><td class="acts">' + acts + '</td></tr>';
  });
  const hid = '<input type="hidden" name="site" value="' + esc(dom) + '"><input type="hidden" name="p" value="' + esc(rel) + '">';
  const up = rel === '/' ? '' : '<a href="' + filesUrl(dom, path.posix.dirname(rel)) + '">&uarr; Up</a><span>&middot;</span>';
  page(req, res, 'Files: ' + dom, '<div class="crumbs">' + up + crumbs + '</div>' +
    '<div class="upl"><b>Upload</b><input type="file" id="up" multiple data-site="' + esc(dom) + '" data-path="' + esc(rel) + '" data-csrf="' + esc(req.session.csrf) + '"><span id="upstat" class="muted"></span></div>' +
    '<div class="grid two"><form class="row" method="post" action="/files/mkdir">' + csrf(req) + hid + '<input name="name" placeholder="New folder name" required><button class="g">Create folder</button></form>' +
    '<form class="row" method="post" action="/files/touch">' + csrf(req) + hid + '<input name="name" placeholder="New file name" required><button class="g">Create file</button></form></div>' +
    table(['Name', 'Size', 'Modified (UTC)', 'Mode', 'Actions'], rows, 'Empty folder'));
});
const fback = (req) => filesUrl(String(req.body.site), normRel(req.body.p));
const fop = (op, extra) => awrap(async (req) => {
  const s = mySite(req, load(), String(req.body.site)), dir = normRel(req.body.p), name = okName(req.body.name), target = path.posix.join(dir, name);
  if (op === 'rename') { await fm(s, 'rename', target, path.posix.join(dir, okName(req.body.to))); return 'Renamed'; }
  await fm(s, op, target, extra ? extra(req) : ''); return op + ' done';
}, fback, 'FILE_OP');
app.post('/files/mkdir', auth, fop('mkdir'));
app.post('/files/touch', auth, fop('touch'));
app.post('/files/rename', auth, fop('rename'));
app.post('/files/delete', auth, fop('rm'));
app.post('/files/unzip', auth, fop('unzip'));
app.post('/files/chmod', auth, fop('chmod', (req) => String(req.body.mode || '').trim()));
app.get('/files/edit', auth, async (req, res) => {
  const dom = String(req.query.site || ''), rel = normRel(req.query.p);
  try {
    const s = mySite(req, load(), dom), text = JSON.parse(await fm(s, 'read', rel)).c;
    page(req, res, 'Edit: ' + path.posix.basename(rel), '<div class="crumbs mono">' + esc(dom + rel) + '</div><form method="post" action="/files/save" data-nolock>' + csrf(req) + '<input type="hidden" name="site" value="' + esc(dom) + '"><input type="hidden" name="p" value="' + esc(rel) + '">' +
      '<textarea class="ed" name="content" spellcheck="false" wrap="off">' + esc(text) + '</textarea><p><button>Save file</button> <a class="btn g" href="' + filesUrl(dom, path.posix.dirname(rel)) + '">Back to folder</a></p></form>');
  } catch (e) { req.session.flash = { t: 'err', m: errMsg(e) }; res.redirect(filesUrl(dom, path.posix.dirname(rel))); }
});
app.post('/files/save', auth, awrap(async (req) => {
  const s = mySite(req, load(), String(req.body.site)), rel = normRel(req.body.p), text = String(req.body.content || '').replace(/\r\n/g, '\n');
  if (Buffer.byteLength(text) > 1048576) throw new Error('File too large (max 1 MB)');
  await fm(s, 'put', rel, tmpName(), text); return 'Saved ' + rel;
}, (req) => '/files/edit?' + q({ site: String(req.body.site), p: normRel(req.body.p) }), 'FILE_SAVE'));
app.get('/files/download', auth, async (req, res) => {
  try {
    const s = mySite(req, load(), String(req.query.site || '')), rel = normRel(req.query.p), st = JSON.parse(await fm(s, 'stat', rel));
    if (st.t !== 'f') throw new Error('Not a file');
    const fname = path.posix.basename(rel).replace(/[\r\n"]/g, '_');
    res.set({ 'Content-Type': 'application/octet-stream', 'Content-Length': st.s, 'Content-Disposition': 'attachment; filename="' + fname.replace(/[^\x20-\x7e]/g, '_') + '"; filename*=UTF-8\'\'' + encodeURIComponent(fname), 'Content-Security-Policy': 'sandbox' });
    audit(req, 'FILE_DOWNLOAD', s.domain + ':' + rel);
    const child = spawn(process.execPath, [WORKER, 'cat', s.home, rel, ''], Object.assign({ stdio: ['ignore', 'pipe', 'ignore'] }, fmOpts(s)));
    child.stdout.pipe(res);
    res.on('close', () => { try { child.kill('SIGKILL'); } catch (e) {} });
  } catch (e) { res.status(400).send(esc(errMsg(e))); }
});
app.put('/files/upload', auth, (req, res) => {
  let s, target;
  try { s = mySite(req, load(), String(req.query.site || '')); target = path.posix.join(normRel(req.query.p), okName(req.query.name)); } catch (e) { req.resume(); return res.status(400).json({ error: errMsg(e) }); }
  if (parseInt(req.headers['content-length'] || '0', 10) > MAX_UPLOAD) { req.resume(); return res.status(413).json({ error: 'File too large (max 1 GB)' }); }
  try { sys.requireDisk(s.home, 95, 'the upload'); } catch (e) { req.resume(); return res.status(507).json({ error: errMsg(e) }); }
  const tmp = tmpName(), tmpRel = path.posix.join(path.posix.dirname(target), tmp);
  const child = spawn(process.execPath, [WORKER, 'put', s.home, target, tmp], Object.assign({ stdio: ['pipe', 'pipe', 'pipe'] }, fmOpts(s)));
  let err = '', bytes = 0, done = false;
  child.stderr.on('data', (x) => { err += x; });
  child.stdin.on('error', () => {});
  const cleanup = () => { fm(s, 'rm', tmpRel).catch(() => {}); };
  const abort = (code, msg) => { if (done) return; done = true; try { req.unpipe(child.stdin); child.kill('SIGKILL'); } catch (e) {} try { res.status(code).json({ error: msg }); } catch (e) {} setTimeout(cleanup, 300); };
  req.on('data', (x) => { bytes += x.length; if (bytes > MAX_UPLOAD) abort(413, 'File too large (max 1 GB)'); });
  req.on('aborted', () => abort(499, 'Upload aborted'));
  req.pipe(child.stdin);
  child.on('close', (code) => {
    if (done) return; done = true;
    if (code === 0) { audit(req, 'FILE_UPLOAD', s.domain + ':' + target); return res.json({ ok: 1 }); }
    cleanup(); res.status(500).json({ error: err.trim().slice(0, 300) || 'Upload failed' });
  });
});

/* ================= cron ================= */
app.get('/cron', auth, (req, res) => {
  const d = load(), dom = String(req.query.site || '');
  if (!dom) return page(req, res, 'Cron Jobs', '<div class="grid">' + (mySites(req, d).map((s) => '<a class="card" href="/cron?' + q({ site: s.domain }) + '"><small>Edit crontab</small><div class="big">' + esc(s.domain) + '</div></a>').join('') || '<div class="card empty">No websites yet.</div>') + '</div>');
  try {
    mySite(req, load(), dom); const r = S.getCron(dom);
    page(req, res, 'Cron: ' + dom, '<p class="muted">Runs as the Linux user <b class="mono">' + esc(r.s.user) + '</b>. Use full paths (for example /usr/bin/php).</p><form method="post" action="/cron/save" data-nolock>' + csrf(req) + '<input type="hidden" name="domain" value="' + esc(dom) + '">' +
      '<textarea class="ed" name="content" spellcheck="false" wrap="off">' + esc(r.text) + '</textarea><p><button>Save crontab</button></p></form>');
  } catch (e) { req.session.flash = { t: 'err', m: errMsg(e) }; res.redirect('/cron'); }
});
app.post('/cron/save', auth, wrap((req) => { mySite(req, load(), req.body.domain); return S.saveCron(String(req.body.domain), req.body.content); }, (req) => '/cron?' + q({ site: String(req.body.domain) }), 'CRON_SAVE'));

/* ================= updates ================= */
function releaseHtml(req) {
  let body;
  if (!updater) body = '<p class="muted">The release updater is not available on this install.</p>';
  else {
    const last = updater.getLast(), lr = updater.lastResult();
    const lines = [];
    lines.push('<p>Installed: <b>v' + esc(VERSION) + '</b> &middot; Source: <span class="mono">github.com/therealkiranda/hostpanel</span> (signed releases only)</p>');
    if (!updater.hasKey()) lines.push('<p>' + badge('No signing key', 'warn') + ' <span class="muted">This install has no <span class="mono">lib/release-key.pub</span>, so it can look for new releases but will never install one.</span></p>');
    if (!last) lines.push('<p class="muted">Not checked yet.</p>');
    else if (last.error && !last.newer) lines.push('<p>' + badge('Check failed', 'err') + ' ' + esc(last.error) + '</p>');
    else if (last.newer) lines.push('<p>' + badge('v' + last.latest + ' available', last.verified ? 'ok' : 'warn') + ' ' + (last.verified ? 'Signature verified.' : esc(last.error || 'Not verified - it will not be installed.')) + '</p>');
    else lines.push('<p>' + badge('Up to date', 'ok') + ' <span class="muted">checked ' + esc(new Date(last.checkedAt).toISOString().slice(0, 16).replace('T', ' ')) + ' UTC</span></p>');
    if (lr) lines.push('<p class="muted">Last update attempt: <b>' + esc(lr.status) + '</b> (v' + esc(lr.version) + ', ' + esc(lr.time) + ')' + (lr.status === 'rolled-back' ? ' - the new version did not start, so the previous one was restored.' : '') + '</p>');
    let acts = fbtn(req, '/updates/release/check', {}, 'Check GitHub for a new version', 'g');
    if (last && last.newer && last.verified && updater.hasKey()) acts += fbtn(req, '/updates/release/apply', { version: last.latest }, 'Install v' + esc(last.latest), '', 'data-confirm="Install HostPanel v' + esc(last.latest) + ' now? The panel restarts, and rolls back by itself if the new version does not start. Websites keep running."');
    body = lines.join('') + '<div class="row-acts">' + acts + '</div>';
  }
  return '<div class="card section"><h2>HostPanel release</h2>' + body + '</div>';
}
app.get('/updates', auth, (req, res) => {
  const releaseCard = releaseHtml(req), up = sys.pendingUpdates(), last = sys.lastAptUpdate(), reboot = fs.existsSync('/var/run/reboot-required'), auto = sys.autoUpdatesOn();
  page(req, res, 'Updates', releaseCard + '<div class="grid">' + stat('Pending updates', up.count + ' (' + up.security + ' security)', up.count ? 'warn' : 'on') + stat('Package lists refreshed', last ? fmtDate(last) + ' UTC' : 'unknown') +
    stat('Auto security updates', auto ? 'ON' : 'OFF', auto ? 'on' : 'off') + stat('Reboot required', reboot ? 'YES' : 'No', reboot ? 'warn' : 'on') + '</div>' +
    '<div class="card section"><div class="row-acts">' + fbtn(req, '/updates/refresh', {}, 'Check for updates', 'g') + fbtn(req, '/updates/install', {}, 'Install all updates', '', 'data-confirm="Install all pending updates now?"') +
    fbtn(req, '/updates/auto', { on: auto ? '0' : '1' }, auto ? 'Disable auto updates' : 'Enable auto updates', 'g') +
    (reboot ? fbtn(req, '/updates/reboot', {}, 'Reboot server', 'd', 'data-confirm="Reboot the server now? Websites will be down for about a minute."') : '') + '</div></div>' +
    '<div class="sec-h"><h2>Pending packages</h2></div><pre class="log">' + esc(up.list.join('\n') || 'Everything is up to date.') + '</pre>');
});
app.post('/updates/refresh', auth, wrap(() => { c.runSteps('Check for updates', [['apt-get', ['update']]], () => sys.invalidateUpdates()); return 'Started - see Tasks page'; }, '/tasks', 'UPD_REFRESH'));
app.post('/updates/install', auth, wrap(() => {
  c.runSteps('Install system updates', [['apt-get', ['update']], ['apt-get', ['-y', '-o', 'Dpkg::Options::=--force-confold', 'upgrade']], ['apt-get', ['-y', 'autoremove']]], () => { sys.invalidateUpdates(); sys.clearSecCache(); });
  return 'Update started - see Tasks page';
}, '/tasks', 'UPD_INSTALL'));
app.post('/updates/release/check', auth, awrap(async () => {
  if (!updater) throw new Error('The release updater is not available on this install');
  const r = await updater.check();
  if (r.error && !r.newer) throw new Error(r.error);
  return r.newer ? 'Version ' + r.latest + ' is available' + (r.verified ? ' (signature verified)' : '') : 'HostPanel is up to date (v' + VERSION + ')';
}, '/updates', 'UPD_RELEASE_CHECK'));
app.post('/updates/release/apply', auth, wrap((req) => {
  if (!updater) throw new Error('The release updater is not available on this install');
  const last = updater.getLast();
  if (!last || last.latest !== String(req.body.version) || !last.verified) throw new Error('Check for updates first, then install the verified release');
  updater.startUpdate(c.runAsync);
  return 'Update started - see Tasks page. The panel restarts when it is done.';
}, '/tasks', 'UPD_RELEASE'));
app.post('/updates/auto', auth, wrap((req) => { sys.setAutoUpdates(req.body.on === '1'); sys.clearSecCache(); return 'Automatic security updates ' + (req.body.on === '1' ? 'enabled' : 'disabled'); }, '/updates', 'UPD_AUTO'));
app.post('/updates/reboot', auth, wrap(() => { setTimeout(() => { try { sh('systemctl', ['reboot']); } catch (e) {} }, 1500); return 'Rebooting... reload this page in about a minute.'; }, '/updates', 'REBOOT'));

/* ================= security ================= */
app.get('/security', auth, (req, res) => {
  const list = sys.securityChecks(req.query.refresh === '1'), good = list.filter((x) => x.ok).length, score = Math.round((good / list.length) * 100);
  const rows = list.map((x) => '<div class="chk"><span class="mark ' + (x.ok ? 'ok' : (x.level === 'info' ? 'info' : 'err')) + '">' + (x.ok ? '&#10003;' : (x.level === 'info' ? 'i' : '!')) + '</span><div><b>' + esc(x.name) + '</b><small>' + esc(x.detail) + '</small></div></div>').join('');
  const jails = sys.f2bJails();
  const jrows = jails.map((j) => '<tr><td><b>' + esc(j.jail) + '</b></td><td>' + j.total + '</td><td class="mono">' + (j.banned.map((ip) => esc(ip) + ' ' + fbtn(req, '/security/unban', { jail: j.jail, ip }, 'Unban', 'g')).join('<br>') || '<span class="muted">none</span>') + '</td></tr>');
  page(req, res, 'Security', '<div class="grid"><div class="card"><small>Security score</small><div class="score ' + (score >= 80 ? 'on' : 'warn') + '">' + score + '%</div><div class="bar' + (score < 60 ? ' hot' : '') + '"><i data-w="' + score + '"></i></div></div>' +
    '<div class="card"><small>Checks passed</small><div class="big">' + good + ' / ' + list.length + '</div><p></p><a class="btn g s" href="/security?refresh=1">Re-run checks</a></div></div>' +
    '<div class="wrap section">' + rows + '</div><div class="sec-h"><h2>Fail2ban</h2></div>' + table(['Jail', 'Total bans', 'Currently banned'], jrows, 'Fail2ban is not running') +
    '<div class="sec-h"><h2>Firewall (ufw)</h2></div><pre class="log">' + esc(sys.ufwStatus()) + '</pre>');
});
app.post('/security/unban', auth, wrap((req) => sys.f2bUnban(String(req.body.jail), String(req.body.ip)), '/security', 'UNBAN'));

/* ================= services / tasks / audit ================= */
app.get('/services', auth, (req, res) => {
  const sv = sys.svcStates(true);
  const rows = sys.serviceDefs().map((x) => '<tr><td><b>' + esc(x.n) + '</b></td><td>' + badge(sv[x.n] ? 'running' : 'stopped', sv[x.n] ? 'ok' : 'err') + '</td><td class="acts">' +
    (x.a.length ? x.a.map((a) => fbtn(req, '/services/action', { name: x.n, action: a }, a, a === 'stop' ? 'd' : 'g', a === 'stop' ? 'data-confirm="Stop ' + esc(x.n) + '?"' : '')).join('') : '<span class="muted">status only</span>') + '</td></tr>');
  page(req, res, 'Services', table(['Service', 'Status', 'Actions'], rows) + '<p class="muted">The firewall and SSH are status-only here on purpose, so a click can never lock you out.</p>');
});
app.post('/services/action', auth, wrap((req) => {
  const n = String(req.body.name), a = String(req.body.action), def = sys.serviceDefs().find((x) => x.n === n);
  if (!def || !def.a.includes(a)) throw new Error('Not allowed');
  if (n === 'hostpanel') { setTimeout(() => { try { sh('systemctl', ['restart', 'hostpanel']); } catch (e) {} }, 800); return 'Panel restarting...'; }
  sh('systemctl', [a, n]); sys.svcStates(true); return n + ': ' + a + ' done';
}, '/services', 'SERVICE'));
app.get('/tasks', auth, (req, res) => {
  let j = c.getJob(), running = c.jobRunning();
  if (j && isClient(req) && j.owner !== actorOf(req).tenantId) { j = null; running = false; }
  page(req, res, 'Tasks', j ? '<div class="card section"><div class="sec-h"><div><b>' + esc(j.label) + '</b><div class="muted">Started ' + esc(new Date(j.start).toISOString().slice(0, 19).replace('T', ' ')) + ' UTC</div></div>' +
    (running ? badge('running', 'warn') + '<span data-refresh="3000"></span>' : (j.code === 0 ? badge('finished', 'ok') : badge('failed (exit ' + j.code + ')', 'err'))) + '</div></div><pre class="log">' + esc(j.log.trim() || 'Starting...') + '</pre>' : '<div class="card empty">No background task has run since the panel started.</div>');
});
app.get('/audit', auth, (req, res) => {
  let lines = []; try { lines = fs.readFileSync(P.AUDIT, 'utf8').trim().split('\n').slice(-200).reverse(); } catch (e) {}
  page(req, res, 'Audit Log', '<p class="muted">Last 200 actions (UTC).</p><pre class="log">' + esc(lines.join('\n') || 'Empty') + '</pre>');
});

/* ================= settings ================= */
app.get('/settings', auth, (req, res) => {
  const d = load(), st = d.settings, ip = st.ip || 'YOUR-SERVER-IP', me = c.cleanIp(req);
  const domCard = '<div class="card"><h2>Panel domain</h2>' + (st.panelDomain ? '<p>' + (st.panelSsl ? badge('Live with SSL', 'ok') : badge('Waiting for certificate', 'warn')) + ' <a href="https://' + esc(st.panelDomain) + '" target="_blank" rel="noopener">https://' + esc(st.panelDomain) + '</a></p>' : '<p class="muted">Use a nice address like <span class="mono">panel.yourdomain.com</span> instead of IP:' + PORT + '.</p>') +
    '<ol class="steps"><li>Create a DNS <b>A record</b>: <span class="mono">panel.yourdomain.com &rarr; ' + esc(ip) + '</span> (turn the Cloudflare proxy OFF, grey cloud).</li><li>Enter it below. The panel gets a free Let\'s Encrypt certificate.</li></ol>' +
    '<form class="row" method="post" action="/settings/panel-domain" data-nolock>' + csrf(req) + '<input name="domain" value="' + esc(st.panelDomain) + '" placeholder="panel.yourdomain.com" required><input type="email" name="email" value="' + esc(d.email) + '" placeholder="Email for Let\'s Encrypt" required><button>' + (st.panelDomain ? 'Update domain' : 'Enable domain') + '</button></form>' +
    (st.panelDomain ? fbtn(req, '/settings/panel-domain/remove', {}, 'Remove panel domain', 'd', 'data-confirm="Remove the panel domain? You can still use the IP and port ' + PORT + '."') : '') + '</div>';
  const directCard = '<div class="card"><h2>Direct access (IP:' + PORT + ')</h2><p class="muted">' + (st.directIps.length ? 'Port ' + PORT + ' only accepts the addresses below. The panel domain still works from anywhere.' : 'Port ' + PORT + ' is open to everyone. After your panel domain works, you can limit it to your own IP.') + '</p>' +
    '<form method="post" action="/settings/direct" data-nolock>' + csrf(req) + field('Allowed IPs (one per line or comma separated)', '<textarea name="ips" rows="3" class="mono" placeholder="203.0.113.7">' + esc(st.directIps.join('\n')) + '</textarea>', 'Your current IP: <span class="mono">' + esc(me) + '</span>. Leave empty to open the port to everyone. Requires the panel domain with working SSL first.') + '<button>Save</button></form>' +
    '<p class="muted">Locked out? On the server run: <span class="mono">sudo hostpanel-cli open-port</span></p></div>';
  const emailCard = '<div class="card"><h2>Let\'s Encrypt email</h2><p class="muted">Used for certificate expiry notices and as the default for new websites.</p><form class="row" method="post" action="/settings/email">' + csrf(req) + '<input type="email" name="email" value="' + esc(d.email) + '" placeholder="you@example.com" required><button>Save</button></form></div>';
  const polCard = '<div class="card"><h2>PHP security policy</h2><form method="post" action="/settings/php-policy">' + csrf(req) + field('Disabled PHP functions', sel('policy', [['strict', 'Strict (blocks exec, proc_open, shell_exec, system, passthru ...) - recommended'], ['standard', 'Standard (blocks shell_exec, system, passthru, popen ...)']], st.phpPolicy), 'Use Standard only if a plugin (for example an image optimizer or backup plugin) needs exec().') + '<button>Apply to all PHP versions</button></form></div>';
  const sftpCard = '<div class="card"><h2>SFTP password login</h2><p class="muted">Site users can only use SFTP (no shell). Turn passwords off to allow SSH keys only (add keys on each website page).</p><form class="row" method="post" action="/settings/sftp">' + csrf(req) + sel('on', [['1', 'Passwords allowed'], ['0', 'SSH keys only']], st.sftpPassword ? '1' : '0') + '<button>Save</button></form></div>';
  const toolsCard = '<div class="card"><h2>Server tools</h2><p class="muted">Extra software HostPanel can add with one click. Each runs as a visible task.</p>' + Object.keys(tools.TOOLS).map((id) => { const t = tools.TOOLS[id], on = t.ready(); return '<div class="row-acts"><b>' + esc(t.label) + '</b> ' + (on ? badge('Installed', 'ok') : badge('Not installed', 'warn')) + ' <span class="muted">' + esc(t.summary) + '</span> ' + (on ? '' : fbtn(req, '/tools/install', { id }, 'Install', 'g', 'data-confirm="Install ' + esc(t.label) + ' now?"')) + '</div>'; }).join('') + '</div>';
  page(req, res, 'Settings', '<div class="grid two">' + domCard + directCard + emailCard + polCard + sftpCard + toolsCard + '</div>');
});
app.post('/settings/panel-domain', auth, wrap((req) => S.setPanelDomain(req.body.domain, req.body.email), '/tasks', 'PANEL_DOMAIN'));
app.post('/settings/panel-domain/remove', auth, wrap(() => S.removePanelDomain(), '/settings', 'PANEL_DOMAIN_REMOVE'));
app.post('/settings/direct', auth, wrap((req) => S.setDirect(S.cleanIpList(req.body.ips)), '/settings', 'DIRECT_ACCESS'));
app.post('/settings/email', auth, wrap((req) => { const e = String(req.body.email || '').trim(); if (!S.EMAIL_RE.test(e)) throw new Error('Invalid email'); const d = load(); d.email = e; save(d); return 'Saved'; }, '/settings', 'EMAIL'));
app.post('/settings/php-policy', auth, wrap((req) => S.setPhpPolicy(String(req.body.policy)), '/settings', 'PHP_POLICY'));
app.post('/settings/sftp', auth, wrap((req) => S.setSftpPassword(req.body.on === '1'), '/settings', 'SFTP_POLICY'));

/* ================= new website wizards, databases, clients ================= */
const apps = createApps({ S, c, sys, exec: siteexec });
const ctx = { app, auth, page, csrf, esc, badge, fbtn, field, sel, table, q, c, load, save, audit, apps, sys, S, wrap, rand };
require('./lib/routes/wizard')(ctx);
require('./lib/routes/databases')(ctx);
require('./lib/routes/users')(ctx);

/* ================= account (a client only changes their own password) ================= */
app.get('/account', auth, (req, res, next) => {
  if (!isClient(req)) return next();
  const me = load().users.find((x) => x.id === req.session.uid);
  page(req, res, 'Account', '<div class="card section"><h2>Your account</h2><dl class="kv"><dt>Username</dt><dd class="mono">' + esc(me.username) + '</dd><dt>Email</dt><dd>' + esc(me.email) + '</dd></dl></div>' +
    '<div class="card section"><h2>Change password</h2>' + (me.mustChange ? '<p>' + badge('Required', 'warn') + ' Please choose a new password before you continue.</p>' : '') + '<form method="post" action="/account" data-nolock>' + csrf(req) +
    '<div class="fgrid">' + field('Current password', '<input type="password" name="current" autocomplete="current-password" required>') + field('New password', '<input type="password" name="password" minlength="12" autocomplete="new-password" required>', 'At least 12 characters.') + field('Repeat new password', '<input type="password" name="again" minlength="12" autocomplete="new-password" required>') + '</div><button>Change password</button></form></div>');
});
app.post('/account', auth, (req, res, next) => {
  if (!isClient(req)) return next();
  let ok = true;
  try {
    const d = load(), me = d.users.find((x) => x.id === req.session.uid);
    if (!bcrypt.compareSync(String(req.body.current || ''), me.passwordHash)) throw new Error('Current password is wrong');
    if (String(req.body.password) !== String(req.body.again)) throw new Error('The new passwords do not match');
    if (String(req.body.password) === String(req.body.current)) throw new Error('Choose a password you have not used');
    req.session.sv = U.setPassword(me.id, req.body.password, false);
    req.session.flash = { t: 'ok', m: 'Password changed' };
  } catch (e) { ok = false; req.session.flash = { t: 'err', m: errMsg(e) }; }
  audit(req, 'ACCOUNT_PASSWORD' + (ok ? '' : ' FAILED'), '');
  res.redirect(ok ? '/' : '/account');
});
/* ================= account routes (extracted module) ================= */
require('./lib/routes/account')({ app, auth, page, csrf, esc, badge, fbtn, field, rand, c, sys, load, save, bcrypt, wrap, audit });

/* ================= fallbacks ================= */
app.use((req, res) => { if (!req.session.user) return res.status(404).send('Not found'); res.status(404); page(req, res, 'Not found', '<div class="card empty"><h2>404</h2><p>That page does not exist.</p><a class="btn" href="/">Back to dashboard</a></div>'); });
app.use((err, req, res, next) => { res.status(err && err.status >= 400 && err.status < 500 ? err.status : 500).send('Request error'); });

/* ================= schedulers + start ================= */
// async route handlers must never be able to take the whole panel down
process.on('unhandledRejection', (e) => { try { c.auditSys('UNHANDLED_REJECTION', errMsg(e)); } catch (x) {} });
if (IS_ROOT) { c.every(60000, S.scheduledBackup); c.every(300000, S.autoSslTick); setTimeout(pma.refreshIfEnabled, 15000).unref(); c.every(3600000, pma.refreshIfEnabled); }
const server = https.createServer({ key: fs.readFileSync(P.DATA + '/panel.key'), cert: fs.readFileSync(P.DATA + '/panel.crt'), minVersion: 'TLSv1.2' }, app);
server.requestTimeout = 30 * 60 * 1000; server.headersTimeout = 30000;
server.listen(PORT, process.env.PANEL_HOST || '0.0.0.0', () => console.log('HostPanel ' + VERSION + ' on https://' + (process.env.PANEL_HOST || '0.0.0.0') + ':' + PORT));
