'use strict';
// Glue between the web UI and the installer: turns a submitted wizard form into (optionally) a new website plus a background
// installation job. All checks that can fail cheaply run BEFORE the website is created, so a typo never leaves clutter.
const catalog = require('./catalog');
const engine = require('./engine');
const stable = require('./stable');
const tenancy = require('../tenancy');
const dbs = require('../dbs');
const { createHost } = require('./host');

const truthy = (v) => v === true || v === '1' || v === 'on';
const NEW = '__new__';

// The pieces start() needs from the rest of the panel; injected so tests can drive it without a server.
function createApps(deps) {
  const { S, c, sys } = deps;

  const installed = (actor) => {
    const rows = [];
    for (const s of c.load().sites) { if (actor && !tenancy.owns(actor, s)) continue; for (const a of s.apps || []) rows.push(Object.assign({ domain: s.domain }, a)); }
    return rows.sort((a, b) => String(b.installedAt).localeCompare(String(a.installedAt)));
  };

  // Sites an application can be installed on (right type); a client only sees their own websites.
  const eligibleSites = (app, d, actor) => d.sites.filter((s) => app.siteTypes.includes(s.type) && (!actor || tenancy.owns(actor, s)));

  // actor: { role, tenantId, id } of the signed-in user. Clients may only install onto an existing website of their own.
  async function start(form, actor) {
    const app = catalog.get(form.app);
    if (!app) throw new Error('Unknown application');
    if (c.jobRunning()) throw new Error('Another task is running (see Tasks page). Try again when it has finished.');
    sys.requireDisk(c.P.HOMES, 90, 'the installation');
    const d = c.load();
    const isCustomer = !!actor && actor.role === 'customer';
    const isNew = String(form.target || NEW) === NEW;
    if (isNew && isCustomer) throw new Error('Only the administrator can create new websites');
    const https = truthy(form.https);
    const path = app.subfolder ? engine.cleanSubdir(form.path) : '';
    let domain, site = null;
    if (isNew) {
      domain = String(form.domain || '').trim().toLowerCase().replace(/^www\./, '');
      if (!S.DOMAIN_RE.test(domain)) throw new Error('Enter a valid domain, for example example.com');
      if (d.sites.some((x) => x.domain === domain)) throw new Error('A website with that domain already exists');
    } else {
      site = S.getSite(d, String(form.target));
      if (actor) tenancy.assertOwns(actor, site, 'Website');
      domain = site.domain;
    }
    const input = Object.assign({}, form, { domain, path, https });
    app.handler.validate(input, app);                                    // fail on bad input before creating anything

    const phpVersion = isNew ? String(form.php || '') : String(site.php || '');
    if (isCustomer && d.dbs.filter((x) => x.site === domain).length >= dbs.MAX_DBS_CUSTOMER) throw new Error('This website already has the maximum number of databases');
    // Stable only: look up the newest stable release; refuse early when the website's PHP is too old for it.
    const st = await stable.latest(app.id, deps.stableOpts).catch(() => null);
    if (st && st.php && /^\d+\.\d+$/.test(phpVersion) && !stable.phpAtLeast(phpVersion, st.php)) throw new Error(app.name + ' ' + st.version + ' needs PHP ' + st.php + ' or newer, but this website uses PHP ' + phpVersion + '. Choose a newer PHP version.');

    const host = createHost(deps);
    if (!isNew) { // fail fast on a wrong site type / non-empty folder, with no side effects
      if (!app.siteTypes.includes(site.type)) throw new Error(app.name + ' needs a ' + app.siteTypes.join(' / ') + ' website; ' + domain + ' is "' + site.type + '"');
      if ((site.apps || []).some((a) => a.id === app.id && (a.path || '') === path)) throw new Error(app.name + ' is already installed there');
      await host.inspectTarget(site, path, app);
      if (c.jobRunning()) throw new Error('Another task is running (see Tasks page). Try again when it has finished.');
    }

    let message = '';
    if (isNew) {
      message = S.createSite({ domain, type: app.siteType, php: form.php, ownerId: form.ownerId || 'system' });   // no certificate is requested: issue it from the site's SSL section
    }
    c.runAsync('Install ' + app.name + ' on ' + domain + (path ? '/' + path : ''), async (log) => {
      const result = await engine.installApp(app, input, createHost(deps, log), log);
      log('\nDONE: ' + app.name + (result.meta && result.meta.version ? ' ' + result.meta.version : '') + ' is ready.');
      log('Open:  ' + (result.url || ''));
      if (result.adminUrl) log('Admin: ' + result.adminUrl + '   (user: ' + (result.meta && result.meta.adminUser) + ')');
      if (https && !(() => { try { return !!S.getSite(c.load(), domain).ssl; } catch (e) { return false; } })()) log('HTTPS: now open the website in HostPanel -> Manage -> SSL certificate and press Issue certificate (DNS must point to this server). Until then the browser shows a certificate warning.');
      c.auditSys('APP_INSTALL_DONE', app.id + ' ' + domain);
    });
    c.setJobOwner(isCustomer ? actor.tenantId : 'system');
    return (message ? message + '\n\n' : '') + app.name + ' installation started. Follow it on the Tasks page - it takes a minute or two.';
  }

  return { list: catalog.list, get: catalog.get, installed, eligibleSites, start, NEW };
}

module.exports = { createApps, NEW };
