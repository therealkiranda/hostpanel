'use strict';
// Glue between the web UI and the installer: turns a submitted form into (optionally) a new website plus a background
// installation job. All checks that can fail cheaply run BEFORE the website is created, so a typo never leaves clutter.
const catalog = require('./catalog');
const engine = require('./engine');
const { createHost } = require('./host');

const truthy = (v) => v === true || v === '1' || v === 'on';
const NEW = '__new__';

// The pieces start() needs from the rest of the panel; injected so tests can drive it without a server.
function createApps(deps) {
  const { S, c, sys } = deps;

  const installed = () => {
    const rows = [];
    for (const s of c.load().sites) for (const a of s.apps || []) rows.push(Object.assign({ domain: s.domain }, a));
    return rows.sort((a, b) => String(b.installedAt).localeCompare(String(a.installedAt)));
  };

  // Sites an application can be installed on (right type, and not already holding that app in its root).
  const eligibleSites = (app, d) => d.sites.filter((s) => app.siteTypes.includes(s.type));

  async function start(form) {
    const app = catalog.get(form.app);
    if (!app) throw new Error('Unknown application');
    if (c.jobRunning()) throw new Error('Another task is running (see Tasks page). Try again when it has finished.');
    sys.requireDisk(c.P.HOMES, 90, 'the installation');
    const d = c.load();
    const isNew = String(form.target || NEW) === NEW;
    const https = truthy(form.https);
    const path = app.subfolder ? engine.cleanSubdir(form.path) : '';
    let domain, site = null;
    if (isNew) {
      domain = String(form.domain || '').trim().toLowerCase().replace(/^www\./, '');
      if (!S.DOMAIN_RE.test(domain)) throw new Error('Enter a valid domain, for example example.com');
    } else {
      site = S.getSite(d, String(form.target));
      domain = site.domain;
    }
    const input = Object.assign({}, form, { domain, path, https });
    app.handler.validate(input, app);                                    // fail on bad input before creating anything

    const host = createHost(deps);
    if (!isNew) { // fail fast on a wrong site type / non-empty folder, with no side effects
      if (!app.siteTypes.includes(site.type)) throw new Error(app.name + ' needs a ' + app.siteTypes.join(' / ') + ' website; ' + domain + ' is "' + site.type + '"');
      if ((site.apps || []).some((a) => a.id === app.id && (a.path || '') === path)) throw new Error(app.name + ' is already installed there');
      await host.inspectTarget(site, path, app);
      if (c.jobRunning()) throw new Error('Another task is running (see Tasks page). Try again when it has finished.');
    }

    let message = '';
    if (isNew) {
      message = S.createSite({ domain, type: app.siteType, php: form.php });   // no certificate is requested: issue it from the site's SSL section
    }
    c.runAsync('Install ' + app.name + ' on ' + domain + (path ? '/' + path : ''), async (log) => {
      const result = await engine.installApp(app, input, createHost(deps, log), log);
      log('\nDONE: ' + app.name + (result.meta && result.meta.version ? ' ' + result.meta.version : '') + ' is ready.');
      log('Open:  ' + (result.url || ''));
      if (result.adminUrl) log('Admin: ' + result.adminUrl + '   (user: ' + (result.meta && result.meta.adminUser) + ')');
      if (https && !(() => { try { return !!S.getSite(c.load(), domain).ssl; } catch (e) { return false; } })()) log('HTTPS: now open the website in HostPanel -> Manage -> SSL certificate and press Issue certificate (DNS must point to this server). Until then the browser shows a certificate warning.');
      c.auditSys('APP_INSTALL_DONE', app.id + ' ' + domain);
    });
    return (message ? message + '\n\n' : '') + app.name + ' installation started. Follow it on the Tasks page - it takes a minute or two.';
  }

  return { list: catalog.list, get: catalog.get, installed, eligibleSites, start, NEW };
}

module.exports = { createApps, NEW };
