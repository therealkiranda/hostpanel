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
      message = S.createSite({ domain, type: app.siteType, php: form.php, email: form.email, autoSsl: https ? '1' : '' }, { deferSsl: true });
    } else if (https && !site.ssl && !site.autoSsl) {
      const d2 = c.load(), s2 = S.getSite(d2, domain); s2.autoSsl = true; s2.sslTry = null; c.save(d2);   // retried automatically once the job is done
      message = 'Auto-SSL turned on for ' + domain + ' (needs a Let\'s Encrypt email in Settings and DNS pointing here).';
    }
    c.runAsync('Install ' + app.name + ' on ' + domain + (path ? '/' + path : ''), async (log) => {
      const result = await engine.installApp(app, input, createHost(deps, log), log);
      log('\nDONE: ' + app.name + (result.meta && result.meta.version ? ' ' + result.meta.version : '') + ' is ready.');
      log('Open:  ' + (result.url || ''));
      if (result.adminUrl) log('Admin: ' + result.adminUrl + '   (user: ' + (result.meta && result.meta.adminUser) + ')');
      if (https) log('HTTPS: the address above only works once the Let\'s Encrypt certificate is issued (DNS must point to this server; auto-SSL tries within a few minutes).');
      c.auditSys('APP_INSTALL_DONE', app.id + ' ' + domain);
    });
    return (message ? message + '\n\n' : '') + app.name + ' installation started. Follow it on the Tasks page - it takes a minute or two.';
  }

  return { list: catalog.list, get: catalog.get, installed, eligibleSites, start, NEW };
}

module.exports = { createApps, NEW };
