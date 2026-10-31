'use strict';
// App installer coordinator. It owns the ORDER of operations and the rollback; every side effect is an injected
// "host" adapter (lib/apps/host.js in production, fakes in the tests), so a failed install can be tested without
// touching a real server. Handlers (lib/apps/wordpress.js ...) only describe what is specific to one application.
//
// Safety rules enforced here, for every app:
//  - all input is validated BEFORE anything is created;
//  - the target folder must be empty (or only hold HostPanel's own placeholder page) - nothing is ever overwritten;
//  - if any step fails, only what THIS attempt created is removed (database, files, new folder); the website
//    itself, its Linux user, nginx config and certificate are left alone so the install can simply be retried.
const SUBDIR_RE = /^[a-z0-9][a-z0-9_-]{0,30}$/;
const RESERVED_SUBDIRS = new Set(['tmp', 'logs', 'cgi-bin']);

// '' (site root) or a single lower-case folder name such as "blog". Never nested, never dotted: no traversal possible.
function cleanSubdir(value) {
  const v = String(value == null ? '' : value).trim().replace(/^\/+|\/+$/g, '').toLowerCase();
  if (!v) return '';
  if (!SUBDIR_RE.test(v) || RESERVED_SUBDIRS.has(v)) throw new Error('Folder must be one name made of a-z, 0-9, "-" or "_" (for example: blog), or empty for the site root');
  return v;
}

const HOST_METHODS = ['findSite', 'inspectTarget', 'claimTarget', 'createDatabase', 'rollback', 'recordInstalled'];

async function installApp(app, input, host, log) {
  log = typeof log === 'function' ? log : () => {};
  if (!app || !app.handler || typeof app.handler.validate !== 'function' || typeof app.handler.install !== 'function') throw new Error('Unknown application');
  for (const k of HOST_METHODS) if (!host || typeof host[k] !== 'function') throw new Error('Missing installer adapter: ' + k);

  const x = app.handler.validate(input, app);                      // throws on bad input; nothing exists yet
  const site = await host.findSite(x.domain);
  if (!site || site.domain !== x.domain) throw new Error('Website not found: ' + x.domain);
  if (!app.siteTypes.includes(site.type)) throw new Error(app.name + ' needs a ' + app.siteTypes.join(' / ') + ' website, but ' + site.domain + ' is "' + site.type + '"');
  if (x.path && !app.subfolder) throw new Error(app.name + ' can only be installed in the site root');
  if ((site.apps || []).some((a) => a.id === app.id && (a.path || '') === x.path)) throw new Error(app.name + ' is already installed there');

  const target = await host.inspectTarget(site, x.path, app);      // read-only: refuses a folder that already has content
  const state = { db: null, claimed: false };
  try {
    log('Preparing ' + target.rel);
    state.claimed = true;                                          // before the call: a claim that fails halfway must be undone as well
    await host.claimTarget(site, target);                          // removes the placeholder page / creates the sub-folder
    if (app.needsDb) {
      log('Creating the database');
      state.db = await host.createDatabase(site, app, x);
      if (!state.db || !/^[a-z][a-z0-9_]{2,31}$/.test(state.db.name) || !/^[a-z][a-z0-9_]{2,31}$/.test(state.db.user) || typeof state.db.password !== 'string' || state.db.password.length < 12) throw new Error('Database adapter returned invalid credentials');
    }
    const result = await app.handler.install({ x, site, target, db: state.db, host, log });
    await host.recordInstalled(site, Object.assign({ id: app.id, name: app.name, path: x.path, installedAt: new Date().toISOString(), db: state.db ? state.db.name : null }, result && result.meta));
    return Object.assign({ domain: site.domain, app: app.id }, result);
  } catch (err) {
    log('Installation failed: ' + String((err && err.message) || err).slice(0, 300) + ' - undoing what this attempt created');
    try { await host.rollback(site, target, { db: state.db, claimed: state.claimed }, log); } catch (cleanupError) {
      err.cleanupError = String((cleanupError && cleanupError.message) || cleanupError).slice(0, 300);
      log('Cleanup problem: ' + err.cleanupError);
    }
    throw err;
  }
}

module.exports = { installApp, cleanSubdir, SUBDIR_RE };
