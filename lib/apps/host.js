'use strict';
// Production adapters for the app installer. This is the only module in lib/apps that touches the machine:
//  - files are read/written/deleted through worker.js AS THE WEBSITE'S LINUX USER (never as root), so a malicious
//    archive or a symlink planted by the site cannot make the panel (root) write outside the site folder;
//  - tools (php, wp-cli, composer) also run as that user, with HOME/TMPDIR pointed at the site's private tmp folder;
//  - root is only used for what only root can do: creating/dropping the database and downloading the pinned WP-CLI.
const fs = require('fs');
const crypto = require('crypto');
const { ensureWpCli } = require('./wpcli');
const stable = require('./stable');

const PLACEHOLDER_RE = /Site is ready|Your static website is ready/;
const PLACEHOLDER_FILES = ['index.php', 'index.html'];
const rand = (n) => crypto.randomBytes(n).toString('hex');

// deps: { S: lib/sites, c: lib/core, sys: lib/sys, exec: lib/siteexec }  (+ optional phpBin/composerBin/ensureWpCli overrides for tests)
function createHost(deps, log) {
  const { S, c, exec } = deps;
  log = typeof log === 'function' ? log : () => {};
  const worker = (site, op, rel, arg, input) => exec.worker(site, op, rel, arg, input);
  const relOf = (path) => '/public_html' + (path ? '/' + path : '');
  const phpBin = (site) => {
    if (deps.phpBin) return deps.phpBin(site);
    if (/^\d+\.\d+$/.test(String(site.php || '')) && fs.existsSync('/usr/bin/php' + site.php)) return '/usr/bin/php' + site.php;
    return fs.existsSync('/usr/bin/php') ? '/usr/bin/php' : 'php';
  };

  return {
    async findSite(domain) { return S.getSite(c.load(), domain); },

    // Read-only. Refuses anything that would overwrite existing content.
    async inspectTarget(site, subpath, app) {
      const rel = relOf(subpath), dir = site.home + rel;
      let entries = null;
      try { entries = JSON.parse(await worker(site, 'ls', rel)); } catch (e) {
        if (!subpath || !/ENOENT/.test(String(e.message))) throw new Error('Cannot read ' + rel + ': ' + String(e.message).slice(0, 160));
      }
      if (entries === null) { // the sub-folder does not exist yet: its parent must be a real folder
        JSON.parse(await worker(site, 'ls', '/public_html'));
        return { dir, rel, existed: false, placeholders: [] };
      }
      if (subpath) { // a symlink where we expect a folder would send the install somewhere unexpected
        const parent = JSON.parse(await worker(site, 'ls', '/public_html')).find((e) => e.n === subpath);
        if (parent && parent.t === 'l') throw new Error(rel + ' is a symbolic link. Remove it first.');
      }
      const placeholders = [];
      const isPlaceholder = async (relFile, e) => {
        if (!PLACEHOLDER_FILES.includes(e.n) || e.t !== 'f' || e.s >= 2000) return null;
        const body = JSON.parse(await worker(site, 'read', relFile)).c;
        return PLACEHOLDER_RE.test(body) ? body : null;
      };
      for (const e of entries) {
        const body = await isPlaceholder(rel + '/' + e.n, e);
        if (body !== null) { placeholders.push({ rel: e.n, dir: null, body }); continue; }
        // a Laravel site keeps its "site is ready" page in public/ (its web root): that folder holding only the page is still empty
        if (app && app.siteType === 'laravel' && e.n === 'public' && e.t === 'd') {
          const inner = JSON.parse(await worker(site, 'ls', rel + '/public'));
          const ib = inner.length === 1 ? await isPlaceholder(rel + '/public/' + inner[0].n, inner[0]) : null;
          if (ib !== null) { placeholders.push({ rel: 'public/' + inner[0].n, dir: 'public', body: ib }); continue; }
        }
        throw new Error('The folder ' + rel + ' is not empty (found "' + e.n + '"). HostPanel never overwrites files: empty it in the File Manager, or install into a new folder.');
      }
      return { dir, rel, existed: true, placeholders };
    },
    // Removes HostPanel's own "site is ready" page / creates the folder. Only runs after inspectTarget accepted it.
    async claimTarget(site, target) {
      for (const p of target.placeholders) await worker(site, 'rm', target.rel + '/' + (p.dir || p.rel));
      if (!target.existed) await worker(site, 'mkdir', target.rel);
    },

    // Newest STABLE release from the official source, or null when it cannot be looked up (the tool's default channel is stable too).
    async stableVersion(appId) {
      const found = deps.stable ? await deps.stable(appId) : await stable.latest(appId);
      if (!found) log('Could not look up the latest stable ' + appId + ' version; using the installer tool\'s default (stable) channel');
      return found && stable.isStable(found.version) ? found : null;
    },

    async createDatabase(site, app, x) {
      if (x && x.db && x.db.name) { // typed into the wizard: database name, user and password are separate
        return S.createDbCore(x.db.name, { app: app.id, site: site.domain, ownerId: site.ownerId || 'system' }, { user: x.db.user, password: x.db.password, requireNewUser: true });
      }
      const prefix = String(app.dbPrefix || app.id).replace(/[^a-z0-9]/g, '').slice(0, 4) || 'app';
      const label = site.domain.replace(/[^a-z0-9]/g, '').slice(0, 14);
      let lastErr;
      for (let i = 0; i < 4; i++) { // a random suffix makes a collision very unlikely; the DB layer double-checks the server anyway
        try { return S.createDbCore(prefix + '_' + label + '_' + rand(3), { app: app.id, site: site.domain, ownerId: site.ownerId || 'system' }); } catch (e) { lastErr = e; if (!/already exists/.test(String(e.message))) break; }
      }
      throw lastErr;
    },

    async ensureTool(name, logFn) {
      if (name === 'wp-cli') return deps.ensureWpCli ? deps.ensureWpCli(c.P.BASE, logFn || log) : ensureWpCli(c.P.BASE, logFn || log);
      if (name === 'composer') {
        const found = (deps.composerCandidates || ['/usr/bin/composer', '/usr/local/bin/composer']).find((f) => fs.existsSync(f));
        if (!found) throw new Error('Composer is not installed on this server (run: apt-get install composer)');
        return found;
      }
      throw new Error('Unknown tool: ' + name);
    },
    async makeTemp(site) { const rel = '/tmp/hp-install-' + rand(5); await worker(site, 'mkdir', rel); return { rel, abs: site.home + rel }; },
    async removeTemp(site, tmp) { await worker(site, 'rm', tmp.rel); },

    // Runs php (the website's own PHP version) as the site user. Never put secrets in args: use opts.input / opts.env.
    async php(site, args, opts) {
      opts = opts || {};
      return exec.runAs(site, phpBin(site), ['-d', 'display_errors=stderr'].concat(args), { env: opts.env, input: opts.input, cwd: opts.cwd, timeoutMs: opts.timeoutMs, onLine: (l) => log('  ' + l) });
    },
    async readFile(site, rel) { return JSON.parse(await worker(site, 'read', rel)).c; },
    async writeFile(site, rel, content, mode) {
      await worker(site, 'put', rel, '.hp-up-' + rand(6), content);
      if (mode) await worker(site, 'chmod', rel, mode);
    },

    // Undo exactly what this attempt created. Never touches the website, its user, nginx or certificate.
    async rollback(site, target, state, logFn) {
      const say = logFn || log, problems = [];
      const attempt = async (what, fn) => { try { await fn(); } catch (e) { problems.push(what + ': ' + String(e.message).slice(0, 160)); } };
      if (state.claimed) { // set BEFORE claimTarget runs, so a claim that fails halfway is undone too
        if (!target.existed) await attempt('remove ' + target.rel, () => worker(site, 'rm', target.rel));
        else {
          await attempt('empty ' + target.rel, async () => {
            for (const e of JSON.parse(await worker(site, 'ls', target.rel))) await worker(site, 'rm', target.rel + '/' + e.n);
          });
          for (const p of target.placeholders) {
            await attempt('restore ' + p.rel, async () => {
              if (p.dir) { try { await worker(site, 'mkdir', target.rel + '/' + p.dir); } catch (e) { if (!/exists/i.test(String(e.message))) throw e; } }
              await this.writeFile(site, target.rel + '/' + p.rel, p.body, '640');
            });
          }
        }
      }
      if (state.db) await attempt('drop database ' + state.db.name, () => S.dropDbQuiet(state.db.name));
      if (problems.length) throw new Error(problems.join('; '));
      say('Cleanup finished: the database and files created by this attempt were removed');
    },

    async recordInstalled(site, record) {
      const d = c.load(), s = d.sites.find((x) => x.domain === site.domain);
      if (!s) throw new Error('Website disappeared during the installation');
      s.apps = (s.apps || []).filter((a) => !(a.id === record.id && (a.path || '') === (record.path || ''))).concat([record]);
      c.save(d);
      c.auditSys('APP_INSTALLED', record.id + ' ' + site.domain + (record.path ? '/' + record.path : ''));
    }
  };
}

module.exports = { createHost, PLACEHOLDER_RE };
