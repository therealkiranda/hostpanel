'use strict';
// Laravel handler: composer create-project (Composer verifies package hashes from Packagist), then HostPanel points
// .env at the new database and runs the migrations. Runs as the website's Linux user, in the site root.
const crypto = require('crypto');
const { cleanSubdir } = require('./engine');
const { cleanDbSpec } = require('./dbspec');
const stable = require('./stable');
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

function fields() {
  return [{ name: 'title', label: 'Application name', type: 'text', value: '', placeholder: 'My Laravel App', required: true, hint: 'Letters, numbers, spaces, dots, dashes (APP_NAME).' }];
}
function validate(input) {
  const x = { domain: String(input.domain || '').trim().toLowerCase(), title: String(input.title || '').trim(), path: cleanSubdir(input.path), https: input.https === true || input.https === '1' };
  if (!DOMAIN.test(x.domain)) throw new Error('Enter a valid domain');
  if (!/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,59}$/.test(x.title)) throw new Error('Application name: 1-60 letters, numbers, spaces, dots or dashes');
  if (x.path) throw new Error('Laravel can only be installed in the site root');
  x.db = cleanDbSpec(input);
  return x;
}

const envValue = (v) => (/^[A-Za-z0-9_./:@-]*$/.test(v) ? v : '"' + String(v).replace(/[\\"$]/g, '\\$&') + '"');
// Replace KEY=... (or a commented "# KEY=...") in a .env text, appending the key when it is not there.
function setEnv(text, map) {
  let out = String(text || '');
  for (const [k, v] of Object.entries(map)) {
    const re = new RegExp('^#?\\s*' + k + '=.*$', 'm'), line = k + '=' + envValue(v);
    out = re.test(out) ? out.replace(re, () => line) : (out && !out.endsWith('\n') ? out + '\n' : out) + line + '\n';
  }
  return out;
}

async function install({ x, site, target, db, host, log }) {
  const composer = await host.ensureTool('composer', log);
  const tmp = await host.makeTemp(site);
  try {
    const env = { HOME: tmp.abs, TMPDIR: tmp.abs, COMPOSER_HOME: tmp.abs + '/composer', COMPOSER_CACHE_DIR: tmp.abs + '/composer-cache', COMPOSER_NO_INTERACTION: '1', COMPOSER_MEMORY_LIMIT: '-1' };
    // Stable releases only: --stability=stable refuses dev/alpha/beta/RC packages, and the newest stable skeleton is pinned.
    const st = host.stableVersion ? await host.stableVersion('laravel') : null;
    log('Downloading Laravel ' + (st ? st.version + ' ' : '') + '(latest stable) with Composer (this can take a few minutes)');
    await host.php(site, ['-d', 'memory_limit=-1', composer, 'create-project', 'laravel/laravel', target.dir].concat(st && stable.isStable(st.version) ? [st.version] : [], ['--stability=stable', '--no-interaction', '--prefer-dist', '--no-progress', '--no-ansi']), { env, timeoutMs: 1500000 });
    const url = (x.https ? 'https://' : 'http://') + x.domain;
    let envText = '';
    try { envText = await host.readFile(site, target.rel + '/.env'); } catch (e) { envText = await host.readFile(site, target.rel + '/.env.example'); }
    log('Configuring .env');
    await host.writeFile(site, target.rel + '/.env', setEnv(envText, { APP_NAME: x.title, APP_ENV: 'production', APP_DEBUG: 'false', APP_URL: url, DB_CONNECTION: 'mysql', DB_HOST: db.host || 'localhost', DB_PORT: '3306', DB_DATABASE: db.name, DB_USERNAME: db.user, DB_PASSWORD: db.password }), '600');
    const artisan = (args) => host.php(site, [target.dir + '/artisan'].concat(args, ['--no-interaction', '--no-ansi']), { env, cwd: target.dir });
    if (!/^APP_KEY=\S+/m.test(envText)) await artisan(['key:generate', '--force']);
    log('Running database migrations');
    await artisan(['migrate', '--force']);
    let version = '';
    try { version = (/Laravel Framework ([\d.]+)/.exec(await artisan(['--version'])) || ['', ''])[1]; } catch (e) { /* cosmetic */ }
    log('Laravel' + (version ? ' ' + version : '') + ' is installed');
    return { url: url + '/', meta: { version, url: url + '/' } };
  } finally { await host.removeTemp(site, tmp).catch(() => {}); }
}

module.exports = { validate, install, fields, setEnv, envValue };
