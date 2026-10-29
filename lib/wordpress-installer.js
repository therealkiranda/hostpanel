'use strict';
// Transaction coordinator for WordPress. All privileged side effects are injected so tests can
// exercise rollback without touching the host. Production adapters must use the restricted helper.
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const USER = /^[A-Za-z][A-Za-z0-9_.-]{2,31}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function validate(input) {
  const x = {
    domain: String(input.domain || '').trim().toLowerCase(),
    title: String(input.title || '').trim(),
    adminUsername: String(input.adminUsername || '').trim(),
    adminEmail: String(input.adminEmail || '').trim().toLowerCase(),
    adminPassword: String(input.adminPassword || ''),
    locale: String(input.locale || 'en_US')
  };
  if (!DOMAIN.test(x.domain)) throw new Error('Enter a valid domain');
  if (!x.title || x.title.length > 120 || /[\0\r\n]/.test(x.title)) throw new Error('Site title must be 1-120 characters');
  if (!USER.test(x.adminUsername) || /^admin$/i.test(x.adminUsername)) throw new Error('Choose a non-default administrator username');
  if (!EMAIL.test(x.adminEmail) || x.adminEmail.length > 254) throw new Error('Enter a valid administrator email');
  if (x.adminPassword.length < 16 || x.adminPassword.length > 200 || /[\0\r\n]/.test(x.adminPassword)) throw new Error('Use a 16-200 character password without line breaks');
  if (!/^[a-z]{2,3}(?:_[A-Z]{2})?$/.test(x.locale)) throw new Error('Invalid WordPress locale');
  return x;
}
async function installWordPress(input, adapters) {
  const x = validate(input);
  const required = ['findSite', 'createDatabase', 'downloadVerifiedCore', 'extractCore', 'writeConfig', 'runCoreInstall', 'setOwnership', 'removePartialInstall'];
  for (const k of required) if (!adapters || typeof adapters[k] !== 'function') throw new Error('Missing installer adapter: ' + k);
  const site = await adapters.findSite(x.domain);
  if (!site || site.domain !== x.domain || !['php', 'wordpress'].includes(site.type)) throw new Error('A compatible PHP website must exist first');
  if (site.wordpressInstalled) throw new Error('WordPress is already installed');
  let db = null, coreStarted = false;
  try {
    db = await adapters.createDatabase(site);
    if (!db || !/^[a-z][a-z0-9_]{2,31}$/.test(db.name) || !/^[a-z][a-z0-9_]{2,31}$/.test(db.user) || typeof db.password !== 'string' || db.password.length < 24) throw new Error('Database adapter returned invalid credentials');
    const core = await adapters.downloadVerifiedCore(x.locale);
    if (!core || !core.verified || typeof core.path !== 'string') throw new Error('WordPress core download was not verified');
    await adapters.extractCore(core.path, site);
    await adapters.writeConfig(site, db, x);
    coreStarted = true;
    await adapters.runCoreInstall(site, x);
    await adapters.setOwnership(site);
    if (typeof adapters.recordInstalled === 'function') await adapters.recordInstalled(site, { installedAt: new Date().toISOString(), version: core.version || null, dbName: db.name });
    return { domain: site.domain, adminUsername: x.adminUsername, adminUrl: 'https://' + site.domain + '/wp-admin/', database: db.name, success: true };
  } catch (err) {
    // Do not delete the whole site. Only clean the exact install paths/resources created by this attempt.
    try { await adapters.removePartialInstall(site, { database: db, coreStarted }); } catch (cleanupError) {
      err.cleanupError = String(cleanupError.message || cleanupError).slice(0, 200);
    }
    throw err;
  }
}
module.exports = { validate, installWordPress };
