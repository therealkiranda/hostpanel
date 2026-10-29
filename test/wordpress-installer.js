'use strict';
const assert = require('assert');
const { validate, installWordPress } = require('../lib/wordpress-installer');
const input = { domain: 'example.com', title: 'Example', adminUsername: 'siteowner', adminEmail: 'owner@example.com', adminPassword: 'very-long-and-random-password-2026', locale: 'en_US' };
assert.equal(validate(input).domain, 'example.com');
assert.throws(() => validate({ ...input, adminUsername: 'admin' }), /non-default/);
assert.throws(() => validate({ ...input, adminPassword: 'short' }), /16-200/);
(async () => {
  const calls = [];
  const adapters = {
    findSite: async () => ({ domain: 'example.com', type: 'php', wordpressInstalled: false }),
    createDatabase: async () => ({ name: 'wp_example', user: 'wp_example', password: 'x'.repeat(32) }),
    downloadVerifiedCore: async () => ({ verified: true, path: '/tmp/fake.tar.gz', version: '6.8.3' }),
    extractCore: async () => calls.push('extract'), writeConfig: async () => calls.push('config'),
    runCoreInstall: async () => { calls.push('install'); throw new Error('simulated failure'); },
    setOwnership: async () => calls.push('ownership'), removePartialInstall: async () => calls.push('cleanup')
  };
  await assert.rejects(() => installWordPress(input, adapters), /simulated failure/);
  assert.deepEqual(calls, ['extract', 'config', 'install', 'cleanup']);
  console.log('WordPress installer validation/rollback tests passed');
})().catch((e) => { console.error(e); process.exitCode = 1; });
