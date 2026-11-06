'use strict';
// Regression: a background task can start while the stable-release lookup is pending.
// A rejected app install must not create an orphaned website.
const assert = require('assert');
const { createApps } = require('../lib/apps');
const S = require('../lib/sites');

(async () => {
  let running = false, created = 0, release;
  const gate = new Promise((resolve) => { release = resolve; });
  const c = {
    P: { HOMES: '/tmp' },
    load: () => ({ sites: [], dbs: [] }),
    jobRunning: () => running,
    runAsync: () => { throw new Error('should not claim the job slot'); },
  };
  const apps = createApps({
    S: Object.assign({}, S, { createSite: () => { created++; return 'created'; } }),
    c,
    sys: { requireDisk() {} },
    exec: {},
    stableOpts: { getJson: async () => { await gate; return { offers: [] }; } },
  });
  const pending = apps.start({
    app: 'wordpress', target: '__new__', domain: 'race-example.com', php: '8.3',
    title: 'Race test', adminUsername: 'siteowner', adminEmail: 'owner@example.com',
    adminPassword: 'very-long-and-random-password-2026', locale: 'en_US', https: '0',
  });
  await new Promise((resolve) => setImmediate(resolve));
  running = true; // another request wins the single background-job slot
  release();
  await assert.rejects(pending, /Another task is running/);
  assert.equal(created, 0, 'site creation is not attempted after losing the job-slot race');
  console.log('app installation job-slot race test passed');
})().catch((e) => { console.error(e); process.exitCode = 1; });
