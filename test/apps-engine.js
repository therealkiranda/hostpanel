'use strict';
// App installer coordinator: validation first, no overwriting, and rollback of exactly what an attempt created.
// Uses fake adapters, so it never touches the machine.
const assert = require('assert');
const { installApp, cleanSubdir } = require('../lib/apps/engine');
const catalog = require('../lib/apps/catalog');

/* ---- folder names ---- */
assert.equal(cleanSubdir(''), ''); assert.equal(cleanSubdir(' /Blog/ '), 'blog'); assert.equal(cleanSubdir('shop_2-x'), 'shop_2-x');
for (const bad of ['..', '../x', 'a/b', '.hidden', 'a b', 'x;rm', 'tmp', 'logs', '-x', 'a'.repeat(40), 'ü']) assert.throws(() => cleanSubdir(bad), /Folder must be/, bad);

/* ---- catalog sanity ---- */
const apps = catalog.list();
assert.ok(apps.length >= 2 && catalog.get('wordpress') && catalog.get('laravel') && !catalog.get('nope'));
for (const a of apps) {
  assert.match(a.id, /^[a-z][a-z0-9-]*$/); assert.ok(a.name && a.summary && a.category && ['stable', 'beta'].includes(a.status));
  assert.ok(Array.isArray(a.siteTypes) && a.siteTypes.length && a.siteTypes.includes(a.siteType));
  assert.equal(typeof a.handler.validate, 'function'); assert.equal(typeof a.handler.install, 'function'); assert.equal(typeof a.handler.fields, 'function');
  assert.ok(a.handler.fields({ email: 'a@b.co', password: 'x' }).every((f) => f.name && f.label && f.type));
}
assert.equal(new Set(apps.map((a) => a.id)).size, apps.length, 'unique ids');

/* ---- a fake host that records everything ---- */
function fakeHost(over) {
  const calls = [];
  const site = { domain: 'example.com', type: 'php', php: '8.3', user: 'w1', home: '/h/w1', apps: [] };
  const h = {
    calls, site,
    findSite: async (d) => { calls.push('findSite'); return d === site.domain ? site : null; },
    inspectTarget: async (s, p) => { calls.push('inspect'); return { dir: '/h/w1/public_html' + (p ? '/' + p : ''), rel: '/public_html' + (p ? '/' + p : ''), existed: !p, placeholders: [] }; },
    claimTarget: async () => { calls.push('claim'); },
    createDatabase: async () => { calls.push('db'); return { name: 'wp_example_a1b2c3', user: 'wp_example_a1b2c3', password: 'p'.repeat(24), host: 'localhost' }; },
    rollback: async (s, t, st) => { calls.push('rollback:' + JSON.stringify({ claimed: st.claimed, db: !!st.db })); },
    recordInstalled: async (s, r) => { calls.push('record:' + r.id); h.record = r; },
    ensureTool: async () => '/x/wp.phar', makeTemp: async () => ({ rel: '/tmp/t', abs: '/h/w1/tmp/t' }), removeTemp: async () => { calls.push('rmtemp'); },
    php: async (s, a) => { calls.push('php:' + a.filter((x) => !String(x).startsWith('--path')).slice(1, 3).join(' ')); return ''; },
    writeFile: async (s, rel) => { calls.push('write:' + rel); }, readFile: async () => ''
  };
  return Object.assign(h, over || {});
}
const wpInput = { domain: 'example.com', title: 'Example', adminUsername: 'siteowner', adminEmail: 'o@example.com', adminPassword: 'very-long-and-random-password-2026', locale: 'en_US' };
const wp = catalog.get('wordpress'), lv = catalog.get('laravel');

(async () => {
  /* ---- happy path: order of operations, record written ---- */
  let h = fakeHost(); const logs = [];
  let r = await installApp(wp, wpInput, h, (m) => logs.push(m));
  assert.deepEqual(h.calls.filter((c) => !c.startsWith('php:') && !c.startsWith('write:')), ['findSite', 'inspect', 'claim', 'db', 'rmtemp', 'record:wordpress']);
  assert.ok(h.calls.indexOf('claim') < h.calls.indexOf('db'), 'target is checked/claimed before a database is created');
  assert.equal(r.domain, 'example.com'); assert.ok(r.adminUrl.endsWith('/wp-admin/')); assert.equal(h.record.db, 'wp_example_a1b2c3');
  assert.ok(!JSON.stringify(h.record).includes(wpInput.adminPassword), 'the administrator password is never recorded');
  assert.ok(!logs.join('\n').includes(wpInput.adminPassword), 'the administrator password is never logged');

  /* ---- bad input: nothing at all is created ---- */
  for (const [patch, re] of [[{ adminUsername: 'admin' }, /non-default/], [{ adminPassword: 'short' }, /16-200/], [{ domain: 'nope' }, /valid domain/], [{ adminEmail: 'x' }, /email/], [{ path: '../etc' }, /Folder must be/], [{ locale: 'xx;rm' }, /locale/]]) {
    h = fakeHost(); await assert.rejects(() => installApp(wp, Object.assign({}, wpInput, patch), h, () => {}), re);
    assert.deepEqual(h.calls, [], 'no adapter was called for invalid input: ' + JSON.stringify(patch));
  }
  /* ---- site problems ---- */
  h = fakeHost(); await assert.rejects(() => installApp(wp, Object.assign({}, wpInput, { domain: 'other.com' }), h, () => {}), /Website not found/);
  h = fakeHost(); h.site.type = 'static'; await assert.rejects(() => installApp(wp, wpInput, h, () => {}), /needs a php website/); assert.ok(!h.calls.includes('claim'));
  h = fakeHost(); h.site.apps = [{ id: 'wordpress', path: '' }]; await assert.rejects(() => installApp(wp, wpInput, h, () => {}), /already installed/); assert.ok(!h.calls.includes('claim'));
  h = fakeHost(); h.site.apps = [{ id: 'wordpress', path: 'blog' }]; await installApp(wp, Object.assign({}, wpInput, { path: 'shop' }), h, () => {}); assert.equal(h.record.path, 'shop', 'a different folder is fine');
  h = fakeHost(); h.site.type = 'laravel'; await assert.rejects(() => installApp(lv, Object.assign({}, wpInput, { title: 'App', path: 'sub' }), h, () => {}), /site root/);
  // a non-empty folder is refused by the host before anything is touched
  h = fakeHost({ inspectTarget: async () => { throw new Error('The folder /public_html is not empty'); } });
  await assert.rejects(() => installApp(wp, wpInput, h, () => {}), /not empty/); assert.deepEqual(h.calls, ['findSite']);

  /* ---- rollback at every stage ---- */
  const failing = async (stage, expectRollback) => {
    const over = {};
    if (stage === 'claim') over.claimTarget = async () => { throw new Error('boom-claim'); };
    if (stage === 'db') over.createDatabase = async () => { throw new Error('boom-db'); };
    if (stage === 'badDb') over.createDatabase = async () => ({ name: 'x', user: 'x', password: 'short' });
    if (stage === 'record') over.recordInstalled = async () => { throw new Error('boom-record'); };
    if (stage === 'install') over.php = async (s, a) => { if (a.includes('install')) throw new Error('boom-install'); return ''; };
    const host = fakeHost(over);
    await assert.rejects(() => installApp(wp, wpInput, host, () => {}), /boom|invalid credentials/);
    assert.equal(host.calls.filter((c) => c.startsWith('rollback')).length, 1, stage + ': rollback runs exactly once');
    assert.equal(host.calls.find((c) => c.startsWith('rollback')), 'rollback:' + JSON.stringify(expectRollback), stage);
    assert.ok(!host.calls.includes('record:wordpress') || stage === 'record');
  };
  await failing('claim', { claimed: true, db: false }); // set before the call: a claim that dies halfway is undone too
  await failing('db', { claimed: true, db: false });
  await failing('badDb', { claimed: true, db: true }); // malformed credentials: whatever the adapter created is still handed to rollback
  await failing('install', { claimed: true, db: true });
  await failing('record', { claimed: true, db: true });

  /* ---- a failing rollback never hides the original error ---- */
  h = fakeHost({ createDatabase: async () => { throw new Error('original'); }, rollback: async () => { throw new Error('cleanup broke'); } });
  const err = await installApp(wp, wpInput, h, () => {}).catch((e) => e);
  assert.equal(err.message, 'original'); assert.match(err.cleanupError, /cleanup broke/);

  /* ---- adapters are mandatory ---- */
  await assert.rejects(() => installApp(wp, wpInput, {}, () => {}), /Missing installer adapter/);
  await assert.rejects(() => installApp(null, wpInput, fakeHost(), () => {}), /Unknown application/);
  console.log('app installer engine tests passed');
})().catch((e) => { console.error(e); process.exitCode = 1; });
