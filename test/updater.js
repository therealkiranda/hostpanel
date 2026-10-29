'use strict';
const assert = require('assert');
const crypto = require('crypto');
const { verifyManifest, applyVerifiedUpdate, manifestPayload, isNewer } = require('../lib/updater');
(async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const m = { version: '1.0.1', assetUrl: 'https://github.com/therealkiranda/hostpanel/releases/download/v1.0.1/hostpanel-1.0.1.tar.gz', sha256: 'a'.repeat(64) };
  m.signature = crypto.sign(null, Buffer.from(manifestPayload(m)), privateKey).toString('base64');
  assert.equal(verifyManifest(m, publicKey).version, '1.0.1');
  assert.throws(() => verifyManifest({ ...m, assetUrl: 'https://evil.example/payload.tar.gz' }, publicKey), /outside the trusted/);
  let rolledBack = false;
  const adapters = {
    download: async () => Buffer.from('artifact'), sha256: async () => 'b'.repeat(64), validateArchive: async () => true,
    backup: async () => 'backup-1', stage: async () => 'stage-1', atomicSwitch: async () => true,
    healthCheck: async () => true, rollback: async () => { rolledBack = true; }, cleanup: async () => true
  };
  await assert.rejects(() => applyVerifiedUpdate(m, publicKey, adapters), /SHA-256 mismatch/);
  assert.equal(rolledBack, false); // no switch occurred before checksum validation
  adapters.sha256 = async () => m.sha256;
  adapters.healthCheck = async () => false;
  await assert.rejects(() => applyVerifiedUpdate(m, publicKey, adapters), /health check/);
  assert.equal(rolledBack, true);
  // downgrade / replay protection
  assert.equal(isNewer('1.0.2', '1.0.1'), true); assert.equal(isNewer('1.0.1', '1.0.1'), false); assert.equal(isNewer('1.0.0', '1.0.1'), false); assert.equal(isNewer('1.10.0', '1.9.9'), true); assert.equal(isNewer('x', '1.0.0'), false);
  adapters.healthCheck = async () => true;
  await assert.rejects(() => applyVerifiedUpdate(m, publicKey, adapters, { currentVersion: '1.0.1' }), /not newer/);
  const m2 = { ...m, version: '1.0.2', assetUrl: m.assetUrl.replace(/1\.0\.1/g, '1.0.2') };
  m2.signature = crypto.sign(null, Buffer.from(manifestPayload(m2)), privateKey).toString('base64');
  assert.equal((await applyVerifiedUpdate(m2, publicKey, adapters, { currentVersion: '1.0.1' })).version, '1.0.2');
  // a switch that fails halfway must still be rolled back
  rolledBack = false; adapters.atomicSwitch = async () => { throw new Error('rename failed'); };
  await assert.rejects(() => applyVerifiedUpdate(m2, publicKey, adapters, { currentVersion: '1.0.1' }), /rename failed/);
  assert.equal(rolledBack, true);
  console.log('signed updater verification/rollback tests passed');
})().catch((e) => { console.error(e); process.exitCode = 1; });
