'use strict';
// Release updater primitives: signed manifest verification + backup/stage/switch/health/rollback.
// A deployment adapter must provide atomic filesystem operations; no git pull or shell strings.
const crypto = require('crypto');
const semver = (v) => /^\d+\.\d+\.\d+$/.test(String(v));
const RELEASE_HOST = 'github.com';
const cmp = (a, b) => { const x = String(a).split('.').map(Number), y = String(b).split('.').map(Number); for (let i = 0; i < 3; i++) { if (x[i] !== y[i]) return x[i] > y[i] ? 1 : -1; } return 0; };
const isNewer = (candidate, current) => semver(candidate) && semver(current) && cmp(candidate, current) > 0;
function manifestPayload(m) { return [m.version, m.assetUrl, String(m.sha256).toLowerCase()].join('\n'); }
function verifyManifest(m, publicKey) {
  if (!m || typeof m !== 'object' || !semver(m.version)) throw new Error('Invalid release version');
  let u; try { u = new URL(m.assetUrl); } catch (e) { throw new Error('Invalid release asset URL'); }
  if (u.protocol !== 'https:' || u.hostname !== RELEASE_HOST || !/^\/therealkiranda\/hostpanel\/releases\/download\/v\d+\.\d+\.\d+\/hostpanel-\d+\.\d+\.\d+\.tar\.gz$/.test(u.pathname)) throw new Error('Release asset is outside the trusted GitHub release path');
  const pathVersion = /\/download\/v(\d+\.\d+\.\d+)\/hostpanel-(\d+\.\d+\.\d+)\.tar\.gz$/.exec(u.pathname);
  if (!pathVersion || pathVersion[1] !== m.version || pathVersion[2] !== m.version) throw new Error('Release URL version does not match manifest version');
  if (!m.sha256 || !/^[a-f0-9]{64}$/i.test(m.sha256)) throw new Error('Invalid SHA-256');
  if (typeof m.signature !== 'string' || !m.signature.length || !publicKey) throw new Error('A trusted Ed25519 public key and signature are required');
  let key; try { key = publicKey && publicKey.type === 'public' && publicKey.asymmetricKeyType ? publicKey : crypto.createPublicKey(publicKey); } catch (e) { throw new Error('Invalid trusted public key'); }
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Updater trust key must be Ed25519');
  const sig = Buffer.from(m.signature, 'base64');
  if (!crypto.verify(null, Buffer.from(manifestPayload(m)), key, sig)) throw new Error('Release signature verification failed');
  return { version: m.version, assetUrl: u.toString(), sha256: m.sha256.toLowerCase() };
}
// opts.currentVersion (recommended): refuse anything that is not strictly newer, so an old but validly
// signed manifest cannot be replayed to downgrade the panel to a version with known bugs.
async function applyVerifiedUpdate(manifest, publicKey, adapters, opts) {
  const verified = verifyManifest(manifest, publicKey);
  if (opts && opts.currentVersion !== undefined && !isNewer(verified.version, opts.currentVersion)) throw new Error('Release ' + verified.version + ' is not newer than the installed version ' + opts.currentVersion);
  const required = ['download', 'sha256', 'validateArchive', 'backup', 'stage', 'atomicSwitch', 'healthCheck', 'rollback', 'cleanup'];
  for (const k of required) if (!adapters || typeof adapters[k] !== 'function') throw new Error('Missing updater adapter: ' + k);
  const artifact = await adapters.download(verified.assetUrl);
  let switched = false, backup = null, staged = null;
  try {
    const digest = await adapters.sha256(artifact);
    if (String(digest).toLowerCase() !== verified.sha256) throw new Error('Release SHA-256 mismatch');
    await adapters.validateArchive(artifact);
    backup = await adapters.backup();
    staged = await adapters.stage(artifact, verified.version);
    switched = true; // set first: a switch that fails halfway must also be rolled back
    await adapters.atomicSwitch(staged, verified.version);
    const healthy = await adapters.healthCheck(verified.version);
    if (!healthy) throw new Error('Updated service failed its health check');
    await adapters.cleanup({ artifact, staged, backup, keepBackup: true });
    return { success: true, version: verified.version, backup };
  } catch (err) {
    if (switched && backup !== null) {
      try { await adapters.rollback(backup); } catch (rollbackError) { err.rollbackError = String(rollbackError.message || rollbackError).slice(0, 240); }
    }
    try { await adapters.cleanup({ artifact, staged, backup, keepBackup: true }); } catch (e) {}
    throw err;
  }
}
module.exports = { verifyManifest, applyVerifiedUpdate, manifestPayload, isNewer };
