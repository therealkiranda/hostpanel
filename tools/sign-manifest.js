#!/usr/bin/env node
'use strict';
// usage: HOSTPANEL_SIGNING_KEY="$(cat private.pem)" node tools/sign-manifest.js <version> <hostpanel-X.Y.Z.tar.gz> > manifest.json
const crypto = require('crypto');
const fs = require('fs');
const { manifestPayload } = require('../lib/updater');
const [, , version, file] = process.argv;
try {
  if (!/^\d+\.\d+\.\d+$/.test(version || '') || !file) throw new Error('usage: sign-manifest.js <version> <tarball>');
  if (!process.env.HOSTPANEL_SIGNING_KEY) throw new Error('HOSTPANEL_SIGNING_KEY is not set');
  const key = crypto.createPrivateKey(process.env.HOSTPANEL_SIGNING_KEY);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('The signing key must be Ed25519');
  const m = { version, assetUrl: 'https://github.com/therealkiranda/hostpanel/releases/download/v' + version + '/hostpanel-' + version + '.tar.gz', sha256: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') };
  m.signature = crypto.sign(null, Buffer.from(manifestPayload(m)), key).toString('base64');
  // refuse to emit a manifest the panels would reject
  const pub = fs.readFileSync(__dirname + '/../lib/release-key.pub', 'utf8');
  require('../lib/updater').verifyManifest(m, crypto.createPublicKey(pub));
  process.stdout.write(JSON.stringify(m, null, 2) + '\n');
} catch (e) { console.error('sign-manifest: ' + e.message); process.exit(1); }
