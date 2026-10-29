#!/usr/bin/env node
'use strict';
// One-time setup: creates the Ed25519 key pair that signs HostPanel releases.
//   node tools/make-release-key.js
// - writes the PUBLIC key to lib/release-key.pub (commit it; panels use it to verify updates)
// - prints the PRIVATE key once. Save it as the GitHub secret HOSTPANEL_SIGNING_KEY and keep a copy offline.
// Never commit the private key. If it leaks, generate a new pair and ship a new release-key.pub with a normal install.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const target = path.join(__dirname, '..', 'lib', 'release-key.pub');
if (fs.existsSync(target) && !process.argv.includes('--force')) { console.error('lib/release-key.pub already exists. Use --force only if you really want to replace the signing key.'); process.exit(1); }
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
fs.writeFileSync(target, publicKey.export({ type: 'spki', format: 'pem' }));
console.log('Public key written to lib/release-key.pub (commit this file).\n');
console.log('PRIVATE KEY - add it as the repository secret HOSTPANEL_SIGNING_KEY, then delete this terminal output:\n');
console.log(privateKey.export({ type: 'pkcs8', format: 'pem' }));
