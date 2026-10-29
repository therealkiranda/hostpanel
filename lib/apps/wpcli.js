'use strict';
// WP-CLI is the standard tool for installing and managing WordPress from the command line. It is downloaded once from
// the project's GitHub release and checked against a SHA-256 pinned HERE (not fetched from the same place as the file),
// then kept root-owned in /opt/hostpanel/bin so a website can never replace it. To upgrade: change the three values
// below after verifying the new release's published .sha512 / your own download.
const fs = require('fs');
const path = require('path');
const { fetchVerified, sha256File } = require('./download');

const WPCLI = {
  version: '2.12.0',
  url: 'https://github.com/wp-cli/wp-cli/releases/download/v2.12.0/wp-cli-2.12.0.phar',
  sha256: 'ce34ddd838f7351d6759068d09793f26755463b4a4610a5a5c0a97b68220d85c'
};

// Returns the path of a verified phar, downloading it first when missing or when it does not match the pin.
async function ensureWpCli(baseDir, log, opts) {
  opts = opts || {};
  const pin = opts.pin || WPCLI;
  const dir = path.join(baseDir, 'bin'), file = path.join(dir, 'wp-cli.phar');
  fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
  try { fs.chmodSync(dir, 0o755); } catch (e) {}
  try { if (fs.lstatSync(file).isFile() && sha256File(file) === pin.sha256) return file; } catch (e) {}
  if (log) log('Downloading WP-CLI ' + pin.version + ' (checksum pinned in HostPanel)');
  await fetchVerified(pin.url, pin.sha256, file, opts.fetch);
  fs.chmodSync(file, 0o644);
  return file;
}

module.exports = { WPCLI, ensureWpCli };
