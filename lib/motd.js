'use strict';
// SSH login banner. Ubuntu's pam_motd runs every executable in /etc/update-motd.d at each interactive login (password
// or key), so a script there is shown on EVERY ssh login without touching sshd_config. Non-interactive uses
// (scp, sftp, `ssh host command`) never show it, so file transfers are not polluted.
// The visible text lives in /etc/hostpanel/motd: edit it freely, upgrades never overwrite it.
const fs = require('fs');
const path = require('path');

const E = process.env;
const DIR = E.HP_MOTD_D || '/etc/update-motd.d';
const CONF = E.HP_MOTD_CONF || '/etc/hostpanel/motd';
const STATE = E.HP_MOTD_STATE || '/etc/hostpanel/motd-disabled';
const SCRIPT = '00-hostpanel';
// Noisy stock Ubuntu greeting parts that "quiet" may switch off. Security notices (updates available, reboot required,
// fsck) are deliberately not in this list.
const STOCK_NOISE = ['10-help-text', '50-landscape-sysinfo', '50-motd-news', '85-fwupd', '88-esm-announcements', '91-contract-ufn', '91-release-upgrade'];

const WIDTH = 56;
const bar = '#'.repeat(WIDTH);
const title = (t) => { const inner = WIDTH - 6, left = Math.floor((inner - t.length) / 2); return '###' + ' '.repeat(left) + t + ' '.repeat(inner - t.length - left) + '###'; };
const BANNER = [bar, title('Welcome to Hostpanel'), bar, '', '* Website:         https://www.khadkakiran.com.np', '* Documentation:   coming soon', '', ''].join('\n');
const scriptBody = () => '#!/bin/sh\n# Managed by HostPanel. Edit ' + CONF + ' to change the text shown at login.\n[ -r "' + CONF + '" ] && cat "' + CONF + '"\nexit 0\n';

function install() {
  fs.mkdirSync(path.dirname(CONF), { recursive: true, mode: 0o755 });
  const kept = fs.existsSync(CONF);
  if (!kept) fs.writeFileSync(CONF, BANNER, { mode: 0o644 });
  fs.mkdirSync(DIR, { recursive: true, mode: 0o755 });
  fs.writeFileSync(path.join(DIR, SCRIPT), scriptBody(), { mode: 0o755 });
  fs.chmodSync(path.join(DIR, SCRIPT), 0o755);
  return 'SSH login banner installed (' + (kept ? 'kept your edited ' + CONF : 'text in ' + CONF) + ')';
}
function remove() { try { fs.unlinkSync(path.join(DIR, SCRIPT)); } catch (e) { if (e.code !== 'ENOENT') throw e; } return 'SSH login banner removed (' + CONF + ' kept)'; }

const readState = () => { try { return JSON.parse(fs.readFileSync(STATE, 'utf8')).filter((n) => STOCK_NOISE.includes(n)); } catch (e) { return []; } };
function quiet() {
  const done = readState();
  for (const n of STOCK_NOISE) {
    const f = path.join(DIR, n);
    try { const st = fs.statSync(f); if (st.isFile() && (st.mode & 0o111)) { fs.chmodSync(f, st.mode & ~0o111); if (!done.includes(n)) done.push(n); } } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
  fs.mkdirSync(path.dirname(STATE), { recursive: true, mode: 0o755 });
  fs.writeFileSync(STATE, JSON.stringify(done));
  return done.length ? 'Hid the standard Ubuntu greeting parts: ' + done.join(', ') + '. Undo with: hostpanel-cli motd default' : 'Nothing to hide.';
}
function restoreDefault() {
  const done = readState(); let n = 0;
  for (const name of done) { const f = path.join(DIR, name); try { const st = fs.statSync(f); fs.chmodSync(f, st.mode | 0o755); n++; } catch (e) { if (e.code !== 'ENOENT') throw e; } }
  try { fs.unlinkSync(STATE); } catch (e) {}
  return 'Restored ' + n + ' standard Ubuntu greeting part(s).';
}
function status() {
  const on = fs.existsSync(path.join(DIR, SCRIPT));
  return 'Banner: ' + (on ? 'installed' : 'not installed') + '\nText file: ' + CONF + '\nHidden Ubuntu parts: ' + (readState().join(', ') || 'none');
}
module.exports = { BANNER, install, remove, quiet, restoreDefault, status, STOCK_NOISE, scriptBody, paths: { DIR, CONF, STATE, SCRIPT } };
