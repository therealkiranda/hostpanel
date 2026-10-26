#!/usr/bin/env node
'use strict';
// hostpanel-cli: recovery tools, run on the server as root.
const c = require('./lib/core');
const cmd = process.argv[2];
const usage = () => {
  console.log('HostPanel ' + c.VERSION + ' recovery tool\n\nUsage: sudo hostpanel-cli <command>\n\n  reset-password   Generate a new admin password (and turn the "must change" flag on)\n  disable-2fa      Turn off two-factor authentication\n  open-port        Open the panel port to everyone again (undo IP restriction)\n  status           Show panel settings');
  process.exit(cmd ? 1 : 0);
};
if (!cmd || ['-h', '--help', 'help'].indexOf(cmd) >= 0) usage();
if (!c.IS_ROOT) { console.error('Run as root: sudo hostpanel-cli ' + cmd); process.exit(1); }
const fs = require('fs');
try { fs.accessSync(c.P.DB_FILE); } catch (e) { console.error('No panel data found at ' + c.P.DB_FILE); process.exit(1); }
const d = c.load();
if (cmd === 'reset-password') {
  const pass = c.rand(8);
  d.admin.hash = c.bcrypt.hashSync(pass, 12); d.admin.mustChange = true; c.save(d);
  console.log('Username: ' + d.admin.user + '\nNew password: ' + pass + '\nRestart the panel to sign out old sessions: systemctl restart hostpanel');
} else if (cmd === 'disable-2fa') {
  d.admin.totp = null; c.save(d); console.log('2FA disabled.');
} else if (cmd === 'open-port') {
  const S = require('./lib/sites');
  console.log(S.setDirect([]));
} else if (cmd === 'status') {
  const st = d.settings;
  console.log('Version: ' + c.VERSION + '\nAdmin user: ' + d.admin.user + '\n2FA: ' + (d.admin.totp ? 'on' : 'off') + '\nPanel domain: ' + (st.panelDomain || '-') + (st.panelSsl ? ' (SSL)' : '') + '\nDirect IPs: ' + (st.directIps.join(', ') || 'open to all') + '\nSites: ' + d.sites.length + '\nDatabases: ' + d.dbs.length);
} else usage();
