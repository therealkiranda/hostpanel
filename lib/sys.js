'use strict';
// HostPanel system helpers: stats, services, updates, security checks, firewall, fail2ban.
const fs = require('fs');
const os = require('os');
const net = require('net');
const https = require('https');
const c = require('./core');
const { P, sh, soft, both, ok } = c;

/* ---------- php / services ---------- */
const phpVersions = () => {
  try { return fs.readdirSync(P.PHP).filter((v) => /^\d+\.\d+$/.test(v) && fs.existsSync(P.PHP + '/' + v + '/fpm/pool.d')).sort(); } catch (e) { return []; }
};
const unitExists = (n) => ok('systemctl', ['cat', n]);
const DBSVC = (() => {
  const cand = ['mysql', 'mariadb'];
  return cand.find((n) => unitExists(n) && ok('systemctl', ['is-active', '--quiet', n])) || cand.find(unitExists) || 'mysql';
})();
const SSHSVC = unitExists('ssh') ? 'ssh' : 'sshd';

// Which actions the Services page offers. ufw/ssh are status-only on purpose:
// stopping the firewall or sshd from a web panel is a foot-gun.
function serviceDefs() {
  const full = ['restart', 'start', 'stop'];
  return [
    { n: 'nginx', a: full }, { n: DBSVC, a: full }, { n: 'fail2ban', a: full },
    { n: 'ufw', a: [] }, { n: SSHSVC, a: [] }, { n: 'cron', a: ['restart'] },
    { n: 'certbot.timer', a: [] }, { n: 'hostpanel', a: ['restart'] }
  ].concat(phpVersions().map((v) => ({ n: 'php' + v + '-fpm', a: full })));
}
const serviceNames = () => serviceDefs().map((s) => s.n);

let svcCache = { t: 0, v: {} };
function svcStates(force) {
  const names = serviceNames();
  if (!force && Date.now() - svcCache.t < 8000 && names.every((n) => n in svcCache.v)) return svcCache.v;
  const out = soft('systemctl', ['is-active'].concat(names)) || both('systemctl', ['is-active'].concat(names));
  const lines = out.trim().split('\n'), v = {};
  names.forEach((n, i) => { v[n] = lines[i] === 'active'; });
  svcCache = { t: Date.now(), v };
  return v;
}

/* ---------- stats ---------- */
function stats() {
  let total = 1, avail = 1;
  try {
    const mi = fs.readFileSync('/proc/meminfo', 'utf8');
    const g = (k) => parseInt(mi.match(new RegExp('^' + k + ':\\s+(\\d+)', 'm'))[1], 10) * 1024;
    total = g('MemTotal'); avail = g('MemAvailable');
  } catch (e) {}
  let disk = ['-', '-', '-', '-'];
  try { disk = sh('df', ['-h', '/', '--output=size,used,avail,pcent']).split('\n')[1].trim().split(/\s+/); } catch (e) {}
  const up = os.uptime();
  return {
    load: os.loadavg().map((x) => x.toFixed(2)).join(' / '), cores: os.cpus().length,
    ram: ((total - avail) / 1048576).toFixed(0) + ' / ' + (total / 1048576).toFixed(0) + ' MB', ramPct: Math.round(((total - avail) / total) * 100),
    disk: disk[1] + ' / ' + disk[0] + ' (' + disk[3] + ')', diskPct: parseInt(disk[3], 10) || 0,
    uptime: Math.floor(up / 86400) + 'd ' + Math.floor((up % 86400) / 3600) + 'h ' + Math.floor((up % 3600) / 60) + 'm'
  };
}

/* ---------- updates (apt list is slow, so it is cached) ---------- */
let updCache = { t: 0, v: null };
function pendingUpdates(force) {
  if (!force && updCache.v && Date.now() - updCache.t < 300000) return updCache.v;
  const t = soft('apt', ['list', '--upgradable']);
  const l = t.split('\n').filter((x) => x.includes('/') && !x.startsWith('Listing'));
  updCache = {
    t: Date.now(),
    v: { count: l.length, security: l.filter((x) => /security/.test(x)).length, list: l.slice(0, 80).map((x) => x.split(' ')[0] + ' ' + (x.split(' ')[1] || '')) }
  };
  return updCache.v;
}
const invalidateUpdates = () => { updCache.t = 0; };
const updatesPeek = () => updCache.v;
const AUTOUP = '/etc/apt/apt.conf.d/20auto-upgrades';
const autoUpdatesOn = () => { try { return /Unattended-Upgrade\s+"1"/.test(fs.readFileSync(AUTOUP, 'utf8')); } catch (e) { return false; } };
const setAutoUpdates = (on) => fs.writeFileSync(AUTOUP, 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "' + (on ? '1' : '0') + '";\nUnattended-Upgrade::Automatic-Reboot "false";\n');
const lastAptUpdate = () => { try { return fs.statSync('/var/lib/apt/periodic/update-success-stamp').mtimeMs / 1000; } catch (e) { return 0; } };

/* ---------- certificates ---------- */
const certFile = (domain) => P.LE + '/live/' + domain + '/fullchain.pem';
const certExists = (domain) => fs.existsSync(certFile(domain));
let certCache = {};
function certDays(domain) {
  const e = certCache[domain];
  if (e && Date.now() - e.t < 600000) return e.v;
  let v = null;
  const o = soft('openssl', ['x509', '-noout', '-enddate', '-in', certFile(domain)]);
  const m = /notAfter=(.+)/.exec(o);
  if (m) { const t = new Date(m[1].replace(/\s+/g, ' ')).getTime(); if (!isNaN(t)) v = Math.floor((t - Date.now()) / 86400000); }
  certCache[domain] = { t: Date.now(), v };
  return v;
}
const clearCertCache = () => { certCache = {}; };

/* ---------- security checks ---------- */
let secCache = { t: 0, v: null };
function securityChecks(force) {
  if (!force && secCache.v && Date.now() - secCache.t < 60000) return secCache.v;
  const d = c.load(), out = [];
  const add = (name, good, detail, level) => out.push({ name, ok: good, detail: detail || '', level: level || 'warn' });
  const run = (cmd, a) => soft(cmd, a);
  add('Firewall (UFW) is active', /Status: active/.test(run('ufw', ['status'])), 'Fix: sudo ufw enable');
  add('Fail2ban is running', svcStates()['fail2ban'] === true, 'Blocks brute-force on SSH and this panel');
  add('Automatic security updates ON', autoUpdatesOn(), 'Toggle on the Updates page');
  const up = pendingUpdates();
  add('No pending package updates', up.count === 0, up.count + ' pending (' + up.security + ' security)');
  add('No reboot required', !fs.existsSync('/var/run/reboot-required'), 'Kernel/library update needs a reboot');
  add('Panel 2FA enabled', !!d.admin.totp, 'Account page -> Enable 2FA');
  add('Panel default password changed', !d.admin.mustChange, '');
  add('Panel served over a trusted HTTPS domain', !!(d.settings.panelDomain && d.settings.panelSsl), 'Settings -> Panel domain (Let\'s Encrypt)', 'info');
  add('Direct panel port restricted to your IPs', (d.settings.directIps || []).length > 0, 'Settings -> Direct access (needs the panel domain first)', 'info');
  const sshd = run('sshd', ['-T']);
  const m = (k) => (sshd.match(new RegExp('^' + k + ' (\\S+)', 'm')) || [])[1];
  add('SSH root login disabled', !!sshd && m('permitrootlogin') !== 'yes', 'Set PermitRootLogin no in /etc/ssh/sshd_config');
  add('SSH password login disabled (keys only)', m('passwordauthentication') === 'no', 'Recommended once your SSH key works. Site SFTP users are managed separately.', 'info');
  add('Site users are SFTP-only (no shell, chrooted)', fs.existsSync(P.SSHD_D + '/99-hostpanel.conf') && /chrootdirectory/.test(run('sshd', ['-T', '-C', 'user=hpcheck,host=localhost,addr=127.0.0.1']) || 'chrootdirectory') , 'Drop-in /etc/ssh/sshd_config.d/99-hostpanel.conf');
  add('Database listens on localhost only', !/\s(0\.0\.0\.0|\*|\[::\]):3306\s/.test(run('ss', ['-H', '-tln'])), 'Port 3306 must not be public');
  add('Nginx hides version (server_tokens off)', /server_tokens off/.test(run('nginx', ['-T'])), '');
  const soon = d.sites.filter((s) => s.ssl).map((s) => ({ s, days: certDays(s.domain) })).filter((x) => x.days !== null && x.days < 14);
  add('No certificates expiring within 14 days', soon.length === 0, soon.map((x) => x.s.domain + ' (' + x.days + 'd)').join(', ') || 'Renewal is automatic (certbot.timer)');
  secCache = { t: Date.now(), v: out };
  return out;
}
const clearSecCache = () => { secCache.t = 0; };
const securityPeek = () => secCache.v;

/* ---------- fail2ban / ufw ---------- */
function f2bJails() {
  const o = both('fail2ban-client', ['status']);
  const m = /Jail list:\s*(.*)/.exec(o);
  if (!m) return [];
  return m[1].split(/,\s*/).map((x) => x.trim()).filter((x) => /^[\w.-]+$/.test(x)).map((j) => {
    const t = both('fail2ban-client', ['status', j]);
    const b = /Banned IP list:\s*(.*)/.exec(t);
    const tot = /Total banned:\s*(\d+)/.exec(t);
    return { jail: j, banned: b && b[1].trim() ? b[1].trim().split(/\s+/) : [], total: tot ? +tot[1] : 0 };
  });
}
function f2bUnban(jail, ip) {
  if (!/^[\w.-]+$/.test(jail) || !net.isIP(ip)) throw new Error('Bad jail or IP');
  if (!f2bJails().some((j) => j.jail === jail)) throw new Error('Unknown jail');
  sh('fail2ban-client', ['set', jail, 'unbanip', ip]);
  return 'Unbanned ' + ip + ' from ' + jail;
}
const ufwStatus = () => both('ufw', ['status', 'verbose']).trim() || 'ufw not available';

/* ---------- public ip ---------- */
function discoverIp(cb) {
  const req = https.get('https://checkip.amazonaws.com', { timeout: 6000 }, (res) => {
    let b = '';
    res.on('data', (x) => { b += x; if (b.length > 200) res.destroy(); });
    res.on('end', () => {
      const ip = b.trim();
      if (net.isIP(ip)) { const d = c.load(); if (d.settings.ip !== ip) { d.settings.ip = ip; c.save(d); } }
      if (cb) cb(ip);
    });
  });
  req.on('error', () => cb && cb(''));
  req.on('timeout', () => req.destroy());
}

module.exports = {
  phpVersions, DBSVC, SSHSVC, serviceDefs, serviceNames, svcStates, stats, pendingUpdates, invalidateUpdates, updatesPeek, securityPeek,
  autoUpdatesOn, setAutoUpdates, lastAptUpdate, certFile, certExists, certDays, clearCertCache,
  securityChecks, clearSecCache, f2bJails, f2bUnban, ufwStatus, discoverIp
};
