'use strict';
// Per-website phpMyAdmin. One phpMyAdmin installation (Debian/Ubuntu package) is served by nginx on its own HTTPS port
// (8444, a different browser origin from the panel). Nobody types database credentials there: HostPanel signs the user in
// through a one-time ticket (lib/pma/signon.php) as a MariaDB account that can only see THAT website's databases.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const c = require('./core');
const sys = require('./sys');
const dbs = require('./dbs');
const { P, sh, soft } = c;

const PORT = 8444;
const ROOT = process.env.HP_PMA_ROOT || '/usr/share/phpmyadmin';
const CONF = process.env.HP_PMA_CONF || '/etc/phpmyadmin/config.inc.php';
const DIR = P.BASE + '/pma', TICKETS = DIR + '/tickets';
const SOCK = '/run/php/hostpanel-pma.sock';
const exists = (f) => { try { fs.lstatSync(f); return true; } catch (e) { return false; } };

const installed = () => exists(ROOT + '/index.php');
const ready = () => installed() && exists(P.NGINX + '/sites-enabled/hostpanel-pma.conf') && exists(DIR + '/signon.php');

/* ---------- generated files (pure, unit-tested) ---------- */
function configPhp(secret) {
  if (!/^[A-Za-z0-9]{32,64}$/.test(secret)) throw new Error('Bad secret');
  return "<?php\n// Managed by HostPanel - changes made here are overwritten. Sign-in happens only through HostPanel (single sign-on).\n" +
    "$cfg['blowfish_secret'] = '" + secret + "';\n$i = 1;\n" +
    "$cfg['Servers'][$i]['auth_type'] = 'signon';\n$cfg['Servers'][$i]['SignonSession'] = 'HPPMA';\n$cfg['Servers'][$i]['SignonURL'] = '/hp-denied.html';\n$cfg['Servers'][$i]['LogoutURL'] = '/hp-denied.html';\n" +
    "$cfg['Servers'][$i]['host'] = 'localhost';\n$cfg['Servers'][$i]['compress'] = false;\n$cfg['Servers'][$i]['AllowNoPassword'] = false;\n$cfg['Servers'][$i]['hide_db'] = '^(information_schema|performance_schema|mysql|sys)$';\n" +
    "$cfg['ServerDefault'] = 1;\n$cfg['AllowArbitraryServer'] = false;\n$cfg['TempDir'] = '/var/lib/phpmyadmin/tmp';\n$cfg['UploadDir'] = '';\n$cfg['SaveDir'] = '';\n" +
    "$cfg['LoginCookieValidity'] = 3600;\n$cfg['VersionCheck'] = false;\n$cfg['ShowPhpInfo'] = false;\n$cfg['SendErrorReports'] = 'never';\n$cfg['CheckConfigurationPermissions'] = false;\n$cfg['DefaultLang'] = 'en';\n";
}
function poolConf() {
  return '; Managed by HostPanel\n[hostpanel-pma]\nuser = www-data\ngroup = www-data\nlisten = ' + SOCK + '\nlisten.owner = www-data\nlisten.group = www-data\nlisten.mode = 0660\n' +
    'pm = ondemand\npm.max_children = 6\npm.process_idle_timeout = 30s\nrequest_terminate_timeout = 320s\nsecurity.limit_extensions = .php\n' +
    'php_admin_value[open_basedir] = /usr/share:/etc/phpmyadmin:/var/lib/phpmyadmin:' + DIR + ':/tmp:/dev/urandom\n' +
    'php_admin_value[upload_tmp_dir] = ' + DIR + '/tmp\nphp_admin_value[sys_temp_dir] = ' + DIR + '/tmp\nphp_admin_value[session.save_path] = ' + DIR + '/sessions\n' +
    'php_admin_value[memory_limit] = 384M\nphp_admin_value[upload_max_filesize] = 64M\nphp_admin_value[post_max_size] = 72M\nphp_admin_value[max_execution_time] = 300\nphp_admin_flag[expose_php] = off\n';
}
function nginxConf(cert) {
  const sites = require('./sites');
  return '# Managed by HostPanel - phpMyAdmin (single sign-on only)\nserver {\n  listen ' + PORT + ' ssl;\n  listen [::]:' + PORT + ' ssl;\n' + (sites.http2Directive() ? '  http2 on;\n' : '') + '  server_name _;\n' +
    '  ssl_certificate ' + cert.crt + ';\n  ssl_certificate_key ' + cert.key + ';\n  include snippets/hostpanel-ssl.conf;\n' +
    '  root ' + ROOT + ';\n  index index.php;\n  client_max_body_size 72m;\n  access_log ' + P.NGLOG + '/hostpanel-pma.access.log;\n  error_log ' + P.NGLOG + '/hostpanel-pma.error.log;\n' +
    '  add_header X-Content-Type-Options nosniff always;\n  add_header X-Frame-Options SAMEORIGIN always;\n  add_header Referrer-Policy same-origin always;\n  add_header Strict-Transport-Security "max-age=15552000" always;\n' +
    '  location = /hp-signon {\n    include fastcgi_params;\n    fastcgi_param SCRIPT_FILENAME ' + DIR + '/signon.php;\n    fastcgi_param SCRIPT_NAME /hp-signon;\n    fastcgi_pass unix:' + SOCK + ';\n  }\n' +
    '  location = /hp-denied.html { alias ' + DIR + '/denied.html; }\n' +
    '  location ~ ^/(setup|libraries|templates|sql|vendor|locale|examples|doc|test|tmp|config)(/|$) { deny all; }\n  location ~ /\\. { deny all; }\n' +
    '  location / { try_files $uri $uri/ =404; }\n  location ~ \\.php$ {\n    include snippets/fastcgi-php.conf;\n    fastcgi_pass unix:' + SOCK + ';\n    fastcgi_read_timeout 320s;\n  }\n}\n';
}
function certPair() {
  const d = c.load();
  if (d.settings.panelSsl && d.settings.panelDomain && sys.certExists(d.settings.panelDomain)) return { crt: P.LE + '/live/' + d.settings.panelDomain + '/fullchain.pem', key: P.LE + '/live/' + d.settings.panelDomain + '/privkey.pem' };
  return { crt: P.DATA + '/panel.crt', key: P.DATA + '/panel.key' };
}

/* ---------- setup (root; idempotent; safe to run at every panel start) ---------- */
function setup() {
  if (!installed()) throw new Error('phpMyAdmin is not installed');
  const sites = require('./sites');
  const mk = (dir, mode, owner) => { fs.mkdirSync(dir, { recursive: true }); if (c.IS_ROOT) { fs.chmodSync(dir, mode); if (owner) sh('chown', [owner, dir]); } };
  mk(DIR, 0o755, 'root:root'); mk(TICKETS, 0o2770, 'root:www-data'); mk(DIR + '/sessions', 0o700, 'www-data:www-data'); mk(DIR + '/tmp', 0o700, 'www-data:www-data');
  fs.copyFileSync(path.join(__dirname, 'pma', 'signon.php'), DIR + '/signon.php'); fs.copyFileSync(path.join(__dirname, 'pma', 'denied.html'), DIR + '/denied.html');
  fs.chmodSync(DIR + '/signon.php', 0o644); fs.chmodSync(DIR + '/denied.html', 0o644);
  const d = c.load();
  if (!d.settings.pmaSecret) { d.settings.pmaSecret = crypto.randomBytes(24).toString('hex'); c.save(d); }
  if (exists(CONF) && !exists(CONF + '.hp-orig')) { try { fs.copyFileSync(CONF, CONF + '.hp-orig'); } catch (e) {} }
  fs.mkdirSync(path.dirname(CONF), { recursive: true });
  fs.writeFileSync(CONF, configPhp(d.settings.pmaSecret), { mode: 0o640 });
  if (c.IS_ROOT) { sh('chown', ['root:www-data', CONF]); try { fs.mkdirSync('/var/lib/phpmyadmin/tmp', { recursive: true }); sh('chown', ['-R', 'www-data:www-data', '/var/lib/phpmyadmin/tmp']); } catch (e) {} }
  const ver = sys.phpVersions().pop();
  if (!ver) throw new Error('PHP-FPM is not installed');
  for (const v of sys.phpVersions()) { if (v !== ver) { try { fs.unlinkSync(P.PHP + '/' + v + '/fpm/pool.d/hostpanel-pma.conf'); } catch (e) {} } }
  fs.writeFileSync(P.PHP + '/' + ver + '/fpm/pool.d/hostpanel-pma.conf', poolConf());
  if (c.IS_ROOT) { sh('php-fpm' + ver, ['-t']); sh('systemctl', ['reload', 'php' + ver + '-fpm']); }
  sites.applyNginx('hostpanel-pma.conf', nginxConf(certPair()), 0o600);
  if (c.IS_ROOT) { try { sh('ufw', ['allow', PORT + '/tcp']); } catch (e) {} }
  const d2 = c.load(); d2.settings.pmaEnabled = true; c.save(d2);
}
function refreshIfEnabled() { try { if (c.load().settings.pmaEnabled && installed()) setup(); } catch (e) { c.auditSys('PMA_REFRESH_FAILED', c.errMsg(e)); } }

/* ---------- single sign-on ticket ---------- */
const HOST_RE = /^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9a-fA-F:]+\])$/;
function ticket(domain) {
  if (!ready()) throw new Error('phpMyAdmin is not enabled on this server yet. Ask the administrator to enable it (Databases page).');
  const a = dbs.syncPma(domain), id = crypto.randomBytes(24).toString('hex'), now = Math.floor(Date.now() / 1000);
  try { for (const f of fs.readdirSync(TICKETS)) { const st = fs.statSync(TICKETS + '/' + f); if (now - st.mtimeMs / 1000 > 180) fs.unlinkSync(TICKETS + '/' + f); } } catch (e) {}
  fs.writeFileSync(TICKETS + '/' + id, JSON.stringify({ u: a.user, p: a.password, exp: now + 60, s: domain }), { mode: 0o640, flag: 'wx' });
  return id;
}
function urlFor(hostHeader, id) {
  const host = String(hostHeader || '').replace(/:\d+$/, '');
  if (!HOST_RE.test(host)) throw new Error('Cannot work out this server\'s address');
  return 'https://' + host + ':' + PORT + '/hp-signon?t=' + id;
}

module.exports = { PORT, ROOT, DIR, TICKETS, installed, ready, setup, refreshIfEnabled, ticket, urlFor, configPhp, poolConf, nginxConf, certPair };
