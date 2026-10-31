'use strict';
// HostPanel sites: nginx + PHP-FPM + SFTP users, Let's Encrypt, panel domain, databases, backups, cron.
const fs = require('fs');
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const dnsP = require('dns').promises;
const c = require('./core');
const sys = require('./sys');
const dbs = require('./dbs');
const runtime = require('./runtime');
const { P, sh, rand, load, save, runSteps, errMsg } = c;
const PHP_TYPES = ['php', 'laravel'], PROXY_TYPES = ['proxy', 'node', 'python'], TYPES = ['php', 'laravel', 'static', 'proxy', 'node', 'python'];
const isProxyType = (t) => PROXY_TYPES.includes(t), hasPhp = (t) => PHP_TYPES.includes(t);

const DOMAIN_RE = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const EMAIL_RE = /^[^\s@'"`;&|<>$\\]+@[^\s@'"`;&|<>$\\]+\.[^\s@'"`;&|<>$\\]+$/;
const NAME_RE = dbs.NAME_RE, RESERVED_DB = dbs.RESERVED;
const siteUser = (domain) => 'w' + crypto.createHash('sha1').update(domain).digest('hex').slice(0, 10);
const getSite = (d, domain) => { const s = d.sites.find((x) => x.domain === domain); if (!s) throw new Error('Site not found'); return s; };
const tpl = (name, vars) => fs.readFileSync(path.join(__dirname, 'tpl', name), 'utf8').replace(/\{\{(\w+)\}\}/g, (m, k) => String(vars[k]));
const writeIfChanged = (f, body, mode) => {
  let prev = null; try { prev = fs.readFileSync(f, 'utf8'); } catch (e) {}
  if (prev === body) return false;
  fs.writeFileSync(f, body, { mode: mode || 0o644 }); return true;
};

/* ================= per-site php settings ================= */
const defCfg = () => ({ memory: '256M', upload: '128M', exec: 120, children: 8, basedir: true });
const mb = (v) => parseInt(v, 10);
function cleanCfg(f, base) {
  const cfg = Object.assign(defCfg(), base || {});
  if (f.memory !== undefined) {
    const v = String(f.memory).trim().toUpperCase();
    if (!/^\d{2,4}M$/.test(v) || mb(v) < 16 || mb(v) > 8192) throw new Error('Memory limit must look like 256M (16M-8192M)');
    cfg.memory = v;
  }
  if (f.upload !== undefined) {
    const v = String(f.upload).trim().toUpperCase();
    if (!/^\d{1,4}M$/.test(v) || mb(v) < 1 || mb(v) > 4096) throw new Error('Upload limit must look like 128M (1M-4096M)');
    cfg.upload = v;
  }
  if (f.exec !== undefined) { const n = parseInt(f.exec, 10); if (!(n >= 10 && n <= 3600)) throw new Error('Max execution time: 10-3600 seconds'); cfg.exec = n; }
  if (f.children !== undefined) { const n = parseInt(f.children, 10); if (!(n >= 1 && n <= 100)) throw new Error('Max PHP workers: 1-100'); cfg.children = n; }
  if (f.basedir !== undefined) cfg.basedir = f.basedir === true || f.basedir === '1';
  return cfg;
}

/* ================= php ini policy ================= */
const FN_STD = 'passthru,shell_exec,system,popen,pcntl_exec,dl,show_source';
const FN_STRICT = FN_STD + ',exec,proc_open,proc_get_status,proc_terminate,proc_nice,posix_kill,posix_mkfifo,posix_setuid';
function phpIni(policy) {
  return '; Managed by HostPanel\nexpose_php = Off\ncgi.fix_pathinfo = 0\nallow_url_include = Off\nsession.cookie_httponly = 1\nsession.use_strict_mode = 1\nsession.cookie_samesite = Lax\n' +
    'upload_max_filesize = 128M\npost_max_size = 136M\nmemory_limit = 256M\nmax_execution_time = 120\ndisable_functions = ' + (policy === 'standard' ? FN_STD : FN_STRICT) + '\n';
}
function writePhpIni(policy, reload) {
  const changed = [];
  sys.phpVersions().forEach((v) => {
    const dir = P.PHP + '/' + v + '/fpm/conf.d';
    fs.mkdirSync(dir, { recursive: true });
    if (writeIfChanged(dir + '/99-hostpanel.ini', phpIni(policy))) changed.push(v);
  });
  if (reload) changed.forEach((v) => sh('systemctl', ['reload', 'php' + v + '-fpm']));
  return changed;
}

/* ================= nginx ================= */
let nginxV = null;
function nginxVer() {
  if (nginxV) return nginxV;
  const r = spawnSync('nginx', ['-v'], { encoding: 'utf8' });
  const m = /nginx\/(\d+)\.(\d+)\.(\d+)/.exec((r.stderr || '') + (r.stdout || ''));
  nginxV = m ? [+m[1], +m[2], +m[3]] : [1, 18, 0];
  return nginxV;
}
const http2Directive = () => { const v = nginxVer(); return v[0] > 1 || v[1] > 25 || (v[1] === 25 && v[2] >= 1); };
const listen443 = () => http2Directive()
  ? '  listen 443 ssl;\n  listen [::]:443 ssl;\n  http2 on;\n'
  : '  listen 443 ssl http2;\n  listen [::]:443 ssl http2;\n';
const acmeBlock = () => '  location ^~ /.well-known/acme-challenge/ {\n    root ' + P.WEBROOT + ';\n    default_type "text/plain";\n  }\n';
const placeholderCert = () => {
  const crt = P.NGINX + '/hostpanel/default.crt', key = P.NGINX + '/hostpanel/default.key';
  return fs.existsSync(crt) && fs.existsSync(key) ? { crt, key } : null;
};
const certPaths = (domain) => '  ssl_certificate ' + P.LE + '/live/' + domain + '/fullchain.pem;\n  ssl_certificate_key ' + P.LE + '/live/' + domain + '/privkey.pem;\n  include snippets/hostpanel-ssl.conf;\n';

function nginxConf(s) {
  const cfg = Object.assign(defCfg(), s.cfg || {});
  const hasSsl = !!(s.ssl && sys.certExists(s.domain));
  const httpNames = s.domain + ' www.' + s.domain;
  const sslNames = (s.certNames && s.certNames.length ? s.certNames : [s.domain, 'www.' + s.domain]).join(' ');
  const common = '  client_max_body_size ' + (mb(cfg.upload) + 8) + 'M;\n' +
    '  access_log ' + P.NGLOG + '/' + s.domain + '.access.log;\n  error_log ' + P.NGLOG + '/' + s.domain + '.error.log;\n' +
    '  add_header X-Content-Type-Options nosniff always;\n  add_header X-Frame-Options SAMEORIGIN always;\n  add_header Referrer-Policy strict-origin-when-cross-origin always;\n';
  const body = isProxyType(s.type) ? tpl('site-proxy.tpl', { PORT: s.port }) : (s.type === 'static' ? tpl('site-static.tpl', { DOCROOT: s.docroot }) : tpl('site-php.tpl', { DOCROOT: s.docroot, USER: s.user, TIMEOUT: cfg.exec + 5 }));
  const head = '# Managed by HostPanel - changes made here are overwritten\n';
  if (!hasSsl) {
    // No Let's Encrypt certificate yet (it is issued by hand from the site's SSL section, like CloudPanel).
    // Answer on 443 anyway with the shared self-signed certificate, so Cloudflare "Full" or a direct https:// visit
    // reaches the site (browser warning only) instead of failing the TLS handshake (Cloudflare 525 / QUIC errors).
    const self = placeholderCert();
    return head + 'server {\n  listen 80;\n  listen [::]:80;\n' + (self ? listen443() : '') + '  server_name ' + httpNames + ';\n' +
      (self ? '  ssl_certificate ' + self.crt + ';\n  ssl_certificate_key ' + self.key + ';\n  include snippets/hostpanel-ssl.conf;\n' : '') + acmeBlock() + common + body + '}\n';
  }
  return head +
    'server {\n  listen 80;\n  listen [::]:80;\n  server_name ' + httpNames + ';\n' + acmeBlock() + '  location / { return 301 https://$host$request_uri; }\n}\n' +
    'server {\n' + listen443() + '  server_name ' + sslNames + ';\n' + certPaths(s.domain) +
    '  add_header Strict-Transport-Security "max-age=15552000" always;\n' + common + body + '}\n';
}

// Write a vhost, test nginx, reload. Restores the previous file if nginx rejects the new one.
function applyNginx(name, content, mode) {
  const av = P.NGINX + '/sites-available/' + name, en = P.NGINX + '/sites-enabled/' + name;
  fs.mkdirSync(P.NGINX + '/sites-available', { recursive: true }); fs.mkdirSync(P.NGINX + '/sites-enabled', { recursive: true });
  let prev = null; try { prev = fs.readFileSync(av, 'utf8'); } catch (e) {}
  fs.writeFileSync(av, content, { mode: mode || 0o644 });
  let linked = true; try { fs.lstatSync(en); } catch (e) { linked = false; }
  if (!linked) fs.symlinkSync(av, en);
  try { sh('nginx', ['-t']); sh('systemctl', ['reload', 'nginx']); } catch (e) {
    if (prev === null) { try { fs.unlinkSync(en); } catch (x) {} try { fs.unlinkSync(av); } catch (x) {} } else fs.writeFileSync(av, prev, { mode: mode || 0o644 });
    throw e;
  }
}
function removeNginx(name) {
  [P.NGINX + '/sites-enabled/' + name, P.NGINX + '/sites-available/' + name].forEach((f) => { try { fs.unlinkSync(f); } catch (e) {} });
}

/* ================= pool config ================= */
function poolConf(s) {
  const cfg = Object.assign(defCfg(), s.cfg || {}), h = s.home;
  const bd = cfg.basedir ? 'php_admin_value[open_basedir] = ' + h + ':/tmp:/usr/share/php:/usr/share/pear:/usr/share/zoneinfo:/etc/ssl/certs:/dev/urandom\n' : '';
  return '; Managed by HostPanel\n[' + s.user + ']\nuser = ' + s.user + '\ngroup = ' + s.user + '\nlisten = /run/php/' + s.user + '.sock\n' +
    'listen.owner = www-data\nlisten.group = www-data\nlisten.mode = 0660\n' +
    'pm = ondemand\npm.max_children = ' + cfg.children + '\npm.process_idle_timeout = 20s\npm.max_requests = 500\nrequest_terminate_timeout = ' + (cfg.exec + 10) + 's\n' +
    'security.limit_extensions = .php\ncatch_workers_output = yes\n' +
    'php_admin_value[upload_tmp_dir] = ' + h + '/tmp\nphp_admin_value[sys_temp_dir] = ' + h + '/tmp\nphp_admin_value[session.save_path] = ' + h + '/tmp\n' +
    'php_admin_value[error_log] = ' + h + '/logs/php_error.log\nphp_admin_flag[log_errors] = on\n' +
    'php_admin_value[memory_limit] = ' + cfg.memory + '\nphp_admin_value[upload_max_filesize] = ' + cfg.upload + '\nphp_admin_value[post_max_size] = ' + (mb(cfg.upload) + 8) + 'M\n' +
    'php_admin_value[max_execution_time] = ' + cfg.exec + '\n' + bd;
}
const poolFile = (ver, s) => P.PHP + '/' + ver + '/fpm/pool.d/' + s.user + '.conf';

/* ================= base setup (idempotent, runs at every panel start) ================= */
const SSL_SNIPPET = 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;\n' +
  'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\n' +
  'ssl_session_timeout 1d;\nssl_session_cache shared:HPSSL:10m;\nssl_session_tickets off;\n';
const MAPS_CONF = '# Managed by HostPanel\nmap $http_upgrade $hp_conn_upgrade {\n  default upgrade;\n  \'\' close;\n}\n';
const SSHD_BODY = (pw) => '# Managed by HostPanel - do not edit (changes are overwritten)\nMatch Group hpsftp\n  ChrootDirectory %h\n  ForceCommand internal-sftp -d /public_html -u 027\n' +
  '  AuthorizedKeysFile ' + P.KEYS + '/%u\n  PasswordAuthentication ' + (pw ? 'yes' : 'no') + '\n  AllowTcpForwarding no\n  X11Forwarding no\n  AllowAgentForwarding no\n  PermitTunnel no\n  PermitTTY no\n';

function writeSshd() {
  const d = load(), body = SSHD_BODY(d.settings.sftpPassword), f = P.SSHD_D + '/99-hostpanel.conf';
  let prev = null; try { prev = fs.readFileSync(f, 'utf8'); } catch (e) {}
  if (prev === body) return false;
  fs.mkdirSync(P.SSHD_D, { recursive: true });
  let conf = ''; try { conf = fs.readFileSync(P.SSHD_CONF, 'utf8'); } catch (e) {}
  let confPrev = null;
  if (conf && !/^\s*Include\s+\S*sshd_config\.d/m.test(conf)) { confPrev = conf; fs.writeFileSync(P.SSHD_CONF, 'Include ' + P.SSHD_D + '/*.conf\n' + conf); }
  fs.writeFileSync(f, body);
  try { sh('sshd', ['-t']); } catch (e) {
    if (prev === null) { try { fs.unlinkSync(f); } catch (x) {} } else fs.writeFileSync(f, prev);
    if (confPrev !== null) fs.writeFileSync(P.SSHD_CONF, confPrev);
    throw e;
  }
  try { sh('systemctl', ['reload', sys.SSHSVC]); } catch (e) {}
  return true;
}

function ensureBase() {
  const t = (fn, what) => { try { fn(); } catch (e) { c.auditSys('ENSURE_FAILED', what + ': ' + errMsg(e)); console.error('[hostpanel] ' + what + ': ' + errMsg(e)); } };
  t(() => fs.mkdirSync(P.WEBROOT, { recursive: true, mode: 0o755 }), 'webroot');
  t(() => { fs.mkdirSync(P.NGINX + '/snippets', { recursive: true }); writeIfChanged(P.NGINX + '/snippets/hostpanel-ssl.conf', SSL_SNIPPET); }, 'nginx ssl snippet');
  t(() => { // heal an old installer's duplicate "server_tokens" (nginx refuses to load two)
    const ours = P.NGINX + '/conf.d/00-hostpanel.conf', main = P.NGINX + '/nginx.conf';
    let m = ''; try { m = fs.readFileSync(main, 'utf8'); } catch (e) { return; }
    if (/^\s*server_tokens\s/m.test(m)) {
      if (/^\s*server_tokens\s+(?!off\b)[^;]*;/m.test(m)) fs.writeFileSync(main, m.replace(/^(\s*)server_tokens\s+[^;]*;/m, '$1server_tokens off;'));
      try { fs.unlinkSync(ours); } catch (e) {}
    }
  }, 'server_tokens duplicate');
  t(() => { fs.mkdirSync(P.NGINX + '/conf.d', { recursive: true }); writeIfChanged(P.NGINX + '/conf.d/hostpanel-maps.conf', MAPS_CONF); }, 'nginx maps');
  t(() => {
    const dir = P.LE + '/renewal-hooks/deploy';
    fs.mkdirSync(dir, { recursive: true });
    writeIfChanged(dir + '/hostpanel-reload.sh', '#!/bin/sh\nsystemctl reload nginx\n', 0o755);
    try { fs.chmodSync(dir + '/hostpanel-reload.sh', 0o755); } catch (e) {}
  }, 'certbot deploy hook');
  t(() => { if (!c.ok('getent', ['group', 'hpsftp'])) sh('groupadd', ['-f', 'hpsftp']); }, 'sftp group');
  t(() => fs.mkdirSync(P.KEYS, { recursive: true, mode: 0o755 }), 'sftp keys dir');
  t(() => writePhpIni(load().settings.phpPolicy, true), 'php ini');
  t(writeSshd, 'sshd sftp drop-in');
}


// Site homes are root-owned (required by the SFTP chroot), so `userdel -r` refuses to delete them.
// Remove explicitly, but only ever a folder that looks exactly like one we created.
const HOME_RE = /^w[0-9a-f]{10}$/;
function rmHome(home) {
  if (!home || path.dirname(home) !== P.HOMES || !HOME_RE.test(path.basename(home))) throw new Error('Refusing to remove ' + home);
  fs.rmSync(home, { recursive: true, force: true });
}

/* ================= sites ================= */
// SSL is never requested here: like CloudPanel, the certificate is issued manually from the site's SSL section.
// (f.autoSsl is still honoured for scripted use; the UI no longer offers it.)
function createSite(f) {
  const d = load();
  const domain = String(f.domain || '').trim().toLowerCase().replace(/^www\./, '');
  if (!DOMAIN_RE.test(domain)) throw new Error('Invalid domain');
  if (d.sites.find((x) => x.domain === domain)) throw new Error('Site already exists');
  if (d.settings.panelDomain === domain) throw new Error('That domain is used by the panel itself');
  const type = TYPES.includes(f.type) ? f.type : 'php';
  const s = { domain, type, user: siteUser(domain), created: new Date().toISOString(), ssl: false, certNames: [], cfg: defCfg(), autoSsl: f.autoSsl === true || f.autoSsl === '1', ownerId: f.ownerId || 'system' };
  if (s.ownerId !== 'system' && !(d.users || []).some((u) => u.id === s.ownerId)) throw new Error('That client does not exist');
  s.home = P.HOMES + '/' + s.user; s.root = s.home + '/public_html';
  if (isProxyType(type)) {
    s.port = parseInt(f.port, 10) || (type === 'proxy' ? NaN : runtime.nextPort(d));
    if (!(s.port >= 1024 && s.port <= 65535)) throw new Error('Port must be 1024-65535');
    if (s.port === c.PORT || s.port === 8444) throw new Error('That port belongs to the panel');
    if (type !== 'proxy' && d.sites.some((x) => x.port === s.port)) throw new Error('Port ' + s.port + ' is already used by another website');
    if (type !== 'proxy') { s.cmd = runtime.cleanCmd(f.cmd, type); s.docroot = s.root; }
  } else if (type === 'static') {
    s.docroot = s.root;
  } else {
    s.php = String(f.php || '');
    if (!sys.phpVersions().includes(s.php)) throw new Error('PHP version not installed');
    s.docroot = type === 'laravel' ? s.root + '/public' : s.root;
  }
  const email = String(f.email || d.email || '').trim();
  if (s.autoSsl && email && !EMAIL_RE.test(email)) throw new Error('Invalid email for Let\'s Encrypt');
  const pass = rand(9), undo = [];
  try {
    sh('useradd', ['-M', '-d', s.home, '-s', '/usr/sbin/nologin', '-G', 'hpsftp', s.user]);
    undo.push(() => { try { sh('userdel', ['-f', s.user]); } finally { rmHome(s.home); } });
    sh('chpasswd', [], s.user + ':' + pass);
    ['', '/public_html', '/tmp', '/logs'].forEach((x) => fs.mkdirSync(s.home + x, { recursive: true }));
    fs.mkdirSync(s.docroot || s.root, { recursive: true });
    if (type === 'static') fs.writeFileSync(s.docroot + '/index.html', '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + domain + '</title><h1>' + domain + '</h1><p>Your static website is ready. Upload your files to public_html.</p></html>\n', { mode: 0o640 });
    else if (type === 'node' || type === 'python') { const ph = runtime.placeholder(type); fs.writeFileSync(s.docroot + '/' + ph.name, ph.body, { mode: 0o640 }); }
    else if (type !== 'proxy') fs.writeFileSync(s.docroot + '/index.php', '<?php echo "<h1>' + domain + '</h1><p>Site is ready. Upload your files to public_html.</p>";\n', { mode: 0o640 });
    // Chroot rule: the home itself must be root-owned and not writable. Content lives in the subfolders.
    sh('chown', ['root:root', s.home]); sh('chmod', ['755', s.home]);
    sh('chown', ['-R', s.user + ':www-data', s.root]); sh('chmod', ['2750', s.root]);
    sh('chown', [s.user + ':' + s.user, s.home + '/tmp', s.home + '/logs']);
    sh('chmod', ['700', s.home + '/tmp']); sh('chmod', ['750', s.home + '/logs']);
    if (hasPhp(type)) {
      const pf = poolFile(s.php, s);
      fs.writeFileSync(pf, poolConf(s)); undo.push(() => fs.unlinkSync(pf));
      sh('php-fpm' + s.php, ['-t']);
      sh('systemctl', ['reload', 'php' + s.php + '-fpm']);
      undo.push(() => sh('systemctl', ['reload', 'php' + s.php + '-fpm']));
    }
    if (type === 'node' || type === 'python') { runtime.install(s); undo.push(() => runtime.remove(s)); }
    applyNginx(domain + '.conf', nginxConf(s));
    undo.push(() => removeNginx(domain + '.conf'));
  } catch (e) { undo.reverse().forEach((fn) => { try { fn(); } catch (x) {} }); throw e; }
  d.sites.push(s); if (email && EMAIL_RE.test(email)) d.email = email; save(d);
  if (type === 'node') { try { sh('systemctl', ['start', runtime.unitName(s)]); } catch (e) { c.auditSys('APP_START_FAILED', domain + ': ' + errMsg(e)); } }
  let msg = 'Site created: ' + domain + '\nSFTP host: this server, port 22 (SFTP only, no shell)\nSFTP user: ' + s.user + '\nPassword: ' + pass +
    '\nWeb root: ' + (s.docroot || s.root).replace(s.home, '') + (isProxyType(type) ? '\nProxy -> 127.0.0.1:' + s.port : '') + '\n(Password is shown only once)';
  if (s.autoSsl && !email) msg += '\n\nAuto-SSL: add a Let\'s Encrypt email in Settings, then it will run by itself.';
  else if (s.autoSsl) { try { queueSsl(domain, email, false); msg += '\n\nLet\'s Encrypt: requested. Progress: Tasks page.'; } catch (e) { msg += '\n\nLet\'s Encrypt will be retried automatically (' + errMsg(e) + ').'; } }
  else msg += '\n\nSSL: when the domain\'s DNS points to this server, open Manage -> SSL certificate and press "Issue certificate".';
  return msg;
}

function finalDeleteSite(domain) {
  const d = load(), s = d.sites.find((x) => x.domain === domain);
  if (!s) throw new Error('Site not found');
  const t = (fn) => { try { fn(); } catch (e) {} };
  removeNginx(s.domain + '.conf');
  if (s.ssl) t(() => sh('certbot', ['delete', '--cert-name', s.domain, '--non-interactive']));
  if (s.type === 'node' || s.type === 'python') t(() => runtime.remove(s));
  t(() => dbs.dropPma(s.domain));
  if (hasPhp(s.type)) { t(() => fs.unlinkSync(poolFile(s.php, s))); t(() => sh('systemctl', ['reload', 'php' + s.php + '-fpm'])); }
  t(() => fs.unlinkSync(P.KEYS + '/' + s.user));
  t(() => sh('crontab', ['-r', '-u', s.user]));
  t(() => sh('pkill', ['-u', s.user]));
  t(() => sh('userdel', ['-f', s.user]));
  t(() => rmHome(s.home)); // the home is root-owned (SFTP chroot), so 'userdel -r' would silently keep the files
  sh('nginx', ['-t']); sh('systemctl', ['reload', 'nginx']);
  d.sites = d.sites.filter((x) => x.domain !== domain); save(d);
  t(() => dbs.detachSite(domain));
  c.auditSys('SITE_DELETED', domain);
}
const tarStep = (file, user) => [
  ['bash', ['-c', 'tar --warning=no-file-changed -czf "$1" -C "$2" "$3"; rc=$?; [ "$rc" -le 1 ]', 'bash', file, P.HOMES, user]],
  ['chmod', ['600', file]]
];
function deleteSite(domain, skipBackup, confirm) {
  const s = getSite(load(), domain);
  if (confirm !== domain) throw new Error('Confirmation did not match the domain name - nothing was deleted');
  if (skipBackup) { finalDeleteSite(domain); return 'Site deleted: ' + domain + ' (no backup was kept)'; }
  sys.requireDisk(P.BACKUPS, 90, 'the final backup (tick "Skip the final backup" to delete without one)');
  runSteps('Final backup + delete ' + domain, tarStep(P.BACKUPS + '/site-' + domain + '-' + c.stamp() + '.tar.gz', s.user), () => finalDeleteSite(domain));
  return 'Taking a final backup first; the site is deleted when it finishes (see Tasks). The backup stays in Backups.';
}

function setOwner(domain, ownerId) {
  const d = load(), s = getSite(d, domain);
  if (ownerId && ownerId !== 'system' && !d.users.some((u) => u.id === ownerId && u.active !== false)) throw new Error('That client does not exist');
  s.ownerId = ownerId || 'system'; save(d);
  dbs.reassignOwner(domain, s.ownerId);
}

/* ---------- php settings / version ---------- */
function updatePhp(domain, f) {
  const d = load(), s = getSite(d, domain);
  if (!hasPhp(s.type)) throw new Error('This website type has no PHP settings');
  const ver = String(f.php || s.php);
  if (!sys.phpVersions().includes(ver)) throw new Error('PHP version not installed');
  const cfg = cleanCfg(f, s.cfg);
  const oldVer = s.php, oldPool = poolFile(oldVer, s);
  let oldBody = ''; try { oldBody = fs.readFileSync(oldPool, 'utf8'); } catch (e) {}
  const ns = Object.assign({}, s, { php: ver, cfg });
  const newPool = poolFile(ver, ns);
  try {
    fs.writeFileSync(newPool, poolConf(ns));
    if (ver !== oldVer) { try { fs.unlinkSync(oldPool); } catch (e) {} }
    sh('php-fpm' + ver, ['-t']);
    sh('systemctl', ['reload', 'php' + ver + '-fpm']);
    if (ver !== oldVer) sh('systemctl', ['reload', 'php' + oldVer + '-fpm']);
    applyNginx(domain + '.conf', nginxConf(ns));
  } catch (e) {
    try { if (ver !== oldVer) fs.unlinkSync(newPool); fs.writeFileSync(oldPool, oldBody); sh('systemctl', ['reload', 'php' + oldVer + '-fpm']); } catch (x) {}
    throw e;
  }
  s.php = ver; s.cfg = cfg; save(d);
  return 'PHP settings saved (PHP ' + ver + ')';
}

/* ---------- sftp ---------- */
const KEY_RE = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/=]{20,2000}( [^\r\n]{0,80})?$/;
function getKeys(s) { try { return fs.readFileSync(P.KEYS + '/' + s.user, 'utf8'); } catch (e) { return ''; } }
function saveKeys(domain, text) {
  const s = getSite(load(), domain);
  const lines = String(text || '').replace(/\r/g, '').split('\n').map((x) => x.trim()).filter(Boolean);
  if (lines.length > 10) throw new Error('At most 10 keys');
  lines.forEach((l, i) => { if (!KEY_RE.test(l)) throw new Error('Line ' + (i + 1) + ' is not a valid SSH public key'); });
  fs.mkdirSync(P.KEYS, { recursive: true, mode: 0o755 });
  const f = P.KEYS + '/' + s.user;
  if (!lines.length) { try { fs.unlinkSync(f); } catch (e) {} return 'SFTP keys removed'; }
  fs.writeFileSync(f, lines.join('\n') + '\n', { mode: 0o644 });
  return 'Saved ' + lines.length + ' SFTP key(s)';
}
function resetSftpPassword(domain) {
  const s = getSite(load(), domain), pass = rand(9);
  sh('chpasswd', [], s.user + ':' + pass);
  return 'New SFTP password for ' + s.user + ': ' + pass + '\n(shown only once)';
}

/* ================= Let's Encrypt (webroot) ================= */
const CERTBOT_SH = 'certbot certonly --webroot -w "$1" --non-interactive --agree-tos --no-eff-email -m "$2" --cert-name "$3" -d "$3" -d "www.$3" $4 || ' +
  'certbot certonly --webroot -w "$1" --non-interactive --agree-tos --no-eff-email -m "$2" --cert-name "$3" -d "$3" $4';
const certbotStep = (domain, email, force) => ['bash', ['-c', CERTBOT_SH, 'bash', P.WEBROOT, email, domain, force ? '--force-renewal' : '--keep-until-expiring']];
function certNamesOf(domain) {
  const o = c.soft('openssl', ['x509', '-noout', '-ext', 'subjectAltName', '-in', sys.certFile(domain)]);
  const names = []; let m; const re = /DNS:([A-Za-z0-9.*-]+)/g;
  while ((m = re.exec(o))) names.push(m[1].toLowerCase());
  return names.length ? names : [domain];
}
function sslDone(domain, email) {
  const d = load(), s = d.sites.find((x) => x.domain === domain);
  if (!s) throw new Error('Site no longer exists');
  if (!sys.certExists(domain)) throw new Error('Certbot finished but no certificate was found');
  const ns = Object.assign({}, s, { ssl: true, certNames: certNamesOf(domain) });
  applyNginx(domain + '.conf', nginxConf(ns));
  s.ssl = true; s.certNames = ns.certNames; if (email) d.email = email; save(d);
  sys.clearCertCache(); sys.clearSecCache();
  c.auditSys('SSL_ISSUED', domain + ' [' + ns.certNames.join(',') + ']');
}
function queueSsl(domain, email, force) {
  const d = load(), s = getSite(d, domain);
  email = String(email || d.email || '').trim();
  if (!EMAIL_RE.test(email)) throw new Error('Valid email required (Settings -> Let\'s Encrypt email)');
  runSteps('SSL ' + domain, [certbotStep(domain, email, force)], () => sslDone(domain, email));
  s.sslTry = { n: ((s.sslTry && s.sslTry.n) || 0) + 1, last: Date.now() }; save(d);
  return 'SSL request started for ' + domain + ' - see Tasks page. DNS must already point to this server.';
}
function sslOff(domain) {
  const d = load(), s = getSite(d, domain);
  const ns = Object.assign({}, s, { ssl: false });
  applyNginx(domain + '.conf', nginxConf(ns));
  try { sh('certbot', ['delete', '--cert-name', domain, '--non-interactive']); } catch (e) {}
  s.ssl = false; s.certNames = []; s.autoSsl = false; save(d);
  sys.clearCertCache();
  return 'SSL removed for ' + domain + ' (site is HTTP only now)';
}
function autoSslTick() {
  if (c.jobRunning()) return;
  const d = load();
  if (!EMAIL_RE.test(d.email || '')) return;
  const now = Date.now();
  const s = d.sites.find((x) => x.autoSsl && !x.ssl && (!x.sslTry || (x.sslTry.n < 12 && now - x.sslTry.last > 3600000)));
  if (!s) return;
  try { queueSsl(s.domain, d.email, false); c.auditSys('AUTO_SSL_TRY', s.domain); } catch (e) {}
}
async function dnsCheck(domain) {
  const r = { domain, a: [], aaaa: [], www: [], err: '' };
  try { r.a = await dnsP.resolve4(domain); } catch (e) { r.err = e.code || e.message; }
  try { r.aaaa = await dnsP.resolve6(domain); } catch (e) {}
  try { r.www = await dnsP.resolve4('www.' + domain); } catch (e) {}
  return r;
}

/* ================= panel on its own domain ================= */
function panelConf(domain, ssl) {
  if (!ssl) {
    return '# HostPanel panel domain (managed)\nserver {\n  listen 80;\n  listen [::]:80;\n  server_name ' + domain + ';\n' + acmeBlock() +
      '  location / { return 503 "HostPanel: the SSL certificate is being issued. Try again in a minute."; }\n}\n';
  }
  return '# HostPanel panel domain (managed)\nserver {\n  listen 80;\n  listen [::]:80;\n  server_name ' + domain + ';\n' + acmeBlock() + '  location / { return 301 https://$host$request_uri; }\n}\n' +
    'server {\n' + listen443() + '  server_name ' + domain + ';\n' + certPaths(domain) +
    '  client_max_body_size 1100m;\n  access_log ' + P.NGLOG + '/hostpanel.access.log;\n  error_log ' + P.NGLOG + '/hostpanel.error.log;\n' +
    '  location / {\n    proxy_pass https://127.0.0.1:' + c.PORT + ';\n    proxy_ssl_verify off;\n    proxy_http_version 1.1;\n    proxy_set_header Host $host;\n' +
    '    proxy_set_header X-Real-IP $remote_addr;\n    proxy_set_header X-HP-Proxy "' + c.getProxySecret() + '";\n    proxy_set_header X-Forwarded-Proto $scheme;\n' +
    '    proxy_request_buffering off;\n    proxy_buffering off;\n    proxy_read_timeout 1800s;\n    proxy_send_timeout 1800s;\n  }\n}\n';
}
function panelSslDone(domain) {
  if (!sys.certExists(domain)) throw new Error('Certbot finished but no certificate was found');
  applyNginx('hostpanel-panel.conf', panelConf(domain, true), 0o600);
  const d = load(); d.settings.panelDomain = domain; d.settings.panelSsl = true; save(d);
  sys.clearSecCache(); c.auditSys('PANEL_SSL_ISSUED', domain);
}
function setPanelDomain(domainIn, emailIn) {
  const domain = String(domainIn || '').trim().toLowerCase();
  if (!DOMAIN_RE.test(domain)) throw new Error('Invalid domain');
  const d = load();
  if (d.sites.find((x) => x.domain === domain)) throw new Error('That domain is already a hosted site');
  const email = String(emailIn || d.email || '').trim();
  if (!EMAIL_RE.test(email)) throw new Error('Valid email required for Let\'s Encrypt');
  if (c.jobRunning()) throw new Error('Another task is running (see Tasks page)');
  const old = d.settings.panelDomain;
  applyNginx('hostpanel-panel.conf', panelConf(domain, d.settings.panelSsl && old === domain && sys.certExists(domain)), 0o600);
  d.settings.panelDomain = domain; if (old !== domain) d.settings.panelSsl = false; d.email = email; save(d);
  runSteps('SSL panel domain ' + domain, [certbotStep(domain, email, false)], () => panelSslDone(domain));
  return 'Panel domain saved. Requesting the certificate - see Tasks. Then open https://' + domain;
}
function removePanelDomain() {
  const d = load(), dom = d.settings.panelDomain;
  if (!dom) throw new Error('No panel domain is set');
  if ((d.settings.directIps || []).length) setDirect([]); // never leave the panel reachable only through a domain we are removing
  removeNginx('hostpanel-panel.conf');
  try { sh('nginx', ['-t']); sh('systemctl', ['reload', 'nginx']); } catch (e) {}
  try { sh('certbot', ['delete', '--cert-name', dom, '--non-interactive']); } catch (e) {}
  const d2 = load(); d2.settings.panelDomain = ''; d2.settings.panelSsl = false; save(d2);
  sys.clearSecCache();
  return 'Panel domain removed. The panel is still available on port ' + c.PORT + '.';
}
function cleanIpList(text) {
  const out = [];
  String(text || '').split(/[\s,]+/).filter(Boolean).forEach((x) => {
    const [ip, bits] = x.split('/');
    if (!net.isIP(ip)) throw new Error('Not an IP address: ' + x.slice(0, 50));
    if (bits !== undefined && !(/^\d{1,3}$/.test(bits) && +bits <= (net.isIPv4(ip) ? 32 : 128))) throw new Error('Bad CIDR: ' + x.slice(0, 50));
    if (!out.includes(x)) out.push(x);
  });
  if (out.length > 20) throw new Error('At most 20 addresses');
  return out;
}
function setDirect(list) {
  const d = load(), st = d.settings, port = String(c.PORT);
  if (list.length && !(st.panelDomain && st.panelSsl)) throw new Error('Set up the panel domain with working SSL first, so you cannot lock yourself out.');
  (st.directIps || []).forEach((ip) => { try { sh('ufw', ['--force', 'delete', 'allow', 'from', ip, 'to', 'any', 'port', port, 'proto', 'tcp']); } catch (e) {} });
  try { sh('ufw', ['--force', 'delete', 'allow', port + '/tcp']); } catch (e) {}
  if (!list.length) sh('ufw', ['allow', port + '/tcp']);
  else list.forEach((ip) => sh('ufw', ['allow', 'from', ip, 'to', 'any', 'port', port, 'proto', 'tcp']));
  st.directIps = list; save(d); sys.clearSecCache();
  return list.length ? 'Port ' + port + ' now only accepts: ' + list.join(', ') + ' (the domain still works for everyone)' : 'Port ' + port + ' is open to everyone again';
}
function setPhpPolicy(policy) {
  if (!['strict', 'standard'].includes(policy)) throw new Error('Bad policy');
  const d = load(); d.settings.phpPolicy = policy; save(d);
  writePhpIni(policy, true);
  return 'PHP function policy: ' + policy;
}
function setSftpPassword(on) {
  const d = load(); d.settings.sftpPassword = !!on; save(d);
  writeSshd();
  return 'SFTP password login ' + (on ? 'enabled' : 'disabled (keys only)');
}

/* ================= databases (see lib/dbs.js) ================= */
// Back-compat helpers used by the app installer and the tests: database and user get the same name unless told otherwise.
function createDbCore(name, extra, cred) {
  cred = cred || {};
  return dbs.create({ name, user: cred.user || name, password: cred.password, site: (extra && extra.site) || '', ownerId: (extra && extra.ownerId) || 'system', extra, requireNewUser: !!cred.requireNewUser });
}
function createDb(name) {
  const r = createDbCore(name);
  return 'Database created\nDB name: ' + r.name + '\nDB user: ' + r.user + '\nPassword: ' + r.password + '\nHost: localhost\n(Password is shown only once)';
}
const dropDbQuiet = (name) => dbs.dropQuiet(name);
const dumpSteps = (name, base) => [
  ['mysqldump', ['--single-transaction', '--routines', '--events', '--result-file=' + base, name]],
  ['gzip', ['-f', base]], ['chmod', ['600', base + '.gz']]
];
const finalDeleteDb = (name) => dbs.finalDelete(name);
function deleteDb(name, skipBackup, confirm) {
  const d = load();
  if (!d.dbs.find((x) => x.name === name)) throw new Error('Database not found');
  if (confirm !== name) throw new Error('Confirmation did not match the database name - nothing was deleted');
  if (skipBackup) { finalDeleteDb(name); return 'Database deleted: ' + name + ' (no backup was kept)'; }
  runSteps('Final backup + drop database ' + name, dumpSteps(name, P.BACKUPS + '/db-' + name + '-' + c.stamp() + '.sql'), () => finalDeleteDb(name));
  return 'Taking a final dump first; the database is dropped when it finishes (see Tasks). The dump stays in Backups.';
}
function resetDbPass(name, user) {
  const d = load(), db = d.dbs.find((x) => x.name === name);
  if (!db) throw new Error('Database not found');
  user = user || db.users[0];
  if (!db.users.includes(user)) throw new Error('That user has no access to this database');
  const pass = dbs.setPassword(user);
  return 'New password for ' + user + ': ' + pass + '\n(shown only once)';
}

/* ================= backups ================= */
const BK_RE = /^(site|db)-[a-z0-9._-]+-\d{14}\.(tar\.gz|sql\.gz)$/;
const BK_STRIP = /-\d{14}\.(tar\.gz|sql\.gz)$/;
const listBackups = () => {
  try { return fs.readdirSync(P.BACKUPS).filter((f) => BK_RE.test(f)).map((f) => ({ f, s: fs.statSync(P.BACKUPS + '/' + f) })).sort((a, b) => b.s.mtimeMs - a.s.mtimeMs); } catch (e) { return []; }
};
function backupSite(domain) {
  const s = getSite(load(), domain);
  sys.requireDisk(P.BACKUPS, 90, 'the backup');
  runSteps('Backup site ' + domain, tarStep(P.BACKUPS + '/site-' + domain + '-' + c.stamp() + '.tar.gz', s.user));
  return 'Backup started - see Tasks page';
}
function backupDb(name) {
  sys.requireDisk(P.BACKUPS, 90, 'the backup');
  if (!load().dbs.find((x) => x.name === name)) throw new Error('Database not found');
  runSteps('Backup database ' + name, dumpSteps(name, P.BACKUPS + '/db-' + name + '-' + c.stamp() + '.sql'));
  return 'Backup started - see Tasks page';
}
function pruneBackups(keep) {
  const groups = {};
  listBackups().forEach((b) => { const k = b.f.replace(BK_STRIP, ''); (groups[k] = groups[k] || []).push(b); });
  Object.values(groups).forEach((g) => g.slice(keep).forEach((b) => { try { fs.unlinkSync(P.BACKUPS + '/' + b.f); } catch (e) {} }));
}
const RCLONE_RE = /^[A-Za-z0-9_.-]+:[A-Za-z0-9_./ -]*$/;
const hasRclone = () => c.ok('which', ['rclone']);
function saveBackupSchedule(f) {
  const d = load(), b = d.settings.backup;
  const hour = parseInt(f.hour, 10), keep = parseInt(f.keep, 10), remote = String(f.remote || '').trim();
  if (!(hour >= 0 && hour <= 23)) throw new Error('Hour must be 0-23');
  if (!(keep >= 1 && keep <= 60)) throw new Error('Keep 1-60 copies');
  if (remote && !RCLONE_RE.test(remote)) throw new Error('Remote looks like  r2:my-bucket/hostpanel');
  if (remote && !hasRclone()) throw new Error('rclone is not installed (apt install rclone, then run: rclone config)');
  Object.assign(b, { enabled: f.enabled === '1', hour, keep, remote });
  save(d);
  return b.enabled ? 'Daily backups at ' + String(hour).padStart(2, '0') + ':00 server time, keeping ' + keep + ' copies per item' + (remote ? ', copied to ' + remote : '') : 'Scheduled backups are OFF';
}
function backupAll(label) {
  sys.requireDisk(P.BACKUPS, 90, 'the backup');
  const d = load(), b = d.settings.backup, st = c.stamp(), steps = [];
  d.sites.forEach((s) => tarStep(P.BACKUPS + '/site-' + s.domain + '-' + st + '.tar.gz', s.user).forEach((x) => steps.push(x)));
  d.dbs.forEach((x) => dumpSteps(x.name, P.BACKUPS + '/db-' + x.name + '-' + st + '.sql').forEach((y) => steps.push(y)));
  if (!steps.length) throw new Error('Nothing to back up yet');
  if (b.remote && hasRclone()) steps.push(['rclone', ['copy', '--max-age', '72h', P.BACKUPS, b.remote]]);
  runSteps(label || 'Backup everything', steps, () => pruneBackups(b.keep));
  return 'Backup of all sites and databases started - see Tasks page';
}
function scheduledBackup() {
  const d = load(), b = d.settings.backup;
  if (!b.enabled || c.jobRunning()) return;
  const now = new Date(), pad = (n) => String(n).padStart(2, '0');
  const today = now.getFullYear() + '-' + pad(now.getMonth() + 1) + '-' + pad(now.getDate());
  if (now.getHours() !== b.hour || b.last === today) return;
  if (!d.sites.length && !d.dbs.length) return;
  b.last = today; save(d);
  backupAll('Scheduled backup');
  c.auditSys('BACKUP_SCHEDULED', today);
}
function restoreBackup(file, confirm) {
  if (!BK_RE.test(file) || !fs.existsSync(P.BACKUPS + '/' + file)) throw new Error('Backup not found');
  const d = load(), full = P.BACKUPS + '/' + file; let m;
  if ((m = /^site-(.+)-\d{14}\.tar\.gz$/.exec(file))) {
    const s = getSite(d, m[1]);
    if (confirm !== s.domain) throw new Error('Confirmation did not match - nothing was restored');
    sys.requireDisk(P.BACKUPS, 90, 'the restore');
    // 1) safety backup of the current state, 2) scan the archive, 3) empty the three site folders
    // (find -delete never follows symlinks, so a symlink planted by the site cannot redirect the restore),
    // 4) extract. The safety backup is the way back if anything fails after step 3.
    const emptyDirs = ['bash', ['-c', 'set -e; for d in "$@"; do if [ -d "$d" ]; then find "$d" -mindepth 1 -delete; fi; done', 'bash', s.home + '/public_html', s.home + '/tmp', s.home + '/logs']];
    const steps = tarStep(P.BACKUPS + '/site-' + s.domain + '-' + c.stamp() + '.tar.gz', s.user)
      .concat([[process.execPath, [path.join(__dirname, 'archive-check.js'), full, s.user, '--allow-symlinks']], emptyDirs, ['tar', ['-xzpf', full, '-C', P.HOMES]]]);
    runSteps('Restore site ' + s.domain, steps);
    return 'Restore started for ' + s.domain + '. A safety backup of the current state is taken first, the archive is scanned, and the site folders are replaced by the backup contents. See Tasks.';
  }
  if ((m = /^db-([a-z][a-z0-9_]*)-\d{14}\.sql\.gz$/.exec(file))) {
    const name = m[1];
    if (!d.dbs.find((x) => x.name === name)) throw new Error('Database ' + name + ' is not registered in the panel');
    if (confirm !== name) throw new Error('Confirmation did not match - nothing was restored');
    const steps = dumpSteps(name, P.BACKUPS + '/db-' + name + '-' + c.stamp() + '.sql').concat([['bash', ['-o', 'pipefail', '-c', 'gunzip -c "$1" | mysql "$2"', 'bash', full, name]]]);
    runSteps('Restore database ' + name, steps);
    return 'Restore started for database ' + name + '. A safety dump is taken first. See Tasks.';
  }
  throw new Error('Cannot restore this file');
}

/* ================= cron / logs ================= */
const CRON_HINT = '# m h dom mon dow command   (runs as the site user, no shell login)\n# Laravel scheduler:\n# * * * * * cd /home/USER/public_html && /usr/bin/php artisan schedule:run >> /dev/null 2>&1\n# WordPress cron (after DISABLE_WP_CRON in wp-config.php):\n# */5 * * * * cd /home/USER/public_html && /usr/bin/php wp-cron.php >> /dev/null 2>&1\n';
function getCron(domain) {
  const s = getSite(load(), domain); let cur = '';
  try { cur = sh('crontab', ['-l', '-u', s.user]); } catch (e) {}
  return { s, text: cur || CRON_HINT.replace(/USER/g, s.user) };
}
function saveCron(domain, text) {
  const s = getSite(load(), domain), txt = String(text || '').replace(/\r\n/g, '\n').replace(/\0/g, '');
  if (txt.length > 8192) throw new Error('Crontab too long');
  txt.split('\n').forEach((l, i) => {
    l = l.trim();
    if (!l || l[0] === '#' || /^[A-Za-z_][A-Za-z0-9_]*\s*=/.test(l)) return;
    if (!/^(@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|(\S+\s+){5})\S/.test(l)) throw new Error('Invalid cron line ' + (i + 1) + ': ' + l.slice(0, 60));
  });
  sh('crontab', ['-u', s.user, '-'], txt.endsWith('\n') ? txt : txt + '\n');
  return 'Crontab saved';
}
function tailLog(domain, type) {
  const s = getSite(load(), domain);
  if (type === 'app') return runtime.journal(s);
  const file = type === 'php' ? s.home + '/logs/php_error.log' : P.NGLOG + '/' + s.domain + '.' + (type === 'access' ? 'access' : 'error') + '.log';
  if (!fs.existsSync(file)) return '(no log yet)';
  try { return sh('tail', ['-n', '300', file]); } catch (e) { return errMsg(e); }
}

module.exports = {
  applyNginx, http2Directive, setOwner, TYPES, PHP_TYPES, PROXY_TYPES, isProxyType, hasPhp, siteUser, RESERVED_DB, DOMAIN_RE, EMAIL_RE, NAME_RE, getSite, ensureBase, createSite, deleteSite, updatePhp, getKeys, saveKeys, resetSftpPassword,
  queueSsl, sslOff, autoSslTick, dnsCheck, setPanelDomain, removePanelDomain, cleanIpList, setDirect, setPhpPolicy, setSftpPassword,
  createDb, createDbCore, dropDbQuiet, deleteDb, resetDbPass, listBackups, backupSite, backupDb, saveBackupSchedule, scheduledBackup, backupAll, BK_RE, pruneBackups, restoreBackup, hasRclone,
  getCron, saveCron, tailLog, defCfg, nginxConf, poolConf, panelConf
};
