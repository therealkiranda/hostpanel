'use strict';
// Node.js and Python websites: nginx proxies the domain to 127.0.0.1:PORT and a systemd service (running as the
// website's own Linux user, never root) keeps the application alive. Logs go to the journal, not to a file in the
// site's folder: systemd opens files as root, and a symlink planted by the site could then make it append to /etc/*.
const fs = require('fs');
const c = require('./core');
const { sh, soft, ok, P } = c;

const UNIT_DIR = process.env.HP_SYSTEMD || '/etc/systemd/system';
const KINDS = {
  node: { label: 'Node.js', defaultCmd: 'node server.js' },
  python: { label: 'Python', defaultCmd: 'venv/bin/python app.py' }
};
const CMD_RE = /^[A-Za-z0-9][A-Za-z0-9 ._\/:=@+,{}-]{0,199}$/;
const unitName = (s) => 'hp-app-' + s.user;
const unitFile = (s) => UNIT_DIR + '/' + unitName(s) + '.service';

function cleanCmd(v, kind) {
  const cmd = String(v || '').trim() || KINDS[kind].defaultCmd;
  if (!CMD_RE.test(cmd)) throw new Error('Start command: letters, numbers, spaces and . _ / : = @ + , - only (no quotes, $, &, ;, |). Put anything complicated into a package.json script or a shell script file.');
  if (/\.\.|(^|\s)\/(etc|root|proc|sys|dev)\b/.test(cmd)) throw new Error('That start command is not allowed');
  return cmd;
}

function unitText(s) {
  const kind = KINDS[s.type]; if (!kind) throw new Error('Not an application website');
  if (!/^w[0-9a-f]{10}$/.test(s.user) || !/^\d{4,5}$/.test(String(s.port))) throw new Error('Unsafe service settings');
  const cmd = cleanCmd(s.cmd, s.type).replace(/\{PORT\}/g, String(s.port));
  const root = s.home + '/public_html', tmp = s.home + '/tmp';
  return '# Managed by HostPanel - changes made here are overwritten\n[Unit]\nDescription=HostPanel ' + kind.label + ' application for ' + s.domain + '\nAfter=network.target\n\n[Service]\n' +
    'Type=simple\nUser=' + s.user + '\nGroup=' + s.user + '\nWorkingDirectory=' + root + '\n' +
    'Environment=PORT=' + s.port + '\nEnvironment=HOST=127.0.0.1\nEnvironment=NODE_ENV=production\nEnvironment=HOME=' + tmp + '\nEnvironment=TMPDIR=' + tmp + '\nEnvironment=PATH=' + root + '/venv/bin:/usr/local/bin:/usr/bin:/bin\n' +
    'ExecStart=/bin/sh -c \'exec ' + cmd + '\'\nRestart=on-failure\nRestartSec=3\nStartLimitIntervalSec=60\nStartLimitBurst=8\n' +
    'SyslogIdentifier=' + unitName(s) + '\n' +
    // other websites\' folders are invisible to the application, and it can never gain privileges
    'NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=full\nProtectKernelTunables=true\nProtectControlGroups=true\nRestrictSUIDSGID=true\nTemporaryFileSystem=/home:ro\nBindPaths=' + s.home + '\n' +
    'MemoryMax=' + (s.memoryMax || '768M') + '\nTasksMax=300\n\n[Install]\nWantedBy=multi-user.target\n';
}

function install(s) {
  fs.writeFileSync(unitFile(s), unitText(s), { mode: 0o644 });
  sh('systemctl', ['daemon-reload']);
  sh('systemctl', ['enable', unitName(s)]);
}
function remove(s) {
  const t = (fn) => { try { fn(); } catch (e) {} };
  t(() => sh('systemctl', ['disable', '--now', unitName(s)]));
  t(() => fs.unlinkSync(unitFile(s)));
  t(() => sh('systemctl', ['daemon-reload']));
  t(() => sh('systemctl', ['reset-failed', unitName(s)]));
}
const ACTIONS = ['start', 'stop', 'restart'];
function action(s, a) {
  if (!ACTIONS.includes(a)) throw new Error('Not allowed');
  if (!fs.existsSync(unitFile(s))) install(s);
  sh('systemctl', [a, unitName(s)]);
  return s.domain + ': application ' + a + (a === 'stop' ? 'ped' : a === 'start' ? 'ed' : 'ed');
}
const active = (s) => ok('systemctl', ['is-active', '--quiet', unitName(s)]);
function journal(s) {
  const out = soft('journalctl', ['-u', unitName(s), '-n', '300', '--no-pager', '-o', 'short-iso']);
  return out || '(no output yet)';
}

/* ---------- placeholder applications, so a new site answers immediately ---------- */
const NODE_APP = "const http = require('http');\nconst port = process.env.PORT || 3000;\nhttp.createServer((req, res) => {\n  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });\n  res.end('<h1>' + (req.headers.host || 'Node.js') + '</h1><p>Your Node.js app is running. Replace server.js with your own application.</p>');\n}).listen(port, '127.0.0.1');\n";
const PY_APP = "import os\nfrom http.server import BaseHTTPRequestHandler, HTTPServer\n\nclass H(BaseHTTPRequestHandler):\n    def do_GET(self):\n        self.send_response(200)\n        self.send_header('Content-Type', 'text/html; charset=utf-8')\n        self.end_headers()\n        self.wfile.write(b'<h1>Python app</h1><p>Your Python app is running. Replace app.py with your own application.</p>')\n\nHTTPServer(('127.0.0.1', int(os.environ.get('PORT', '8000'))), H).serve_forever()\n";
const placeholder = (type) => (type === 'node' ? { name: 'server.js', body: NODE_APP } : { name: 'app.py', body: PY_APP });

// Free port for a new application: not used by another site, not the panel, not a well-known service.
function nextPort(d) {
  const used = new Set((d.sites || []).map((x) => x.port).filter(Boolean).concat([c.PORT, 3306, 8443, 8444]));
  for (let p = 3001; p < 4000; p++) if (!used.has(p)) return p;
  throw new Error('No free application port left (3001-3999)');
}

/* ---------- background jobs (run as the website's Linux user) ---------- */
const siteEnv = (s) => ({ HOME: s.home + '/tmp', TMPDIR: s.home + '/tmp', npm_config_cache: s.home + '/tmp/npm-cache', PIP_CACHE_DIR: s.home + '/tmp/pip-cache', PIP_DISABLE_PIP_VERSION_CHECK: '1' });
async function ensureVenv(s, log, exec) {
  const root = s.home + '/public_html';
  if (fs.existsSync(root + '/venv/bin/python')) return;
  log('Creating the Python virtual environment');
  try { await exec.runAs(s, '/usr/bin/python3', ['-m', 'venv', root + '/venv'], { env: siteEnv(s), cwd: root, onLine: (l) => log('  ' + l) }); }
  catch (e) { throw new Error('Could not create the virtual environment. Is python3-venv installed? (Administrator: Settings -> Server tools -> Python.) ' + c.errMsg(e).slice(0, 200)); }
}
async function bootstrap(s, log, exec) {
  exec = exec || require('./siteexec');
  if (s.type === 'python') await ensureVenv(s, log, exec);
  log('Starting the application');
  sh('systemctl', ['restart', unitName(s)]);
}
async function installDeps(s, log, exec) {
  exec = exec || require('./siteexec');
  const root = s.home + '/public_html', env = siteEnv(s), onLine = (l) => log('  ' + l);
  if (s.type === 'node') {
    const lock = fs.existsSync(root + '/package-lock.json');
    if (!fs.existsSync(root + '/package.json')) throw new Error('There is no package.json in public_html');
    log('Running npm ' + (lock ? 'ci' : 'install') + ' as ' + s.user);
    await exec.runAs(s, '/usr/bin/npm', [lock ? 'ci' : 'install', '--omit=dev', '--no-audit', '--no-fund'], { env, cwd: root, timeoutMs: 900000, onLine });
  } else {
    await ensureVenv(s, log, exec);
    if (!fs.existsSync(root + '/requirements.txt')) throw new Error('There is no requirements.txt in public_html');
    log('Running pip install -r requirements.txt as ' + s.user);
    await exec.runAs(s, root + '/venv/bin/pip', ['install', '--no-input', '-r', 'requirements.txt'], { env, cwd: root, timeoutMs: 900000, onLine });
  }
  log('Restarting the application');
  sh('systemctl', ['restart', unitName(s)]);
}

module.exports = { bootstrap, installDeps, siteEnv, KINDS, CMD_RE, ACTIONS, unitName, unitFile, cleanCmd, unitText, install, remove, action, active, journal, placeholder, nextPort };
