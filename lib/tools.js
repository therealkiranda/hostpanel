'use strict';
// Server tools the administrator can add with one click from the panel (an auto-update only swaps panel files, it never
// runs the installer, so anything new that needs system packages is installed on demand, as a visible background task).
const fs = require('fs');
const c = require('./core');
const pma = require('./pma');
const sys = require('./sys');

// Extra PHP versions. Ubuntu's own repositories only carry one PHP version, so when the requested one is not there the
// well-known ondrej/php PPA is added first (it is what almost every Ubuntu PHP host uses). Runs as a visible task.
const PHP_EXT = ['fpm', 'cli', 'mysql', 'curl', 'gd', 'mbstring', 'xml', 'zip', 'intl', 'bcmath'];
const phpTool = (v) => ({
  label: 'PHP ' + v, summary: 'PHP ' + v + ' (latest ' + v + '.x patch release) with PHP-FPM, so a website can use it.',
  ready: () => sys.phpVersions().includes(v),
  steps: () => [
    ['bash', ['-c', 'if ! apt-cache show php' + v + '-fpm >/dev/null 2>&1; then apt-get update && apt-get install -y software-properties-common && add-apt-repository -y ppa:ondrej/php; fi']],
    ['apt-get', ['update']],
    ['apt-get', ['install', '-y', '-o', 'Dpkg::Options::=--force-confold'].concat(PHP_EXT.map((e) => 'php' + v + '-' + e))],
    ['systemctl', ['enable', '--now', 'php' + v + '-fpm']]
  ],
  done: () => { try { require('./sites').writePhpIni(c.load().settings.phpPolicy, true); } catch (e) { c.auditSys('PHP_INI_FAILED', c.errMsg(e)); } }
});

const TOOLS = {
  phpmyadmin: {
    label: 'phpMyAdmin', summary: 'Database manager with per-website sign-in (port ' + pma.PORT + ').',
    ready: () => pma.ready(),
    steps: () => [
      ['bash', ['-c', 'printf "%s\\n" "phpmyadmin phpmyadmin/dbconfig-install boolean false" "phpmyadmin phpmyadmin/reconfigure-webserver multiselect none" | debconf-set-selections']],
      ['apt-get', ['update']],
      ['apt-get', ['install', '-y', '--no-install-recommends', '-o', 'Dpkg::Options::=--force-confold', 'phpmyadmin', 'php-mbstring', 'php-xml', 'php-zip', 'php-gd', 'php-curl', 'php-mysql']],
      // phpMyAdmin recommends Apache; HostPanel uses nginx only, so make sure Apache never grabs port 80
      ['bash', ['-c', 'if systemctl is-enabled apache2 >/dev/null 2>&1; then systemctl disable --now apache2; fi; true']]
    ],
    done: () => { pma.setup(); }
  },
  php84: phpTool('8.4'),
  php85: phpTool('8.5'),
  python: {
    label: 'Python 3', summary: 'Python, venv and pip for Python websites.',
    ready: () => fs.existsSync('/usr/bin/python3') && c.ok('/usr/bin/python3', ['-c', 'import venv, ensurepip']),
    steps: () => [['apt-get', ['update']], ['apt-get', ['install', '-y', 'python3', 'python3-venv', 'python3-pip']]],
    done: () => {}
  }
};
function install(id) {
  const t = TOOLS[id]; if (!t) throw new Error('Unknown tool');
  if (t.ready()) throw new Error(t.label + ' is already installed');
  c.runSteps('Install ' + t.label, t.steps(), t.done);
  c.setJobOwner('system');
  return t.label + ' installation started - see the Tasks page.';
}
module.exports = { TOOLS, install };
