'use strict';
// Server tools the administrator can add with one click from the panel (an auto-update only swaps panel files, it never
// runs the installer, so anything new that needs system packages is installed on demand, as a visible background task).
const fs = require('fs');
const c = require('./core');
const pma = require('./pma');

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
