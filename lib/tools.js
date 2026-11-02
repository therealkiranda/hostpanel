'use strict';
// Server tools the administrator can add with one click from the panel (an auto-update only swaps panel files, it never
// runs the installer, so anything new that needs system packages is installed on demand, as a visible background task).
const fs = require('fs');
const c = require('./core');
const pma = require('./pma');
const sys = require('./sys');

// Extra PHP versions. Ubuntu's own repositories carry only one PHP version, so a missing version comes from the PHP
// community repositories: the ondrej/php PPA on Ubuntu 22.04 / 24.04, and packages.sury.org on newer Ubuntu releases (the
// PPA publishes nothing for them and, once added, breaks every "apt-get update"). The script below
//  1. removes a leftover ondrej PPA entry on releases it does not support (heals a server where it was added before),
//  2. stops at once when the Ubuntu archive already has the version,
//  3. otherwise adds the right source, and refuses (changing nothing) when no source exists for this release.
const PHP_REPO_SH = [
  'set -eu',
  'V="$1"; SRC="${HP_APT_SOURCES:-/etc/apt/sources.list.d}"; . "${HP_OS_RELEASE:-/etc/os-release}"; CN="${VERSION_CODENAME:-}"',
  'case "$CN" in jammy|noble) ;; *) rm -f "$SRC"/ondrej-ubuntu-php-*.sources "$SRC"/ondrej-ubuntu-php-*.list ;; esac',
  'if apt-cache show "php$V-fpm" >/dev/null 2>&1; then echo "PHP $V is available from the Ubuntu repositories"; exit 0; fi',
  'case "$CN" in',
  '  jammy|noble) apt-get install -y software-properties-common; add-apt-repository -y ppa:ondrej/php ;;',
  '  *) curl -fsSI "https://packages.sury.org/php/dists/$CN/Release" >/dev/null || { echo "No PHP $V package source exists for Ubuntu \'$CN\' yet: the ondrej PPA stops at 24.04 and packages.sury.org has no \'$CN\' suite. Nothing was changed."; exit 1; }',
  '     curl -fsSL -o /tmp/hp-sury-keyring.deb https://packages.sury.org/debsuryorg-archive-keyring.deb; dpkg -i /tmp/hp-sury-keyring.deb; rm -f /tmp/hp-sury-keyring.deb',
  '     printf "Types: deb\\nURIs: https://packages.sury.org/php/\\nSuites: %s\\nComponents: main\\nSigned-By: /usr/share/keyrings/debsuryorg-archive-keyring.gpg\\n" "$CN" > "$SRC/sury-php.sources" ;;',
  'esac'
].join('\n');
const PHP_EXT = ['fpm', 'cli', 'mysql', 'curl', 'gd', 'mbstring', 'xml', 'zip', 'intl', 'bcmath'];
const phpTool = (v) => ({
  label: 'PHP ' + v, summary: 'PHP ' + v + ' (latest ' + v + '.x patch release) with PHP-FPM, so a website can use it.',
  ready: () => sys.phpVersions().includes(v),
  steps: () => [
    ['bash', ['-c', PHP_REPO_SH, 'bash', v]],
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
module.exports = { TOOLS, install, PHP_REPO_SH };
