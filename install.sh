#!/usr/bin/env bash
# HostPanel 1.0.4 installer - Ubuntu 22.04 / 24.04 / 26.04.
# Run from the unzipped folder:  sudo bash install.sh
# Safe to run again: it upgrades the panel and keeps your data, sites and databases.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root:  sudo bash install.sh"; exit 1; }
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || { echo "HostPanel supports Ubuntu only (22.04 or newer)."; exit 1; }
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SRC/server.js" ] && [ -d "$SRC/lib" ] && [ -d "$SRC/public" ] || { echo "Run this script from inside the unzipped hostpanel folder (server.js, lib/, public/ must be next to it)."; exit 1; }
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
BASE=/opt/hostpanel
PORT=8443
VER=$(grep -m1 '"version"' "$SRC/package.json" | sed -E 's/.*"([0-9.]+)".*/\1/')
step() { echo; echo ">>> $*"; }

step "HostPanel $VER - checking the server"
if [ "$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)" -lt 900 ]; then echo "Warning: less than 1 GB RAM. HostPanel will work but PHP/MySQL need memory."; fi

step "Swap file (small servers need it)"
if [ "$(swapon --show | wc -l)" -eq 0 ]; then
  if fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile; then
    grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  else
    echo "(could not create a swap file on this filesystem - continuing without it)"; rm -f /swapfile
  fi
fi

step "Installing packages and security patches (this takes a few minutes)"
apt-get update -y
DB_PKG=""
if ! systemctl cat mysql >/dev/null 2>&1 && ! systemctl cat mariadb >/dev/null 2>&1; then DB_PKG="mariadb-server"; fi
apt-get install -y $DB_PKG nginx php-fpm php-cli php-mysql php-curl php-gd php-mbstring php-xml php-zip php-intl php-bcmath \
  certbot ufw fail2ban cron curl unzip zip git openssl ca-certificates gnupg composer unattended-upgrades needrestart openssh-server dnsutils python3 python3-venv python3-pip
apt-get install -y rclone >/dev/null 2>&1 || echo "(rclone not available - off-server backups can be added later)"
apt-get -y -o Dpkg::Options::=--force-confold upgrade

if ! command -v node >/dev/null || [ "$(node -v | cut -d. -f1 | tr -d v)" -lt 20 ]; then
  step "Installing Node.js"
  curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
  apt-get install -y nodejs
fi

step "Automatic security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CFG'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
CFG
mkdir -p /etc/needrestart/conf.d
cat > /etc/needrestart/conf.d/hostpanel.conf <<'CFG'
$nrconf{restart} = 'a';
$nrconf{override_rc}->{qr(^hostpanel)} = 0;
CFG

step "PHP services"
for d in /etc/php/*/fpm; do
  v=$(basename "$(dirname "$d")")
  systemctl enable --now "php${v}-fpm"
done

step "Nginx hardening"
# Hide the Nginx version. Reuse whatever directive nginx.conf already has: a second one makes Nginx refuse to start.
NGMAIN=/etc/nginx/nginx.conf
rm -f /etc/nginx/conf.d/00-hostpanel.conf
if grep -Eq '^\s*server_tokens\s' "$NGMAIN"; then
  sed -i -E 's/^(\s*)server_tokens\s+[^;]*;/\1server_tokens off;/' "$NGMAIN"
elif grep -Eq '^\s*#\s*server_tokens' "$NGMAIN"; then
  sed -i -E '0,/^\s*#\s*server_tokens.*/s//\tserver_tokens off;/' "$NGMAIN"
else
  sed -i -E '0,/^\s*http\s*\{/s//http {\n\tserver_tokens off;/' "$NGMAIN"
fi
[ -f /etc/nginx/sites-available/default ] && cp -n /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak || true
NGVER=$(nginx -v 2>&1 | sed -E 's/.*nginx\/([0-9]+\.[0-9]+\.[0-9]+).*/\1/')
if [ "$(printf '%s\n%s\n' 1.19.4 "$NGVER" | sort -V | head -1)" = "1.19.4" ]; then
  cat > /etc/nginx/sites-available/default <<'NG'
# Unknown hostnames get nothing (no site leaks through the bare IP)
server { listen 80 default_server; listen [::]:80 default_server; server_name _; return 444; }
server { listen 443 ssl default_server; listen [::]:443 ssl default_server; server_name _; ssl_reject_handshake on; }
NG
else
  # nginx < 1.19.4 (Ubuntu 22.04) has no ssl_reject_handshake: answer unknown names with a throw-away certificate and close the connection
  install -d -m 755 /etc/nginx/hostpanel
  [ -f /etc/nginx/hostpanel/default.key ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout /etc/nginx/hostpanel/default.key -out /etc/nginx/hostpanel/default.crt -subj "/CN=invalid" 2>/dev/null
  chmod 600 /etc/nginx/hostpanel/default.key
  cat > /etc/nginx/sites-available/default <<'NG'
# Unknown hostnames get nothing (no site leaks through the bare IP)
server { listen 80 default_server; listen [::]:80 default_server; server_name _; return 444; }
server { listen 443 ssl default_server; listen [::]:443 ssl default_server; server_name _; ssl_certificate /etc/nginx/hostpanel/default.crt; ssl_certificate_key /etc/nginx/hostpanel/default.key; return 444; }
NG
fi
ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
mkdir -p /var/www/letsencrypt
DB_SVC=mysql; if systemctl cat mariadb >/dev/null 2>&1 && ! systemctl cat mysql >/dev/null 2>&1; then DB_SVC=mariadb; fi
systemctl enable --now nginx cron "$DB_SVC"
nginx -t && systemctl reload nginx

step "Database: localhost only"
mkdir -p /etc/mysql/conf.d
cat > /etc/mysql/conf.d/99-hostpanel.cnf <<'CFG'
[mysqld]
bind-address = 127.0.0.1
local_infile = 0
CFG
systemctl restart "$DB_SVC" || echo "(database restart skipped)"

step "Kernel network hardening"
cat > /etc/sysctl.d/99-hostpanel.conf <<'CFG'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.dmesg_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
CFG
sysctl --system >/dev/null

step "Fail2ban (SSH + panel login)"
touch /var/log/hostpanel-auth.log && chmod 600 /var/log/hostpanel-auth.log
cat > /etc/fail2ban/filter.d/hostpanel.conf <<'CFG'
[Definition]
failregex = ^\S+ LOGIN_FAIL ip=<HOST>(\s.*)?$
CFG
cat > /etc/fail2ban/jail.d/hostpanel.local <<CFG
[sshd]
enabled = true

[hostpanel]
enabled = true
backend = auto
port = http,https,$PORT
filter = hostpanel
logpath = /var/log/hostpanel-auth.log
maxretry = 5
findtime = 15m
bantime = 1h
CFG
cat > /etc/logrotate.d/hostpanel <<'CFG'
/var/log/hostpanel-auth.log { weekly rotate 8 compress missingok notifempty copytruncate }
/opt/hostpanel/data/audit.log { monthly rotate 12 compress missingok notifempty copytruncate }
CFG
systemctl enable fail2ban && systemctl restart fail2ban

step "Firewall"
SSHP=$(sshd -T 2>/dev/null | awk '/^port /{p=$2} END{print p}' || true); SSHP=${SSHP:-22}
ufw limit "${SSHP}/tcp" >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
# keep an existing IP restriction on re-install; otherwise open the panel port
if ! ufw status | grep -E "^${PORT}/tcp|${PORT}/tcp.*ALLOW|[[:space:]]${PORT}[[:space:]]" >/dev/null 2>&1; then ufw allow "${PORT}/tcp" >/dev/null; fi
ufw --force enable >/dev/null

step "Installing panel files"
install -d -m 755 "$BASE"
install -d -m 700 "$BASE/data" "$BASE/backups" "$BASE/updates"
rm -rf "$BASE/lib" "$BASE/public"
cp -a "$SRC/lib" "$SRC/public" "$BASE/"
install -m 600 "$SRC/server.js" "$BASE/server.js"
install -m 600 "$SRC/cli.js" "$BASE/cli.js"
install -m 644 "$SRC/worker.js" "$BASE/worker.js"
install -m 644 "$SRC/package.json" "$BASE/package.json"
[ -f "$SRC/package-lock.json" ] && install -m 644 "$SRC/package-lock.json" "$BASE/package-lock.json"
chmod -R go-w "$BASE/lib" "$BASE/public"
# every folder 755 and every file 644 under lib/ and public/ (covers lib/routes and lib/apps too)
find "$BASE/lib" "$BASE/public" -type d -exec chmod 755 {} +
find "$BASE/lib" "$BASE/public" -type f -exec chmod 644 {} +
chmod 755 "$BASE"
install -d -m 755 "$BASE/bin"   # verified helper tools for the App Installer (WP-CLI); root-owned so a website can never replace them
# Exact locked versions, no dependency install scripts (reproducible, and nothing runs as root from the registry).
if [ -f "$BASE/package-lock.json" ]; then
  (cd "$BASE" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund)
else
  (cd "$BASE" && npm install --omit=dev --ignore-scripts --no-audit --no-fund)
fi
(cd "$BASE" && npm audit --omit=dev || true)
printf '#!/bin/sh\nexec /usr/bin/env node /opt/hostpanel/cli.js "$@"\n' > /usr/local/bin/hostpanel-cli
chmod 755 /usr/local/bin/hostpanel-cli

step "SSH login banner"
# Shown on every interactive ssh login (password or key) through Ubuntu's pam_motd. Text: /etc/hostpanel/motd (never overwritten).
node "$BASE/cli.js" motd install || echo "(could not install the SSH login banner - continuing)"

if [ ! -f "$BASE/data/panel.key" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout "$BASE/data/panel.key" -out "$BASE/data/panel.crt" -subj "/CN=hostpanel" 2>/dev/null
  chmod 600 "$BASE/data/panel.key"
fi

# NOTE: no systemd sandboxing options on purpose. The panel is the server administrator: it creates users,
# sets setgid folders, runs apt and certbot. Options like RestrictSUIDSGID / NoNewPrivileges break those jobs.
cat > /etc/systemd/system/hostpanel.service <<'UNIT'
[Unit]
Description=HostPanel
After=network-online.target nginx.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/env node /opt/hostpanel/server.js
WorkingDirectory=/opt/hostpanel
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable hostpanel
systemctl restart hostpanel
sleep 5

if ! systemctl is-active --quiet hostpanel; then echo "Panel failed to start:"; journalctl -u hostpanel -n 40 --no-pager; exit 1; fi
IP=$(curl -s --max-time 6 https://checkip.amazonaws.com || hostname -I | awk '{print $1}')
echo
echo "========================================================="
echo " HostPanel $VER is installed"
echo
echo " Open:   https://$IP:$PORT   (the browser warns about a self-signed certificate - that is normal for now)"
if [ -f /root/hostpanel-credentials.txt ]; then sed 's/^/ /' /root/hostpanel-credentials.txt; else echo " Upgrade complete - use your existing login"; fi
echo
echo " Next steps:"
echo "  1. Sign in and change the password (Account page), then enable 2FA"
echo "  2. Settings -> Panel domain: use  panel.yourdomain.com  with a free Let's Encrypt certificate"
echo "  3. Open ports 22, 80, 443, $PORT (and 8444 if you enable phpMyAdmin) in your cloud firewall / security group"
echo " Install WordPress or Laravel in one click:  App Installer (left menu)"
echo " Locked out or forgot the password?   sudo hostpanel-cli reset-password"
echo "========================================================="
