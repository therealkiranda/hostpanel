# 🚀 HostPanel 1.0.4

![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-009639?style=for-the-badge&logo=nginx&logoColor=white)
![PHP](https://img.shields.io/badge/PHP-777BB4?style=for-the-badge&logo=php&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![MariaDB](https://img.shields.io/badge/MariaDB-003545?style=for-the-badge&logo=mariadb&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Let's Encrypt](https://img.shields.io/badge/Let's%20Encrypt-003A70?style=for-the-badge&logo=letsencrypt&logoColor=white)

> A lightweight, blazing-fast hosting control panel for **Ubuntu + Nginx + PHP-FPM + MariaDB**.  
> *Think "CloudPanel / cPanel, but open, minimal, and entirely yours."*

---

## 📌 Overview

HostPanel gives you absolute control over your web server without the bloat of traditional panels. It provides automated security, effortless SSL provisioning, background backup routines, and isolated site environments—all optimized for low-resource VPS setups.

- 🌐 **Websites & Proxies:** Native support for PHP / WordPress, Laravel, or custom reverse-proxies (Node.js, Python, Go, etc.).
- 🔒 **Automated SSL:** Free, auto-renewing Let's Encrypt SSL certificates for every hosted site.
- 🎯 **Custom Panel Domain:** Run your control panel securely under `https://panel.yourdomain.com` with valid certificates alongside standard direct port access (`IP:8443`).
- 📁 **File & Site Management:** Built-in web File Manager, 1GB upload limit, embedded code editor, and SFTP-only isolated site users (strictly no shell access).
- 🧩 **App Installer:** one-click WordPress (and Laravel) on a new or existing site — website, database, configuration and first admin created for you.
- 💾 **Backups & Recovery:** Scheduled or manual backups, easy multi-point restores, and off-server destination sync powered by `rclone`.
- 🛡️ **Hardened Security:** Security score analysis, Fail2ban integration, UFW status monitoring, 2FA authentication, activity audit logging, and automated updates.

---

## ⚙️ System Requirements

| Requirement | Specification |
| :--- | :--- |
| **OS** | Fresh installation of **Ubuntu 22.04 LTS / 24.04 LTS / 26.04 LTS** |
| **Resources** | Minimum **1 GB RAM** |
| **Access** | `root` or a user with elevated `sudo` privileges via SSH |
| **Inbound Ports** | Open ports: **`22`**, **`80`**, **`443`**, and **`8443`** |

> [!TIP]
> **First time installing?** Take a server **snapshot** prior to running the installer so you can easily roll back if necessary.

---

## ⚡ Quick Start & Installation

The installation routine takes approximately 5–10 minutes and automatically configures Nginx, PHP-FPM, MariaDB (bound to localhost), Certbot, Fail2ban, UFW, security updates, swap memory, and the core panel application.

### 1. Upload Assets
From your local terminal or Termux, upload the release package to your server:
```bash
scp hostpanel-1.0.zip root@YOUR_SERVER_IP:/root/
```

### 2. Execute Installer
Connect via SSH and execute the setup script:
```bash
ssh root@YOUR_SERVER_IP
apt-get update && apt-get install -y unzip
unzip hostpanel-1.0.zip
cd hostpanel-1.0
sudo bash install.sh
```

Upon completion, your terminal will display your initial login details:
```text
Open:           https://YOUR_SERVER_IP:8443
Panel user:     admin
Panel password: <generated-password>
```
*(Credentials are temporarily mirrored at `/root/hostpanel-credentials.txt` until changed.)*

### 3. Initial Configuration
1. Navigate to `https://YOUR_SERVER_IP:8443` in your browser. *(Bypass the initial self-signed SSL warning).*
2. Sign in and immediately update your password (minimum 12 characters).
3. Navigate to **Account → Enable 2FA** to pair your preferred authenticator app.

---

## 🌐 Custom Panel Domain Setup

Bind your administrative dashboard to your own domain name (e.g., `panel.yourdomain.com`):

1. **DNS Setup:** Create an `A` record pointing `panel.yourdomain.com` to your server's IP address.
   > *Note for Cloudflare users:* Set proxy mode to **DNS Only** (grey cloud) during initial SSL issuance. You may re-enable proxying afterwards.
2. **Enable Domain:** Inside HostPanel, navigate to **Settings → Panel domain**. Enter `panel.yourdomain.com` and your contact email, then click **Enable panel domain**.
3. **Verify:** Monitor the **Tasks** window. Once complete, visit `https://panel.yourdomain.com` to confirm valid Let's Encrypt SSL termination.
4. *(Optional)* **Restrict Direct Access:** Go to **Settings → Direct access on port 8443** to restrict raw port access to specific IPs while keeping domain routing open.

---

## 🧩 App Installer (WordPress, Laravel)

Open **App Installer** in the left menu, pick an application and fill the short form:

- **Install on:** a brand-new website (enter the domain; HostPanel creates the site, PHP pool, nginx config and SFTP user) or an existing one.
- **Folder:** optional sub-folder such as `blog` (WordPress). Empty = site root.
- **HTTPS:** tick it to use `https://` URLs and have a free Let's Encrypt certificate requested automatically a few minutes after the install (DNS must already point to the server).
- WordPress asks for site title, administrator username/email/password (a strong password is pre-generated — copy it, it is not stored) and language.

Progress and the final login URLs appear on the **Tasks** page. Installed apps are listed on the App Installer page and on each website's page.

What it does for you: creates a dedicated database and user (random name and password), downloads the application, writes the configuration (`wp-config.php` / `.env`, mode 600), runs the installation, and records the result. Everything application-related runs **as the website's own Linux user**, never as root.

Safety rules: it never overwrites files (the target folder must be empty — only HostPanel's "site is ready" page is replaced); input is validated before anything is created; if any step fails, the database and files created by *that attempt* are removed and the placeholder page is restored, so you can simply retry. Uninstalling is not automated yet: delete the files in the File Manager and the database on the Databases page.

WordPress uses [WP-CLI](https://wp-cli.org) (downloaded once to `/opt/hostpanel/bin`, checked against a SHA-256 pinned in `lib/apps/wpcli.js`; WP-CLI itself verifies the WordPress.org checksum). Laravel uses Composer. Laravel is marked **Beta**.

### Adding another application
Add an entry to `lib/apps/catalog.js` and a handler module exporting `validate(input)`, `install({ x, site, target, db, host, log })` and `fields(env)` (copy `lib/apps/wordpress.js`). Use only the `host` adapters (`php`, `writeFile`, `readFile`, `ensureTool`, ...) so the engine can roll back and tests can fake the machine. Cover it in `test/apps-handlers.js`.

---

## 🔑 SSH login banner

The installer adds `/etc/update-motd.d/00-hostpanel`, which Ubuntu shows on **every interactive SSH login** (password or key; `scp`/`sftp`/`ssh host command` stay clean):

```text
########################################################
###               Welcome to Hostpanel               ###
########################################################

* Website:         https://www.khadkakiran.com.np
* Documentation:   coming soon
```

Edit `/etc/hostpanel/motd` to change the text (upgrades never overwrite it). The standard Ubuntu greeting is left in place; `sudo hostpanel-cli motd quiet` hides its noisy parts (help text, news, ESM ads) and `sudo hostpanel-cli motd default` restores them. Update-available and reboot-required notices are never hidden. Remove the banner with `sudo hostpanel-cli motd remove`.

---

## 💻 Managing Websites

### Adding a New Site
1. Go to **Websites → Add a website**.
2. Enter your domain, select your runtime (PHP version or Reverse Proxy), keep **Let's Encrypt** toggled, and submit.
3. Save the generated **SFTP credentials** (shown once).

### Deploying Content
- **SFTP Access:** Use any standard client (Port: `22`, Host: Server IP, Credentials: site SFTP user). 
  ```bash
  sftp wXXXXXXXXXX@YOUR_SERVER_IP
  ```
  *Site users are strictly chrooted and restricted from accessing system directories.*
- **File Manager:** Edit, upload, and modify site files directly via the panel UI.

### Stack Configuration Guides
- **WordPress:** Create a database via **Databases**, upload WordPress core files, and set `localhost` as your database host.
- **Node.js / Python / Go Apps:** Select **Reverse Proxy** during creation and specify the internal port your process binds to (e.g., `3000`). HostPanel handles Nginx proxying and SSL termination.

---

## 💾 Backups & Disaster Recovery

HostPanel offers robust local and remote data preservation workflows:

- **Local Backups:** Initiate single-site or full-server snapshots directly from the **Backups** tab.
- **Automated Schedule:** Configure daily automated backup cycles within the dashboard UI.
- **Remote / Off-Server Copies:** Integrate `rclone` to automatically offload backups to S3-compatible storage (Cloudflare R2, AWS S3, Backblaze B2, etc.):
  ```bash
  apt install rclone
  rclone config   # Configure remote target (e.g., "r2")
  ```
  Specify your destination string (`r2:my-bucket/hostpanel`) in the HostPanel backup settings.
- **Safe Restores & Deletions:** Restores automatically trigger a temporary safety backup before execution. Deleting sites or databases automatically creates a final preservation dump.

---

## 🛠️ Maintenance & CLI Commands

If you lose access or encounter system issues, use the built-in emergency CLI utility via SSH:

```bash
# Reset Panel Admin Password
sudo hostpanel-cli reset-password

# Disable Two-Factor Authentication (2FA)
sudo hostpanel-cli disable-2fa

# Remove IP restrictions on Port 8443
sudo hostpanel-cli open-port
```

### Troubleshooting Quick Reference

| Issue | Resolution / Diagnostic Command |
| :--- | :--- |
| **Panel won't start** | `journalctl -u hostpanel -n 50 --no-pager` |
| **Nginx Syntax Errors** | `nginx -t` |
| **SSL Issuance Failure** | Check **Tasks** log. Ensure `A` records are propagated and Cloudflare proxying is temporarily disabled. |

---

## 🔄 Upgrade Procedure

Upgrading to new versions preserves all existing sites, settings, databases, and credentials:

```bash
unzip hostpanel-new-version.zip
cd hostpanel-new-version
sudo bash install.sh
```

---

## 📋 Changelog (v2 → v1.0)

### 🐛 Bug Fixes
- **UI Metrics Fix:** Resolved issue where RAM and disk consumption indicators appeared continuously full due to strict Content Security Policies blocking inline styles.
- **Session Leak Prevention:** Mitigated session inflation caused by external scanners by isolating sessions strictly to login workflows and active users.
- **Services Control:** Fixed an issue where managing services could inadvertently disable UFW. System firewall and SSH are now read-only status monitors.
- **Dashboard Optimization:** Offloaded update and security evaluation routines to background cached execution.

### 🛡️ Security Hardening
- **Isolated Environments:** Site users are chrooted with SFTP-only permissions (`no-shell`) and support key-based authentication.
- **Strict File Permissions:** Files are constrained per-site using `640`/`750` permission masks to prevent cross-site file reading.
- **PHP Hardening:** Blocked direct execution of PHP files within upload directories; disabled high-risk system functions by default.
- **Accidental Deletion Prevention:** Site/Database removal requires typing full entity names and forces a final backup generation.
- **IP Spoofing Protection:** Proxy headers (`X-Real-IP`) are strictly validated against local proxy origin to ensure accurate Fail2ban IP capturing.

---

## 📂 System Layout

```text
/opt/hostpanel/           # Panel runtime assets (server.js, worker.js, lib/, public/)
/opt/hostpanel/data/      # Internal SQLite database, panel SSL certs, audit logs
/opt/hostpanel/backups/   # Local backup repository
/home/wXXXXXXXXXX/        # Isolated site roots (public_html, tmp, logs)
```

---

## 🧪 Testing & Verification Note

This release has undergone extensive dry-run verification (form validations, session handling, path traversal/symlink attack prevention, error rollbacks, and Nginx syntax verification). Server-level dependencies requiring live internet environments (Let's Encrypt validation, SFTP chroot jails, runtime PHP-FPM pools) should be validated on a test VPS or snapshot before production deployment.

## Version 1.0.4

### What is new
- **One "New website" flow.** *Websites -> New website* shows WordPress, Laravel, Node.js, PHP, Static HTML, Python and Reverse Proxy. Each one opens its own wizard. The separate *App Installer* page is gone (old `/apps` links redirect).
- **WordPress / Laravel wizards** ask for the site details, the first administrator, and a *separate* database name, database username, database password (and WordPress table prefix). Defaults are pre-filled and can be changed.
- **Stable releases only.** The newest stable version is looked up from WordPress.org / Packagist and pinned; Composer runs with `--stability=stable`; any beta / RC / dev version is refused.
- **Databases:** database, user and password are separate. A database can have several users, users can be added/removed and get new passwords, and a database can be assigned to a website.
- **Per-website phpMyAdmin** (Databases page, one click "Install and enable"): single sign-on through a one-time ticket as a MariaDB account that can only see that website's databases. Served by nginx on port **8444**.
- **Clients:** *Clients* page creates a login for a customer and assigns websites to it. The client signs in on the normal login page and can only manage those websites: files, databases, phpMyAdmin, backups, cron, logs, SSL, PHP settings, SFTP keys, and WordPress/Laravel install on their own empty site. Everything else answers 403 (default deny). First login forces a new password.
- **Node.js and Python sites** run as a systemd service under the website's own Linux user (hardened unit, journal logs, start/stop/restart, install dependencies).
- Update from 1.0.3 through the panel's own auto-update: new files only live in `lib/`, `public/`, so the signed update path covers everything. phpMyAdmin and Python tools are installed on demand from *Settings -> Server tools* / *Databases*.

### Notes
- Port 8444 must be open in your cloud firewall for phpMyAdmin (the installer opens it in ufw).
- The panel still runs as root. Client logins are isolated by an allowlist, per-website ownership checks and the per-site Linux users, but a flaw in the panel itself would still be a root flaw. Test on a snapshot before putting real customers on it.

## Version 1.0.3 development notes

- The administrator username can be changed from **Account** after re-authentication; when 2FA is enabled, a fresh 2FA code is required.
- Static HTML sites are supported without creating a PHP-FPM pool.
- This release does **not** yet enable customer multi-tenancy or a privileged-helper boundary. The current root-run server still has a large privileged attack surface. Do not expose customer accounts or treat this development build as a production-ready shared-hosting service.
- Panel self-updates must be implemented with signed/checksummed release artifacts, staging, backups, health checks and rollback. A raw `git pull` from the running panel is intentionally not used.
- The App Installer (WordPress, Laravel) is available (see above). Full tenant isolation is still unfinished work. The installer's network steps (WP-CLI download, WordPress.org, Packagist) and a real MariaDB/PHP-FPM install should be validated on a test VPS snapshot before production use.

### 1.0.3 changes
- **Let's Encrypt is manual** (like CloudPanel): new websites and App Installer sites no longer request a certificate. Open *Manage -> SSL certificate* and press *Issue certificate* when the DNS points to the server. New sites answer on port 443 with the shared self-signed certificate until then, so Cloudflare "Full" and direct https:// visits no longer fail with 525 / QUIC errors.
- **Branded dialogs**: confirm / type-to-confirm / prompt / upload-error pop-ups are now HostPanel-styled modals (keyboard accessible, light and dark) instead of browser pop-ups.
- Release workflow runs scripts through `bash`; `install.sh` firewall step no longer stops under `pipefail`.
