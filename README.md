# HostPanel 1.0

A small, fast hosting control panel for **Ubuntu + Nginx + PHP-FPM + MariaDB**. Think "CloudPanel / cPanel, but yours and tiny".

- Websites: PHP / WordPress, Laravel, and reverse-proxy (Node, Python, anything on a local port)
- **Free Let's Encrypt SSL for every site** (automatic, auto-renewing)
- **Panel on your own domain** (`https://panel.yourdomain.com`) with its own certificate, as well as `IP:8443`
- File manager, uploads up to 1 GB, code editor, SFTP-only site users (no shell), cron, logs
- Databases, backups (manual, daily schedule, restore, off-server copy with rclone)
- Security score, Fail2ban, firewall status, 2FA, audit log, system updates, services

---

## 1. What you need

| | |
|---|---|
| Server | A **fresh** Ubuntu 22.04 / 24.04 / 26.04 VPS, 1 GB RAM or more |
| Access | root (or a sudo user) over SSH |
| Cloud firewall | Allow inbound **22, 80, 443 and 8443** (AWS Lightsail: *Networking* tab -> add rules) |
| A domain | Optional but recommended: for the panel and for your websites |

> First time? Take a **snapshot** of the fresh server before installing, so you can roll back.

## 2. Install (about 5-10 minutes)

**a) Copy the zip to your server.** From your computer or Termux:

```bash
scp hostpanel-1.0.zip root@YOUR_SERVER_IP:/root/
```

**b) On the server:**

```bash
ssh root@YOUR_SERVER_IP
apt-get update && apt-get install -y unzip
unzip hostpanel-1.0.zip
cd hostpanel-1.0
sudo bash install.sh
```

The installer sets up Nginx, PHP, MariaDB (localhost only), Certbot, Fail2ban, the firewall, automatic security updates, a swap file, and the panel itself. At the end it prints:

```
Open:   https://YOUR_SERVER_IP:8443
Panel user: admin
Panel password: xxxxxxxxxxxxxxxx
```

(The same details are saved in `/root/hostpanel-credentials.txt` until you change the password.)

**c) First login**

1. Open `https://YOUR_SERVER_IP:8443`. The browser warns about a self-signed certificate. That is normal until step 3.
2. Sign in, and change the password when asked (12+ characters).
3. **Account -> Enable 2FA** and scan the key with an authenticator app.

## 3. Put the panel on your own domain (like cPanel / CloudPanel)

1. In your DNS, create an **A record**: `panel.yourdomain.com` -> your server IP.
   *Using Cloudflare? Set the record to "DNS only" (grey cloud) until the certificate is issued. You can turn the proxy on afterwards.*
2. In the panel: **Settings -> Panel domain**, enter `panel.yourdomain.com` and your email, press **Enable panel domain**.
3. Watch **Tasks**. When it says *finished OK*, open `https://panel.yourdomain.com`. It now has a real Let's Encrypt certificate.
4. Optional: **Settings -> Direct access on port 8443** to allow only your own IP on the raw port. The domain keeps working for everyone with a login.

## 4. Add your first website

1. **Websites -> Add a website.** Enter the domain, choose the type and PHP version, keep *Let's Encrypt* ticked, press **Create website**.
2. The panel shows the **SFTP username and password once**. Copy it.
3. In your DNS, point the domain (and `www`) to the server IP. The panel retries the certificate every hour for 12 hours, or press **Get free SSL** on the site's page. **Check DNS** tells you what is wrong.
4. Upload files with the **File Manager**, or with any SFTP client (host = server IP, port 22). From Termux:
   ```bash
   sftp wXXXXXXXXXX@YOUR_SERVER_IP
   ```
   Site users have **no shell** and cannot see anything outside their own folder.

**WordPress:** create a database in **Databases**, upload WordPress, and use `localhost` as the database host.
**Node / Python app:** choose *Reverse proxy*, give the local port your app listens on (e.g. 3000). Nginx and SSL are handled for you.

## 5. Backups

**Backups** page: back up one site, or everything. Turn on the **daily schedule**, and optionally add an off-server copy:

```bash
apt install rclone
rclone config          # create a remote, e.g. "r2" for Cloudflare R2
```

then enter `r2:my-bucket/hostpanel` in the schedule form. **Restore** is on each backup row and takes a safety backup of the current state first. Deleting a site keeps a final backup unless you tick *skip*; deleting a database always keeps a final dump.

## 6. If something goes wrong

| Problem | What to do |
|---|---|
| Forgot the password | `sudo hostpanel-cli reset-password` |
| Lost 2FA device | `sudo hostpanel-cli disable-2fa` |
| Locked out by the IP restriction | `sudo hostpanel-cli open-port` |
| Panel will not start | `journalctl -u hostpanel -n 50 --no-pager` |
| Certificate failed | Open the site, press **Check DNS**. The A record must point to this server, and the Cloudflare proxy must be off while issuing. Details are on the **Tasks** page |
| Nginx problem | `nginx -t` shows the exact line |

## 7. Upgrade

Unzip the new version and run `sudo bash install.sh` again. Your sites, databases, settings and password are kept.

## 8. What changed from v2 to 1.0

**Fixed**
- RAM and disk bars always looked full (the security policy blocked their inline styles). Rebuilt without inline styles.
- Memory leak: scanners hitting the panel created sessions forever. Sessions now exist only for the login page and signed-in users, with hard limits.
- The Services page could stop the firewall. Firewall and SSH are now status-only.
- Slow dashboard: update and security checks are cached and refreshed in the background.

**Hardened**
- Site users are SFTP-only and chrooted, with optional key-only login.
- Each site's folder is private from other sites (files are `640`/`750`).
- PHP execution is blocked in upload folders, and more dangerous PHP functions are disabled (strict mode, switchable).
- Deleting a site or database needs you to type its name, and takes a final backup first (sites can skip it explicitly).
- The file manager refuses to follow symlinks out of a site and cannot delete core folders.
- X-Real-IP is trusted only from the local proxy, so fail2ban and rate limits see real client IPs and cannot be spoofed.

**New**
- Let's Encrypt for every site and the panel itself; own-domain panel access; restore; scheduled and off-server backups; per-site PHP settings; recovery CLI; new interface with dark and light themes.

## 9. Layout

```
/opt/hostpanel/           panel code (server.js, worker.js, lib/, public/)
/opt/hostpanel/data/      database file, panel certificate, audit log   (back this up)
/opt/hostpanel/backups/   site and database backups
/home/wXXXXXXXXXX/        one folder per site (public_html, tmp, logs)
```

## Honest note on testing

This build was tested for everything that can run without a full server: all pages and forms, login, CSRF, sessions, file manager (including symlink and path-escape attempts), uploads, validation, rollback on failed site creation, and all generated Nginx configurations against a real `nginx -t`. The parts that need a live server and the internet (the installer end to end, Let's Encrypt issuance, SFTP chroot, PHP-FPM pools) could not be run here, so **do the first install on a fresh VPS or a snapshot** and tell me anything that misbehaves.
