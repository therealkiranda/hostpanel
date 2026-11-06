# HostPanel billing API (v1, since 1.0.8)

Provision and manage hosting from free / open-source billing software (FOSSBilling, Paymenter, your own scripts).
One **service** = one client login + one website. Machine-readable spec: `GET /api/v1/openapi.json` (OpenAPI 3.1).

## 1. Create a key

Panel → **Billing API** → *New key*. The key (`hpk_<8 hex>_<48 hex>`) is shown **once**; only a SHA-256 hash is stored.

- **Scopes:** `read` (list, inspect, usage) and `write` (create, suspend, change, delete).
- **Allowed IP addresses:** put the billing server's address here. With an empty list the key works from anywhere.
- If you restricted port 8443 in *Settings → Direct access*, call the API through your panel domain, or allow the billing server there too.
- Revoke a key from the same page; it stops working at once.

## 2. Call it

```bash
curl -s https://panel.example.com/api/v1/ping -H "Authorization: Bearer hpk_xxxxxxxx_..."
```

All bodies are JSON (`Content-Type: application/json`, max 32 KB). Errors always look like:

```json
{ "error": { "code": "domain_exists", "message": "A website with that domain already exists" } }
```

| Status | Codes |
| :-- | :-- |
| 400 / 413 / 415 | `bad_json`, `too_large`, `unsupported_media_type` |
| 401 | `unauthorized` (missing / wrong key) |
| 403 | `insufficient_scope`, `ip_not_allowed` |
| 404 | `not_found` (also unknown endpoint) · 405 `method_not_allowed` |
| 409 | `domain_exists`, `client_conflict`, `client_disabled`, `client_in_use`, `busy`, `conflict` |
| 422 | `invalid_domain`, `invalid_type`, `invalid_username`, `invalid_email`, `invalid_php`, `invalid_password`, `invalid_limits`, `invalid_plan`, `invalid_external_id`, `python_missing` |
| 429 | `rate_limited` (120 / min per key), `too_many_failures` (10 bad keys per address in 15 min; `Retry-After` is set) |
| 500 | `provision_failed` (message says what failed), `internal` |

`busy` means another background task (backup, delete, install) is running; retry in a minute.

## 3. Endpoints

| Method + path | Scope | What it does |
| :-- | :-- | :-- |
| `GET /api/v1/ping` | any | Checks the key |
| `GET /api/v1/server` | read | Version, IP, installed PHP versions, supported types, load |
| `GET /api/v1/tasks/current` | read | `{running, label, startedAt, endedAt, exitCode}` of the background task |
| `GET /api/v1/services` | read | List. Filters: `externalId`, `status` (`active`/`suspended`), `username`, `limit`, `offset` |
| `POST /api/v1/services` | write | **Provision** (below) |
| `GET /api/v1/services/{domain}` | read | One service |
| `POST /api/v1/services/{domain}/suspend` | write | Suspend, optional `{"reason": "..."}` |
| `POST /api/v1/services/{domain}/unsuspend` | write | Unsuspend |
| `POST /api/v1/services/{domain}/password` | write | `{"password": "12-72 chars"}` sets the client's panel password |
| `POST /api/v1/services/{domain}/sftp-password` | write | New SFTP password, returned once |
| `POST /api/v1/services/{domain}/plan` | write | `{"plan": "Business", "limits": {"diskMb": 5000}}` (only the keys you send change) |
| `GET /api/v1/services/{domain}/usage` | read | Disk used (cached 5 min), limits, database count |
| `DELETE /api/v1/services/{domain}` | write | Terminate. Final backup first (**202**, poll the task) unless `?skipBackup=1` (**200**) |
| `GET /api/v1/clients/{username}` | read | Client and their services |
| `DELETE /api/v1/clients/{username}` | write | Remove a client login that has no services left |

### Provision

```bash
curl -s -X POST https://panel.example.com/api/v1/services \
  -H "Authorization: Bearer hpk_xxxxxxxx_..." -H "Content-Type: application/json" \
  -d '{"domain":"shop.example.com","username":"alice","email":"alice@example.com",
       "type":"php","php":"8.4","externalId":"svc-1001","plan":"Starter",
       "limits":{"diskMb":5000,"bandwidthMb":50000}}'
```

`201 Created`:

```json
{ "created": true,
  "service": { "domain": "shop.example.com", "status": "active", "type": "php", "php": "8.4",
               "externalId": "svc-1001", "plan": "Starter", "client": { "username": "alice", "email": "alice@example.com" },
               "sftp": { "host": "panel.example.com", "port": 22, "user": "w1a2b3c4d5e" } },
  "credentials": { "sftp":  { "host": "...", "port": 22, "user": "w1a2b3c4d5e", "password": "…" },
                   "panel": { "url": "https://panel.example.com", "username": "alice", "password": "…", "mustChangePassword": true } } }
```

- **Credentials are returned once.** They are not stored and not logged. `password` is optional (12–72 characters); when empty a strong one is generated.
- **Retries are safe.** Repeating the call for the same `domain` + `externalId` returns `200` with `"created": false` and `"credentials": null` instead of creating a second site. The same domain with a *different* `externalId` is a `409`.
- **Clients are reused.** The same `username` **and** `email` attaches the new website to the existing login (no new password). The same username with another email, or the same email under another username, is a `409 client_conflict`. The administrator's name is reserved.
- `type`: `php` (default), `static`, `node`, `python`, `proxy` (`proxy` needs `port`). WordPress / Laravel installs are not part of the API yet.
- Nothing is left behind when a request fails (a client created for it is removed again).
- The client's first panel sign-in still requires setting up two-factor authentication.

## 4. What suspend does

Website answers **503** with a plain notice (Let's Encrypt renewals keep working) · SFTP / SSH / cron login of the site user is closed and its running processes are killed · Node.js / Python services are stopped and disabled · the client cannot open that website in the panel. Unsuspend reverses all of it. Calling either twice is harmless.

## 5. Termination

`DELETE /services/{domain}` removes the website, its Linux user, pool, nginx config and certificate. Databases are kept (same as the panel). When it was the client's last website, the client login is closed immediately; remove the record with `DELETE /clients/{username}` after the task finished.

## 6. Honest limits

- **Limits are recorded and reported, not enforced.** `limits.diskMb` is compared with measured disk use (`usage` → `overLimit`); your billing software decides what to do (warn, suspend). No quotas are applied to the filesystem.
- **Bandwidth is not measured** (`bandwidth.measured` is `false`).
- Disk usage is measured with `du` and cached for five minutes per website.
- One background task at a time server-wide (the panel's existing task slot); concurrent heavy calls get `409 busy`.
- The panel runs as root. Treat an API key like a root credential: restrict it by IP, give reporting tools a `read`-only key, and rotate keys when staff leave.

## 7. FOSSBilling

Copy `integrations/fossbilling/Hostpanel.php` to `<fossbilling>/library/Server/Manager/Hostpanel.php`, then *System → Hosting plans and servers → New server*, manager **HostPanel**, hostname = panel address, port = 8443 (443 with a panel domain), **Access hash** = the API key. Package custom values `type` and `php_version` are optional. FOSSBilling cannot change a username, domain or IP through any manager, and does not send the suspension reason on; the module reports those cases as unsupported. The module follows the interface of FOSSBilling's bundled managers but has not been run against a live FOSSBilling by its author: do a test order first.

Other software (for example Paymenter's server extensions) only needs the calls in section 3; import `openapi.json` into any client generator.
