#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
node --check server.js
node --check cli.js
node --check worker.js
node --check lib/core.js
node --check lib/sites.js
node --check lib/sys.js
node --check lib/ui.js
node --check lib/routes/account.js
for f in lib/routes/*.js lib/dbs.js lib/pma.js lib/runtime.js lib/tools.js lib/access.js lib/users.js; do node --check "$f"; done
node --check lib/siteexec.js
node --check lib/motd.js
for f in lib/apps/*.js; do node --check "$f"; done
node --check lib/update-service.js
node --check lib/updater.js
node --check lib/archive-check.js
node --check tools/make-release-key.js
node --check tools/sign-manifest.js
bash -n tools/build-release.sh
node test/template-check.js
node test/nginx-template-smoke.js
node test/username-validation.js
bash -n install.sh
for t in apps-engine apps-handlers apps-download apps-e2e motd v104-units clients-e2e; do grep -q "test/$t.js" package.json; done
grep -q '"version": "1.0.4"' package.json
grep -q "app.post('/account/username'" lib/routes/account.js
grep -q "type === 'static'" lib/sites.js
grep -q 'site-static.tpl' lib/sites.js
grep -q 'ssl_reject_handshake' install.sh
grep -q 'http,https' install.sh
grep -q 'cli.js" motd install' install.sh
grep -q "require('./lib/routes/wizard')" server.js
grep -q "stability=stable" lib/apps/laravel.js
grep -q 'isStable' lib/apps/wordpress.js
grep -q 'npm ci --omit=dev --ignore-scripts' install.sh
grep -q "require('fs')" lib/routes/account.js
echo 'HostPanel source checks passed (syntax and feature markers only).'
