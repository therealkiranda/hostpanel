#!/usr/bin/env bash
# usage: tools/build-release.sh <X.Y.Z>   -> dist/hostpanel-X.Y.Z.tar.gz (top folder "hostpanel/", no node_modules)
set -euo pipefail
cd "$(dirname "$0")/.."
VER="${1:?usage: build-release.sh X.Y.Z}"
[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "bad version"; exit 1; }
[ "$(node -p "require('./package.json').version")" = "$VER" ] || { echo "package.json version does not match $VER"; exit 1; }
for f in server.js cli.js worker.js package.json package-lock.json install.sh lib/release-key.pub; do [ -e "$f" ] || { echo "missing $f"; exit 1; }; done
mkdir -p dist
OUT="dist/hostpanel-$VER.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='2020-01-01 00:00:00' \
    --transform 's,^,hostpanel/,' -cf - server.js cli.js worker.js package.json package-lock.json install.sh lib public | gzip -n -9 > "$OUT"
echo "$OUT"
