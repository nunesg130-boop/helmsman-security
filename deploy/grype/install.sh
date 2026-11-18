#!/bin/sh
# Installs the pinned Grype and Syft for helmsman-security, verified against
# the checksums in versions.json, and sets up the hs-grype user and folders.
# Run as root on the engine machine:  sh /opt/helmsman-security/deploy/grype/install.sh
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
VERSIONS="$HERE/versions.json"
LIB=/usr/local/lib/hs-grype
STATE=/var/lib/hs-grype
ENGINE_GROUP=helmsec

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
getent group "$ENGINE_GROUP" >/dev/null || { echo "group $ENGINE_GROUP not found (is the engine installed?)"; exit 1; }

field() { node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));process.stdout.write(String(v[process.argv[2]][process.argv[3]]))' "$VERSIONS" "$1" "$2"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
install -d -m 0755 -o root -g root "$LIB" "$LIB/bin"

for tool in grype syft; do
  url=$(field "$tool" url); want=$(field "$tool" sha256); version=$(field "$tool" version)
  echo "downloading $tool $version"
  curl --fail --silent --show-error --location -o "$WORK/$tool.tar.gz" "$url"
  got=$(sha256sum "$WORK/$tool.tar.gz" | cut -d' ' -f1)
  if [ "$got" != "$want" ]; then echo "CHECKSUM MISMATCH for $tool: expected $want, got $got. Nothing installed."; exit 1; fi
  echo "$tool checksum ok"
  tar -xzf "$WORK/$tool.tar.gz" -C "$WORK" "$tool"
  install -m 0755 -o root -g root "$WORK/$tool" "$LIB/bin/$tool"
done

# Record what was installed, so the worker can refuse a binary that changed.
node -e '
const fs=require("fs"),c=require("crypto"),v=JSON.parse(fs.readFileSync(process.argv[1]));
const h=(p)=>c.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const rec={grype:{version:v.grype.version,sha256:h(process.argv[2]+"/bin/grype")},syft:{version:v.syft.version,sha256:h(process.argv[2]+"/bin/syft")}};
fs.writeFileSync(process.argv[2]+"/installed.json",JSON.stringify(rec,null,2)+"\n")' "$VERSIONS" "$LIB"
chmod 0644 "$LIB/installed.json"

id hs-grype >/dev/null 2>&1 || useradd --system --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin hs-grype
install -d -m 0750 -o hs-grype -g "$ENGINE_GROUP" "$STATE"
install -d -m 2770 -o hs-grype -g "$ENGINE_GROUP" "$STATE/spool"
install -d -m 2750 -o hs-grype -g "$ENGINE_GROUP" "$STATE/out"
install -d -m 0700 -o hs-grype -g hs-grype "$STATE/db" "$STATE/tmp"

install -m 0644 -o root -g root "$HERE/hs-grype.service" /etc/systemd/system/hs-grype.service
systemctl daemon-reload

echo "--- isolation check (both lines should say 'refused') ---"
if runuser -u hs-grype -- ls /var/lib/helmsman-security >/dev/null 2>&1; then echo "engine data: READABLE by hs-grype -- fix permissions before starting"; else echo "engine data: refused"; fi
if runuser -u hs-grype -- ls /etc/helmsman-security >/dev/null 2>&1; then echo "engine config: READABLE by hs-grype -- fix permissions before starting"; else echo "engine config: refused"; fi
echo "installed. Start with: systemctl enable --now hs-grype"
