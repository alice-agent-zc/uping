#!/bin/sh
# Install the freshly built .deb in the image it targets and check what only
# exists after dpkg ran: the user, the data directory, the unit, the docs, the
# packaged example, an upgrade that leaves /etc alone, and a purge that keeps
# the CA. Runtime behaviour is covered by tests/internal_ca_e2e.rs; this is
# about the package.
#
#   packaging/test-deb.sh [image]
set -eu

PATH="$HOME/.cargo/bin:$PATH"
export PATH

IMAGE=${1:-ubuntu:24.04}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEB=$(ls -1t "$ROOT"/target/debian/uping_*.deb 2>/dev/null | head -1) || true
[ -n "${DEB:-}" ] || {
    echo "test-deb.sh: no .deb in target/debian; run packaging/build-deb.sh first" >&2
    exit 1
}

echo "testing $(basename "$DEB") in $IMAGE" >&2
docker run --rm -i -v "$ROOT/target/debian:/debs:ro" "$IMAGE" sh -eu -s <<'INSIDE'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends /debs/uping_*.deb

echo "--- control fields"
dpkg-query -W -f='${Package} ${Version} ${Architecture} ${Priority} ${Section}\n' uping

# Ubuntu's default dpkg config excludes /usr/share/doc, keeping only the
# copyright file, so a functional asset must not live there. The example is in
# /usr/share/uping for that reason; the docs are checked in the archive itself.
echo "--- the archive carries the documentation"
dpkg-deb -c /debs/uping_*.deb > /tmp/uping-files
grep -q 'usr/share/doc/uping/README.Debian' /tmp/uping-files
grep -q 'usr/share/doc/uping/README.md' /tmp/uping-files

echo "--- files, modes and ownership"
test -x /usr/bin/uping
test -f /usr/lib/systemd/system/uping.service
test -f /usr/lib/tmpfiles.d/uping.conf
test -f /usr/share/uping/config.toml.example
test -f /usr/share/doc/uping/copyright
runuser -u uping -- test -r /usr/bin/uping
stat -c '%a %U:%G %n' /var/lib/uping

echo "--- the packaged example is a valid config, and --check writes nothing"
runuser -u uping -- /usr/bin/uping --check /usr/share/uping/config.toml.example
test ! -e /var/lib/uping/internal

echo "--- the service user can write its state directory"
runuser -u uping -- sh -c 'touch /var/lib/uping/.probe && rm /var/lib/uping/.probe'

echo "--- the packaged binary creates its local CA as the service user"
cat > /tmp/pkg.toml <<'CONFIG'
[listen]
ipv4  = "127.0.0.1"
http  = 18080
https = 18443
[internal]
ca_dir   = "/var/lib/uping/internal/ca"
cert_dir = "/var/lib/uping/internal"
[[server]]
domain       = "app.internal"
keys         = "internal"
serve_http   = false
https_listen = "127.0.0.1:18443"
upstream     = "127.0.0.1:9"
CONFIG
chown uping:uping /tmp/pkg.toml
runuser -u uping -- /usr/bin/uping /tmp/pkg.toml >/tmp/pkg.log 2>&1 &
pkg_pid=$!
i=0
while [ "$i" -lt 100 ]; do
    [ -f /var/lib/uping/internal/ca/root.crt ] && break
    i=$((i + 1))
    sleep 0.1
done
test -f /var/lib/uping/internal/ca/root.crt
test -f /var/lib/uping/internal/ca/root.key
test -f /var/lib/uping/internal/app.internal/fullchain.pem
stat -c '%a %U:%G %n' /var/lib/uping/internal/ca/root.key
kill "$pkg_pid" 2>/dev/null || true
pkill -f '/usr/bin/uping /tmp/pkg.toml' 2>/dev/null || true
rm -f /tmp/pkg.toml /tmp/pkg.log

echo "--- an upgrade never touches an existing /etc/uping/config.toml"
install -d -m 0750 /etc/uping
printf '# admin configuration\n' > /etc/uping/config.toml
chown root:uping /etc/uping/config.toml
chmod 0640 /etc/uping/config.toml
before=$(sha256sum /etc/uping/config.toml)
dpkg -i /debs/uping_*.deb >/dev/null
after=$(sha256sum /etc/uping/config.toml)
[ "$before" = "$after" ] || { echo "config was modified by the upgrade" >&2; exit 1; }

echo "--- purge keeps the configuration and the CA on purpose"
dpkg -P uping >/dev/null
test -f /etc/uping/config.toml
test -d /var/lib/uping
! dpkg-query -W uping >/dev/null 2>&1

echo "ok: package installs, upgrades and purges as documented"
INSIDE

echo "tested $(basename "$DEB") in $IMAGE" >&2
