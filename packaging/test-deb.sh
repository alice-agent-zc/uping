#!/bin/sh
# Install the freshly built .deb in the image it targets and check what only
# exists after dpkg ran: the user, the data directory, the default config the
# postinst writes, the man page, the service the default describes, an upgrade
# that leaves /etc alone, and a purge that keeps the CA.
#
# Runtime behaviour of the proxy is covered by tests/internal_ca_e2e.rs; this
# script is about the package.
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

echo "--- the postinst created the user, the group, the data dir and a config"
id uping
getent group uping >/dev/null
test -f /etc/uping/config.toml
[ "$(stat -c '%U:%G %a' /etc/uping/config.toml)" = "root:uping 640" ]
[ "$(stat -c '%U:%G %a' /var/lib/uping)" = "uping:uping 750" ]

echo "--- standard paths: binary, unit, tmpfiles, man, example, page, docs"
dpkg-deb -c /debs/uping_*.deb > /tmp/uping-files
for f in \
    usr/bin/uping \
    usr/lib/systemd/system/uping.service \
    usr/lib/tmpfiles.d/uping.conf \
    usr/share/man/man8/uping.8 \
    usr/share/uping/config.toml.default \
    usr/share/uping/config.toml.example \
    usr/share/uping/www/index.html \
    usr/share/doc/uping/README.Debian \
    usr/share/doc/uping/README.md; do
    grep -q "$f" /tmp/uping-files || {
        echo "missing from the archive: $f" >&2
        exit 1
    }
done
test -x /usr/bin/uping
test -f /usr/lib/systemd/system/uping.service
test -f /usr/lib/tmpfiles.d/uping.conf
test -f /usr/share/uping/config.toml.default
test -f /usr/share/uping/www/index.html
test -f /usr/share/doc/uping/copyright

echo "--- the default config is valid and --check writes nothing"
runuser -u uping -- /usr/bin/uping --check /etc/uping/config.toml
[ ! -e /var/lib/uping/internal ]

echo "--- the packaged binary serves the default page as uping"
apt-get install -y -qq --no-install-recommends curl >/dev/null
runuser -u uping -- /usr/bin/uping /etc/uping/config.toml >/tmp/uping.log 2>&1 &
pkg_pid=$!
i=0
page=
while [ "$i" -lt 150 ]; do
    if [ -f /var/lib/uping/internal/ca/root.crt ] &&
       page=$(curl -fsS --resolve localhost:8443:127.0.0.1 \
                  --cacert /var/lib/uping/internal/ca/root.crt \
                  https://localhost:8443/ 2>/dev/null); then
        break
    fi
    i=$((i + 1))
    sleep 0.1
done
printf '%s' "$page" | grep -q 'uping is running'
[ "$(stat -c '%U:%G %a' /var/lib/uping/internal/ca/root.key)" = "uping:uping 600" ]
kill "$pkg_pid" 2>/dev/null || true
pkill -f '/usr/bin/uping /etc/uping/config.toml' 2>/dev/null || true

echo "--- an upgrade keeps an existing configuration byte for byte"
printf '# admin configuration\n' > /etc/uping/config.toml
chown root:uping /etc/uping/config.toml
chmod 0640 /etc/uping/config.toml
before=$(sha256sum /etc/uping/config.toml)
dpkg -i /debs/uping_*.deb >/dev/null
after=$(sha256sum /etc/uping/config.toml)
[ "$before" = "$after" ] || { echo "the upgrade replaced the configuration" >&2; exit 1; }

echo "--- purge keeps the configuration and the CA on purpose"
dpkg -P uping >/dev/null
test -f /etc/uping/config.toml
test -d /var/lib/uping/internal/ca
! dpkg-query -W uping >/dev/null 2>&1

echo "ok: dpkg -i installs everything; upgrade and purge behave as documented"
INSIDE

echo "tested $(basename "$DEB") in $IMAGE" >&2
