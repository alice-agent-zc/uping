#!/bin/sh
# install-cert.sh — certbot deploy hook: publish one renewed lineage where the
# unprivileged proxy can read it.
#
#   certbot renew --deploy-hook /usr/local/lib/uping/install-cert.sh
#
# certbot sets RENEWED_LINEAGE to the lineage's live/ directory and only runs
# the hook when that lineage was actually renewed, so this is not a polling job.
#
# Why a copy at all: /etc/letsencrypt/live/*/privkey.pem is mode 0600, root-owned,
# and renewed underneath you. Copying it to a root:uping 0640 file gives the
# proxy the one key it serves and gives it no access to the CA's directory.
set -eu

LINEAGE=${RENEWED_LINEAGE:?this is a certbot deploy hook: RENEWED_LINEAGE is unset}
GROUP=${UPING_GROUP:-uping}
ROOT=${UPING_CERT_ROOT:-/etc/uping/certs}
dst="$ROOT/$(basename "$LINEAGE")"

install -d -o root -g "$GROUP" -m 0750 "$ROOT"
install -d -o root -g "$GROUP" -m 0750 "$dst"

# The chain is public; the key is the secret. Group-read, never world.
install -o root -g "$GROUP" -m 0644 "$LINEAGE/fullchain.pem" "$dst/fullchain.pem"
install -o root -g "$GROUP" -m 0640 "$LINEAGE/privkey.pem"   "$dst/privkey.pem"

# uping loads certificates once at startup, so a renewal is only served after a
# restart. That is a short, deliberate connection drop once per renewal.
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet uping; then
    systemctl restart uping
fi

echo "uping: installed $dst and restarted" >&2
