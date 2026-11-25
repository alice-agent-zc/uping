#!/bin/sh
# uping installer: fetch the published Debian package, verify it, install it.
#
#   curl -fsSL https://raw.githubusercontent.com/raonagos/uping/main/install.sh | sudo sh
#   curl -fsSL .../install.sh | sudo sh -s -- --version v0.4.0
#
# It is non-interactive by design: when it arrives on a pipe, stdin is the
# script itself, so nothing may prompt. The package's postinst does the rest
# (service user, /var/lib/uping, a loopback default config, the unit).
#
# Environment:
#   UPING_BASE_URL  release base URL for a mirror or an air-gapped check
#                   (default https://github.com/raonagos/uping/releases)
set -eu

BASE_URL=${UPING_BASE_URL:-https://github.com/raonagos/uping/releases}
VERSION=latest
DEB=uping_amd64.deb

usage() {
    cat <<'USAGE'
usage: install.sh [--version TAG]

  --version TAG  install the package published for TAG (e.g. v0.4.0)
                 instead of the latest release.
  -h, --help     this text.

Environment
  UPING_BASE_URL release base URL (mirror or air-gapped check), default
                 https://github.com/raonagos/uping/releases
USAGE
}

step() { printf '\n==> %s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case $1 in
        --version)
            [ $# -ge 2 ] || die "--version needs a tag (e.g. v0.4.0)"
            VERSION=$2
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown option `$1`"
            ;;
    esac
done

[ "$(uname -s)" = Linux ] || die "uping installs on Linux; $(uname -s) is not supported"
[ "$(id -u)" = 0 ] || die "run as root: curl -fsSL <url> | sudo sh"
command -v dpkg >/dev/null 2>&1 || die "no dpkg: this installer needs a Debian or Ubuntu system"

case $(uname -m) in
    x86_64 | amd64) ;;
    *) die "no amd64 package is published for $(uname -m)" ;;
esac

if [ "$VERSION" = latest ]; then
    dir="$BASE_URL/latest/download"
else
    dir="$BASE_URL/download/$VERSION"
fi

fetch() { # fetch <url> <dest>
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        die "curl or wget is required"
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

step "downloading $DEB ($VERSION)"
fetch "$dir/$DEB" "$tmp/$DEB" ||
    die "cannot download $dir/$DEB — is $VERSION published?"
fetch "$dir/$DEB.sha256" "$tmp/$DEB.sha256" ||
    die "no published checksum for $DEB: refusing an unverified package"

want=$(cut -d' ' -f1 <"$tmp/$DEB.sha256")
got=$(sha256_of "$tmp/$DEB")
[ -n "$want" ] && [ "$want" = "$got" ] ||
    die "sha256 mismatch for $DEB: published '$want', downloaded '$got'"
printf '  ok    sha256 %s\n' "$got"

step "installing the package"
if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        "$tmp/$DEB" </dev/null || dpkg -i "$tmp/$DEB" </dev/null
else
    dpkg -i "$tmp/$DEB" </dev/null
fi

step "done"
cat <<'DONE'
uping is installed. Next:
  man uping
  sudo editor /etc/uping/config.toml
  sudo -u uping /usr/bin/uping --check /etc/uping/config.toml
  sudo systemctl restart uping
DONE
