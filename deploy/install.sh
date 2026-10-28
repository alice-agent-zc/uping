#!/bin/sh
# install.sh — install or upgrade uping as a systemd service that runs as the
# unprivileged `uping` user with one capability (CAP_NET_BIND_SERVICE).
#
# The deployment is this one file. A sudo user fetches it and runs it:
#
#   curl --proto '=https' --tlsv1.2 -sSf \
#     https://raw.githubusercontent.com/raonagos/uping/main/deploy/install.sh \
#     | sudo sh -s -- --config ./config.toml
#
# No arguments installs the latest release from
# github.com/raonagos/uping/releases: the binary is downloaded, its published
# sha256 is checked, and an unverified download is refused rather than installed.
# `--version v0.1.2` pins a tag; `--binary PATH` installs a local build instead;
# `--fetch-only DIR` does just the download, needs no root, and is how CI proves
# a release is installable.
#
# It is re-runnable: it upgrades the binary and the unit, leaves
# /etc/uping/config.toml alone, and finishes by proving the result. Read-only
# checking is `--verify-only`. `--help` lists the options.
#
# No prompt is ever read. When the script arrives on a pipe, stdin *is* the
# script, so every answer has to be an argument.
#
# Why one file instead of a unit plus two helpers: a unit that must agree with a
# shell script that must agree with a web page is three things to drift apart.
# Here the unit and the certbot hook are heredocs in the installer, so what runs
# is what was reviewed, and `--verify-only` is the acceptance test.
set -eu

SERVICE=uping
UNIT=/etc/systemd/system/$SERVICE.service
BIN=/usr/local/bin/$SERVICE
CONF_DIR=/etc/uping
CONF=$CONF_DIR/config.toml
CERT_DIR=$CONF_DIR/certs
HOOK_DIR=/usr/local/lib/uping
HOOK=$HOOK_DIR/install-cert.sh
HOOK_LINK=/etc/letsencrypt/renewal-hooks/deploy/uping-cert.sh
USER_NAME=uping

# Where release assets come from. The layout is fixed by
# .github/workflows/release.yml: <base>/{latest/download,download/<tag>}/<file>.
# UPING_BASE_URL exists for a mirror or an air-gapped check, not for the normal path.
BASE_URL=${UPING_BASE_URL:-https://github.com/raonagos/uping/releases}
VERSION=latest

step() { printf '\n==> %s\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
info() { printf '        %s\n' "$*"; }
die()  { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
FAILS=0

# --- the release asset ------------------------------------------------------------
# Name a target triple for this machine. Only Linux: the unit is systemd and the
# whole point is binding :80/:443.
release_target() {
    case $(uname -s) in
        Linux) ;;
        *) die "uping installs as a systemd service on Linux; $(uname -s) is not supported" ;;
    esac
    case $(uname -m) in
        x86_64|amd64)  echo x86_64-unknown-linux-gnu ;;
        aarch64|arm64) echo aarch64-unknown-linux-gnu ;;
        *)             die "no release asset is published for machine type $(uname -m)" ;;
    esac
}

release_url() { # release_url <asset-file> -> url
    if [ "$VERSION" = latest ]; then
        printf '%s/latest/download/%s\n' "$BASE_URL" "$1"
    else
        printf '%s/download/%s/%s\n' "$BASE_URL" "$VERSION" "$1"
    fi
}

download() { # download <url> <dest>
    # TLS is pinned to https for a real fetch. Anything else (a file:// mirror in
    # the release workflow) drops the restriction rather than pretending to have it.
    case $1 in
        https://*) proto="--proto =https" ;;
        *)         proto="" ;;
    esac
    if command -v curl >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        curl $proto -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        die "curl or wget is required to download the release; use --binary PATH"
    fi
}

sha256_of() { # sha256_of <file> -> hex
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Download, verify and unpack the release into a directory. Sets FETCHED to the
# extracted binary and EXAMPLE_CONF when the archive ships one. Nothing is
# returned on stdout — info/ok write there, and a caller must not capture them.
# No checksum means no install: an unverified binary that will hold :443 is
# worse than a failed install.
fetch_release() {
    target=$(release_target)
    name="uping-$target.tar.gz"
    dir=$1
    command -v tar >/dev/null 2>&1 || die "tar is required to unpack the release"
    mkdir -p "$dir" || die "cannot create $dir"
    info "release ${VERSION} for $target"
    download "$(release_url "$name")" "$dir/$name" \
        || die "cannot download $(release_url "$name") — is $VERSION published?"
    download "$(release_url "$name.sha256")" "$dir/$name.sha256" \
        || die "no published checksum for $name: refusing an unverified binary (use --binary PATH for a local build)"
    want=$(cut -d' ' -f1 < "$dir/$name.sha256")
    got=$(sha256_of "$dir/$name")
    [ -n "$want" ] && [ "$want" = "$got" ] \
        || die "sha256 mismatch for $name: published '${want}', downloaded '${got}'"
    ok "sha256 $got"
    tar -xzf "$dir/$name" -C "$dir" || die "cannot unpack $dir/$name"
    [ -f "$dir/uping" ] || die "$name does not contain an uping binary"
    FETCHED=$dir/uping
    if [ -f "$dir/config.toml.example" ]; then EXAMPLE_CONF=$dir/config.toml.example; fi
}

elf_or_die() { # elf_or_die <file>
    [ -r "$1" ] || die "cannot read $1"
    magic=$(head -c 4 "$1" | od -An -tx1 | tr -d ' \n')
    [ "$magic" = 7f454c46 ] || die "$1 is not an ELF binary"
}

usage() {
    cat <<'USAGE'
usage: install.sh [options]

  --version TAG    download the release asset for TAG (e.g. v0.1.2).
                   Default: the latest release.
  --binary PATH    install this file instead of downloading a release
                   (checked to be ELF).
  --config PATH    install this file as /etc/uping/config.toml
                   (root:uping 0640). Omit to keep the existing one.
  --fetch-only DIR download and verify the release asset into DIR, install
                   nothing, exit 0. Needs no root; used by CI.
  --no-start       install everything, do not enable or start the service.
  --verify-only    change nothing; run the checks and exit non-zero on failure.
  -h, --help       this text.

Environment
  UPING_BASE_URL   release base URL, default
                   https://github.com/raonagos/uping/releases

Examples
  curl --proto '=https' --tlsv1.2 -sSf <url>/deploy/install.sh \
    | sudo sh -s -- --config ./config.toml

  sudo sh install.sh --version v0.1.2 --config ./config.toml
  sh install.sh --fetch-only ./fetched          # no root, no install
  sudo sh install.sh --verify-only
USAGE
}

BINARY_SRC=""
CONFIG_SRC=""
FETCH_DIR=""
DO_START=1
VERIFY_ONLY=0

while [ $# -gt 0 ]; do
    case $1 in
        --version)     [ $# -ge 2 ] || die "--version needs a tag"; VERSION=$2; shift 2 ;;
        --binary)      [ $# -ge 2 ] || die "--binary needs a path"; BINARY_SRC=$2; shift 2 ;;
        --config)      [ $# -ge 2 ] || die "--config needs a path"; CONFIG_SRC=$2; shift 2 ;;
        --fetch-only)  [ $# -ge 2 ] || die "--fetch-only needs a directory"; FETCH_DIR=$2; shift 2 ;;
        --no-start)    DO_START=0; shift ;;
        --verify-only) VERIFY_ONLY=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             usage >&2; die "unknown argument: $1" ;;
    esac
done

if [ -n "$BINARY_SRC" ] && [ "$VERSION" != latest ]; then
    die "--binary and --version are exclusive: a local file or a release, not both"
fi

# --- 1. verify -------------------------------------------------------------------
# Reading a unit, another user's files and /proc is a root-only read. It changes
# nothing, which is why this runs before the first write as well as after.
verify() {
    FAILS=0
    printf 'uping install check — unit %s, config %s\n' "$UNIT" "$CONF"

    # the unit as systemd reads it
    if [ -r "$UNIT" ]; then ok "unit installed"; else bad "no unit at $UNIT"; fi
    user_line=$(systemctl show -p User --value "$SERVICE" 2>/dev/null || true)
    ambient=$(systemctl show -p AmbientCapabilities --value "$SERVICE" 2>/dev/null || true)
    bound=$(systemctl show -p CapabilityBoundingSet --value "$SERVICE" 2>/dev/null || true)
    case "${user_line:-root}" in
        root|"") bad "service user is ${user_line:-unset (defaults to root)}" ;;
        *)       ok "service user is $user_line" ;;
    esac
    case "$ambient" in
        *cap_net_bind_service*) ok "AmbientCapabilities carries cap_net_bind_service" ;;
        *) bad "AmbientCapabilities does not carry cap_net_bind_service: '${ambient:-empty}'" ;;
    esac
    case "$bound" in
        "")                    info "CapabilityBoundingSet unset: the process keeps every capability granted" ;;
        *cap_net_bind_service) ok "CapabilityBoundingSet is exactly cap_net_bind_service" ;;
        *)                     bad "CapabilityBoundingSet keeps more than one capability: '$bound'" ;;
    esac

    # the service user, and the files it may open as that user
    run_as() { # run_as <user> <cmd...>
        u=$1; shift
        if command -v runuser >/dev/null 2>&1; then runuser -u "$u" -- "$@" 2>/dev/null
        else su -s /bin/sh "$u" -c "$*" 2>/dev/null; fi
    }
    if id -u "$USER_NAME" >/dev/null 2>&1; then
        ok "user $USER_NAME exists (uid $(id -u "$USER_NAME"))"
        if run_as "$USER_NAME" test -r "$CONF"; then
            ok "config readable by $USER_NAME"
        else
            bad "config $CONF is not readable by $USER_NAME"
        fi
        while IFS= read -r val; do
            [ -n "$val" ] || continue
            case $val in /*) path=$val ;; *) path=/$val ;; esac
            if run_as "$USER_NAME" test -r "$path"; then
                ok "cert file readable by $USER_NAME: $val"
            else
                bad "cert file NOT readable by $USER_NAME: $val — publish it with the certbot hook, do not chown /etc/letsencrypt"
            fi
        done <<EOF
$(sed -n 's/^[[:space:]]*\(pub_key\|priv_key\)[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\2/p' "$CONF" 2>/dev/null || true)
EOF
    else
        bad "user $USER_NAME does not exist — nothing can run the unit as it"
    fi

    # the live process: uid, and a capability mask that is one bit wide
    pid=$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || true)
    if [ -n "${pid:-}" ] && [ "$pid" != 0 ] && [ -r "/proc/$pid/status" ]; then
        uid=$(awk '/^Uid:/{print $2}' "/proc/$pid/status")
        if [ "$uid" = 0 ]; then bad "running process $pid is uid 0 — the unit is not in effect yet"
        else ok "running process $pid is uid $uid"; fi
        capeff=$(awk '/^CapEff:/{print $2}' "/proc/$pid/status")
        if [ -n "$capeff" ]; then
            # dash has no 16#base prefix; 0x does.
            cap=$((0x$capeff))
            if [ $((cap & ~0x400)) -ne 0 ]; then
                bad "effective capability set holds more than cap_net_bind_service: $capeff"
            else
                ok "effective capability set is one bit (bind) or empty"
            fi
        fi
    else
        info "no running main process: start the service and check again"
    fi

    # who holds :80 and :443 — ss names the pid, /proc names its uid
    if command -v ss >/dev/null 2>&1; then
        for port in 80 443; do
            line=$(ss -ltnpH "sport = :$port" 2>/dev/null | head -1)
            if [ -z "$line" ]; then info "nothing listening on :$port"; continue; fi
            held=$(printf '%s' "$line" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
            if [ -z "$held" ] || [ ! -r "/proc/$held/status" ]; then
                info ":$port is held by a process this shell cannot name"; continue
            fi
            owner=$(awk '/^Uid:/{print $2}' "/proc/$held/status")
            case $owner in
                0) bad ":$port is held by uid 0 (pid $held)" ;;
                *) ok ":$port is held by uid $owner (pid $held)" ;;
            esac
        done
    fi

    echo
    if [ "$FAILS" -eq 0 ]; then
        echo "no privilege left that needs root"
        return 0
    fi
    echo "$FAILS check(s) failed"
    return 1
}

# The rehearsal: load the config and resolve the certificates exactly as the
# service would, and stop before a socket is created. Needs no root, no free
# port and no network. A load-time rejection — a malformed address, a wildcard
# where an upstream belongs — is an outage at boot, not a warning, so callers
# abort on failure.
config_check() {
    if [ ! -x "$BIN" ]; then
        printf '  FAIL  no binary at %s to run --check with\n' "$BIN"
        return 1
    fi
    if "$BIN" --check "$CONF"; then
        ok "config $CONF loads and its certificates resolve"
        return 0
    fi
    printf '  FAIL  config %s would not load (reasons above)\n' "$CONF"
    return 1
}

# Download-only: the one mode a non-root shell can run, which is the whole point
# — CI proves the published asset is installable before anyone is root.
if [ -n "$FETCH_DIR" ]; then
    fetch_release "$FETCH_DIR"
    elf_or_die "$FETCHED"
    ok "binary $FETCHED"
    if [ -n "${EXAMPLE_CONF:-}" ]; then ok "example config $EXAMPLE_CONF"; fi
    printf '\n%s\n' "$FETCHED"
    exit 0
fi

if [ "$(id -u)" != 0 ]; then
    die "run as root: curl … | sudo sh -s -- --config ./config.toml"
fi
command -v systemctl >/dev/null 2>&1 \
    || die "this installer needs systemd; the manual steps are in CONTRIBUTING.md"

if [ "$VERIFY_ONLY" = 1 ]; then
    [ -r "$CONF" ] || die "no config at $CONF to check"
    step "config check"
    cfg_ok=0
    config_check || cfg_ok=1
    verify || cfg_ok=1
    [ "$cfg_ok" = 0 ] && exit 0
    exit 1
fi

# --- 2. what it needs before it writes anything -----------------------------------
step "preflight"
DOWN_DIR=""
if [ -n "$BINARY_SRC" ]; then
    elf_or_die "$BINARY_SRC"
    ok "binary $BINARY_SRC"
else
    DOWN_DIR=$(mktemp -d) || die "cannot create a temporary directory"
    trap 'rm -rf "$DOWN_DIR"' EXIT INT TERM
    fetch_release "$DOWN_DIR"
    BINARY_SRC=$FETCHED
    elf_or_die "$BINARY_SRC"
    ok "binary $BINARY_SRC"
fi

if [ -n "$CONFIG_SRC" ]; then
    [ -r "$CONFIG_SRC" ] || die "cannot read $CONFIG_SRC"
    ok "config $CONFIG_SRC"
elif [ -r "$CONF" ]; then
    info "no --config: keeping $CONF"
else
    die "no config at $CONF: pass --config PATH, or start from $CONF.example (see README.md)"
fi

# --- 3. the binary, the user, the directories ------------------------------------
step "binary and service user"
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
    ok "created user $USER_NAME"
else
    info "user $USER_NAME already exists"
fi

if [ -n "$BINARY_SRC" ]; then
    # Copy then rename: writing over a running binary is ETXTBSY, a rename is not.
    tmp="$BIN.new.$$"
    cp "$BINARY_SRC" "$tmp"
    chmod 0755 "$tmp"
    mv -f "$tmp" "$BIN"
    ok "installed $BIN"
fi

install -d -o root -g "$USER_NAME" -m 0750 "$CONF_DIR" "$CERT_DIR"
ok "$CONF_DIR and $CERT_DIR are root:$USER_NAME 0750"
if [ -n "$CONFIG_SRC" ]; then
    install -o root -g "$USER_NAME" -m 0640 "$CONFIG_SRC" "$CONF"
    ok "installed $CONF (root:$USER_NAME 0640)"
fi
# The example the release ships, next to the real config and never in its place.
if [ -n "${EXAMPLE_CONF:-}" ] && [ -r "$EXAMPLE_CONF" ]; then
    install -o root -g "$USER_NAME" -m 0640 "$EXAMPLE_CONF" "$CONF.example"
    ok "example config at $CONF.example"
fi

# --- 3b. the rehearsal -----------------------------------------------------------
# Before the unit is written and before the certbot hook can restart anything:
# a config that would not load stops the install here, instead of becoming a
# service that starts and dies. Runs under --no-start too — a bad config on disk
# is a fault either way.
step "config check"
config_check || die "config $CONF would not load — stopping before the service is touched"

# --- 4. the unit -----------------------------------------------------------------
step "unit"
tmp_unit=$(mktemp)
cat > "$tmp_unit" <<'UNIT'
[Unit]
Description=uping reverse proxy
Documentation=https://github.com/raonagos/uping
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Not root. The one thing root used to buy is the right to bind :80 and :443,
# and that is one capability, not an identity: see AmbientCapabilities below.
User=uping
Group=uping
ExecStart=/usr/local/bin/uping /etc/uping/config.toml

# Pingora keeps the main process in the foreground and stops cleanly on SIGTERM.
Restart=on-failure
RestartSec=2
KillSignal=SIGTERM
TimeoutStopSec=10

# The whole of uping's privilege: ports below 1024. Nothing else in the process
# is elevated, and the capability cannot be added back after exec (NoNewPrivileges).
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

StandardOutput=journal
StandardError=journal
SyslogIdentifier=uping
# Uncomment for verbose per-request logging:
#Environment=RUST_LOG=info

# --- Hardening ---
# The config and the certificates are the only files it opens, and it opens them
# read-only. Nothing in the unit needs a writable path: logs go to the journal.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
# No SystemCallFilter here on purpose: pingora's syscall surface (epoll, io_uring
# on some builds, TLS) has not been measured under a filter, and a filter that
# is one call short takes the proxy down at runtime. Add it after a load test.
#
# AF_UNIX stays: glibc resolves names through the resolver's socket.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadOnlyPaths=/etc/uping

[Install]
WantedBy=multi-user.target
UNIT

if [ -r "$UNIT" ] && ! cmp -s "$tmp_unit" "$UNIT"; then
    bak="$UNIT.bak.$(date +%Y%m%d%H%M%S)"
    cp -p "$UNIT" "$bak"
    info "the previous unit is saved as $bak"
fi
install -o root -g root -m 0644 "$tmp_unit" "$UNIT"
rm -f "$tmp_unit"
ok "installed $UNIT"
if command -v systemd-analyze >/dev/null 2>&1; then
    out=$(systemd-analyze verify "$UNIT" 2>&1 || true)
    if [ -n "$out" ]; then
        printf '%s\n' "$out"
        bad "systemd-analyze has something to say about $UNIT (above)"
    else
        ok "systemd-analyze verify"
    fi
fi

# --- 5. the certbot hook ----------------------------------------------------------
step "certificate hook"
install -d -o root -g root -m 0755 "$HOOK_DIR"
tmp_hook=$(mktemp)
cat > "$tmp_hook" <<'HOOK'
#!/bin/sh
# uping-cert.sh — certbot deploy hook: publish one renewed lineage where the
# unprivileged proxy can read it. Installed by deploy/install.sh.
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

# uping loads certificates once at startup, so a renewal is served after a
# restart. That is a short, deliberate connection drop once per renewal.
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet uping; then
    systemctl restart uping
fi

echo "uping: installed $dst and restarted" >&2
HOOK
install -o root -g root -m 0755 "$tmp_hook" "$HOOK"
rm -f "$tmp_hook"
ok "installed $HOOK"
# certbot runs everything in renewal-hooks/deploy after a renewal: a drop-in
# there survives renewals started by the timer, which --deploy-hook does not.
# The directory is created, not probed: certbot makes it only when it first
# runs, so "missing" says nothing about whether certbot is installed — the
# old check told operators with certbot 2.x that certbot was absent.
link_dir=$(dirname "$HOOK_LINK")
install -d -o root -g root -m 0755 "$link_dir"
ln -sfn "$HOOK" "$HOOK_LINK"
ok "linked into $link_dir"
command -v certbot >/dev/null 2>&1 ||
    info "certbot not on PATH: the link is in place and fires on the first renewal once it is"

# A certificate issued before this hook existed is not picked up by the next
# renewal alone — publish what is already on disk so the install converges now.
if [ -d /etc/letsencrypt/live ]; then
    for lineage in /etc/letsencrypt/live/*/; do
        [ -f "$lineage/fullchain.pem" ] || continue
        RENEWED_LINEAGE=${lineage%/} "$HOOK" || bad "hook failed for ${lineage%/}"
        ok "published $(basename "$lineage")"
    done
fi

# --- 6. start --------------------------------------------------------------------
if [ "$DO_START" = 1 ]; then
    step "service"
    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null 2>&1 || true
    systemctl restart "$SERVICE"
    i=0
    while [ "$i" -lt 20 ]; do
        systemctl is-active --quiet "$SERVICE" && break
        i=$((i + 1))
        sleep 0.5
    done
    if systemctl is-active --quiet "$SERVICE"; then
        ok "$SERVICE is active"
    else
        bad "$SERVICE did not come up: journalctl -u $SERVICE -n 50"
    fi
fi

# --- 7. prove it -----------------------------------------------------------------
step "check"
verify || true

if [ "$FAILS" -gt 0 ]; then
    printf '\ninstalled, but %s check(s) failed — see above.\n' "$FAILS" >&2
    exit 1
fi
printf '\ninstalled and checked.\n'
