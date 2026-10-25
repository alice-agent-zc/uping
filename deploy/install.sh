#!/bin/sh
# install.sh — install or upgrade uping as a systemd service that runs as the
# unprivileged `uping` user with one capability (CAP_NET_BIND_SERVICE).
#
# The deployment is this one file. A sudo user fetches it and runs it:
#
#   curl --proto '=https' --tlsv1.2 -sSf \
#     https://raw.githubusercontent.com/raonagos/uping/main/deploy/install.sh \
#     | sudo sh -s -- --binary ./uping
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

step() { printf '\n==> %s\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
info() { printf '        %s\n' "$*"; }
die()  { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
FAILS=0

usage() {
    cat <<'USAGE'
usage: install.sh [options]

  --binary PATH    install this file as the uping binary (checked to be ELF).
                   Omit on an upgrade where /usr/local/bin/uping already exists.
  --config PATH    install this file as /etc/uping/config.toml
                   (root:uping 0640). Omit to keep the existing one.
  --no-start       install everything, do not enable or start the service.
  --verify-only    change nothing; run the checks and exit non-zero on failure.
  -h, --help       this text.

Examples
  curl --proto '=https' --tlsv1.2 -sSf <url>/deploy/install.sh \
    | sudo sh -s -- --binary ./uping --config ./config.toml

  sudo sh install.sh --verify-only
USAGE
}

BINARY_SRC=""
CONFIG_SRC=""
DO_START=1
VERIFY_ONLY=0

while [ $# -gt 0 ]; do
    case $1 in
        --binary)      [ $# -ge 2 ] || die "--binary needs a path"; BINARY_SRC=$2; shift 2 ;;
        --config)      [ $# -ge 2 ] || die "--config needs a path"; CONFIG_SRC=$2; shift 2 ;;
        --no-start)    DO_START=0; shift ;;
        --verify-only) VERIFY_ONLY=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             usage >&2; die "unknown argument: $1" ;;
    esac
done

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

if [ "$(id -u)" != 0 ]; then
    die "run as root: curl … | sudo sh -s -- --binary ./uping"
fi
command -v systemctl >/dev/null 2>&1 \
    || die "this installer needs systemd; the manual steps are in CONTRIBUTING.md"

if [ "$VERIFY_ONLY" = 1 ]; then
    [ -r "$CONF" ] || die "no config at $CONF to check"
    verify && exit 0 || exit 1
fi

# --- 2. what it needs before it writes anything -----------------------------------
step "preflight"
if [ -n "$BINARY_SRC" ]; then
    [ -r "$BINARY_SRC" ] || die "cannot read $BINARY_SRC"
    magic=$(head -c 4 "$BINARY_SRC" | od -An -tx1 | tr -d ' \n')
    [ "$magic" = 7f454c46 ] || die "$BINARY_SRC is not an ELF binary"
    ok "binary $BINARY_SRC"
elif [ -x "$BIN" ]; then
    info "no --binary: keeping the installed $BIN"
else
    die "no binary: pass --binary PATH. There is no release asset to download yet."
fi

if [ -n "$CONFIG_SRC" ]; then
    [ -r "$CONFIG_SRC" ] || die "cannot read $CONFIG_SRC"
    ok "config $CONFIG_SRC"
elif [ -r "$CONF" ]; then
    info "no --config: keeping $CONF"
else
    die "no config at $CONF: pass --config PATH (see README.md for the format)"
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

# --- 4. the unit and the certbot hook --------------------------------------------
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
if [ -d "$(dirname "$HOOK_LINK")" ]; then
    ln -sfn "$HOOK" "$HOOK_LINK"
    ok "linked into $(dirname "$HOOK_LINK")"
else
    info "no $(dirname "$HOOK_LINK") (certbot absent?): run $HOOK by hand after a renewal"
fi

# --- 5. start --------------------------------------------------------------------
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

# --- 6. prove it -----------------------------------------------------------------
step "check"
verify || true

if [ "$FAILS" -gt 0 ]; then
    printf '\ninstalled, but %s check(s) failed — see above.\n' "$FAILS" >&2
    exit 1
fi
printf '\ninstalled and checked.\n'
