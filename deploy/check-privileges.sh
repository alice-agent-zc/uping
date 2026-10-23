#!/bin/bash
# check-privileges.sh — says whether uping can serve :80/:443 without being root
# on this host, and names what still needs root.
#
# Read-only: it changes nothing, restarts nothing. Run it as root, because it
# reads the unit, other people's files, and /proc of the running proxy.
#
#   sudo ./deploy/check-privileges.sh [config.toml] [unit]
#
# Exit status: 0 all checks passed, 1 something failed, 2 could not check.
set -u

CONFIG=${1:-/etc/uping/config.toml}
UNIT=${2:-/etc/systemd/system/uping.service}
UNIT_NAME=$(basename "$UNIT" .service)
GROUP=${UPING_GROUP:-uping}

fails=0
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fails=$((fails + 1)); }
info() { printf '        %s\n' "$*"; }

[ "$(id -u)" = 0 ] || { echo "run as root: this reads the unit and the service user's files" >&2; exit 2; }

echo "uping privilege check — unit $UNIT, config $CONFIG"

# --- 1. the unit -----------------------------------------------------------------
if [ -r "$UNIT" ]; then
    ok "unit installed"
else
    bad "no unit at $UNIT (the proxy is started some other way — a shell as root is the thing to fix)"
fi

user_line=$(systemctl show -p User --value "$UNIT_NAME" 2>/dev/null)
ambient=$(systemctl show -p AmbientCapabilities --value "$UNIT_NAME" 2>/dev/null)
bound=$(systemctl show -p CapabilityBoundingSet --value "$UNIT_NAME" 2>/dev/null)

case "${user_line:-root}" in
    root|"") bad "service user is ${user_line:-unset (defaults to root)}" ;;
    *)       ok "service user is $user_line" ;;
esac
case "$ambient" in
    *cap_net_bind_service*) ok "AmbientCapabilities carries cap_net_bind_service" ;;
    *)                      bad "AmbientCapabilities does not carry cap_net_bind_service: '${ambient:-empty}'" ;;
esac
case "$bound" in
    "")                    info "CapabilityBoundingSet unset: the process keeps every capability it was granted" ;;
    "cap_net_bind_service") ok "CapabilityBoundingSet is exactly cap_net_bind_service" ;;
    *)                     bad "CapabilityBoundingSet keeps more than the one capability: '$bound'" ;;
esac

# --- 2. the service user ---------------------------------------------------------
if id -u "$GROUP" >/dev/null 2>&1; then
    ok "user $GROUP exists (uid $(id -u "$GROUP"))"
else
    bad "user $GROUP does not exist — nothing can run the unit as it"
fi

run_as() { # run_as <user> <test...>
    local u=$1; shift
    if command -v runuser >/dev/null 2>&1; then runuser -u "$u" -- "$@" 2>/dev/null
    else su -s /bin/sh "$u" -c "$*" 2>/dev/null; fi
}

if id -u "$GROUP" >/dev/null 2>&1; then
    # --- 3. the files it opens ---
    if run_as "$GROUP" test -r "$CONFIG"; then
        ok "config readable by $GROUP"
    else
        bad "config $CONFIG is not readable by $GROUP (root-only config is what keeps the proxy root)"
    fi

    # Paths are relative to the process's working directory; under systemd that is /
    workdir=$(systemctl show -p WorkingDirectory --value "$UNIT_NAME" 2>/dev/null)
    [ -n "$workdir" ] || workdir=/

    while IFS= read -r val; do
        [ -n "$val" ] || continue
        case "$val" in
            /*) path=$val ;;
            *)  path="$workdir/$val" ;;
        esac
        if run_as "$GROUP" test -r "$path"; then
            ok "cert file readable by $GROUP: $val"
        else
            bad "cert file NOT readable by $GROUP: $val — install it with deploy/install-cert.sh, not a chown of /etc/letsencrypt"
        fi
    done < <(sed -n 's/^[[:space:]]*\(pub_key\|priv_key\)[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\2/p' "$CONFIG")
fi

# --- 4. the running process ------------------------------------------------------
pid=$(systemctl show -p MainPID --value "$UNIT_NAME" 2>/dev/null)
if [ -n "${pid:-}" ] && [ "$pid" != 0 ] && [ -r "/proc/$pid/status" ]; then
    uid=$(awk '/^Uid:/{print $2}' "/proc/$pid/status")
    if [ "$uid" = 0 ]; then
        bad "running process $pid is uid 0 (root) — the unit is not in effect yet"
    else
        ok "running process $pid is uid $uid"
    fi

    capeff=$(awk '/^CapEff:/{print $2}' "/proc/$pid/status")
    if [ -n "$capeff" ]; then
        cap=$((16#$capeff))
        if [ $((cap & 0x400)) -ne 0 ]; then
            ok "effective capability set includes cap_net_bind_service"
        else
            info "effective capability set has no cap_net_bind_service (expected only if the listeners were already inherited)"
        fi
        if [ $((cap & ~0x400)) -ne 0 ]; then
            bad "effective capability set holds more than cap_net_bind_service: $capeff"
        else
            ok "effective capability set is empty apart from the bind capability"
        fi
    fi
else
    info "no running main process for $UNIT_NAME: start it and run this again to check the live set"
fi

# --- 5. who owns the sockets -----------------------------------------------------
# ss names the process, not its uid: read the uid from /proc of the pid it names.
if command -v ss >/dev/null 2>&1; then
    for port in 80 443; do
        line=$(ss -ltnpH "sport = :$port" 2>/dev/null | head -1)
        if [ -z "$line" ]; then
            info "nothing listening on :$port"
            continue
        fi
        pid_on_port=$(printf '%s' "$line" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
        if [ -z "$pid_on_port" ] || [ ! -r "/proc/$pid_on_port/status" ]; then
            info ":$port is held by a process this shell cannot name"
            continue
        fi
        owner=$(awk '/^Uid:/{print $2}' "/proc/$pid_on_port/status")
        case "$owner" in
            0)  bad ":$port is held by uid 0 (pid $pid_on_port)" ;;
            *)  ok ":$port is held by uid $owner (pid $pid_on_port)" ;;
        esac
    done
fi

echo
if [ "$fails" -eq 0 ]; then
    echo "no privilege left that needs root"
else
    echo "$fails check(s) failed"
fi
exit $(( fails > 0 ? 1 : 0 ))
