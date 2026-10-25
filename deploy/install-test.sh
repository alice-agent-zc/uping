#!/bin/sh
# install-test.sh — prove deploy/install.sh's release path without root, without
# a published release and without touching the host.
#
# It assembles the asset exactly as .github/workflows/release.yml does, serves it
# from a file:// mirror in place of github.com, and then checks the happy paths
# and every refusal. Nothing outside target/install-test is written.
#
#   cargo build --release --locked --target x86_64-unknown-linux-gnu
#   sh deploy/install-test.sh [target/x86_64-unknown-linux-gnu/release/uping]
#
# The privileged half of the installer (useradd, install, systemctl) cannot be
# tested here: it needs root, which the release runner does not grant either.
set -eu

REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"
TARGET=x86_64-unknown-linux-gnu
BIN=${1:-target/$TARGET/release/uping}
NAME=uping-$TARGET.tar.gz
WORK=$REPO/target/install-test

[ -x "$BIN" ] || { echo "no binary at $BIN — run: cargo build --release --locked --target $TARGET" >&2; exit 1; }
[ -x deploy/install.sh ] || exit 1

pass=0
fail=0
check() { # <what> <expected-exit-class: zero|nonzero> <actual-exit> [needle] [output]
    needle=${4:-}; out=${5:-}
    if { [ "$2" = zero ] && [ "$3" -eq 0 ]; } || { [ "$2" = nonzero ] && [ "$3" -ne 0 ]; }; then
        if [ -z "$needle" ] || printf '%s' "$out" | grep -qF -- "$needle"; then
            printf 'ok    %s\n' "$1"; pass=$((pass + 1)); return 0
        fi
        printf 'FAIL  %s: output lacks "%s"\n---\n%s\n---\n' "$1" "$needle" "$out"
    else
        printf 'FAIL  %s: wanted a %s exit, got %s\n---\n%s\n---\n' "$1" "$2" "$3" "$out"
    fi
    fail=$((fail + 1))
}
attempt() { out=$( "$@" 2>&1 ) && rc=0 || rc=$?; }

echo "== the installer is valid shell"
sh -n deploy/install.sh && { echo "ok    sh -n"; pass=$((pass + 1)); }

echo "== build the asset the way the workflow does"
rm -rf "$WORK"
mkdir -p "$WORK/dist"
cp "$BIN" "$WORK/dist/uping"
strip "$WORK/dist/uping" 2>/dev/null || true
cp config.toml "$WORK/dist/config.toml.example"
tar -C "$WORK/dist" -czf "$WORK/$NAME" uping config.toml.example
( cd "$WORK" && sha256sum "$NAME" > "$NAME.sha256" )
echo "ok    $(cat "$WORK/$NAME.sha256")"

mkdir -p "$WORK/mirror/latest/download" "$WORK/mirror/download/v0.1.1"
for d in latest/download download/v0.1.1; do
    cp "$WORK/$NAME" "$WORK/$NAME.sha256" "$WORK/mirror/$d/"
done
MIRROR=file://$WORK/mirror
export UPING_BASE_URL=$MIRROR

echo "== the binary under test runs"
attempt "$BIN" /nonexistent.toml
check "binary reaches config loading" nonzero "$rc" "loading configuration" "$out"

echo "== fetch, latest"
attempt sh deploy/install.sh --fetch-only "$WORK/f1"
check "--fetch-only latest" zero "$rc" "sha256" "$out"
[ -x "$WORK/f1/uping" ] && { echo "ok    binary unpacked and executable"; pass=$((pass + 1)); } \
    || { echo "FAIL  no binary in $WORK/f1"; fail=$((fail + 1)); }
[ -f "$WORK/f1/config.toml.example" ] && { echo "ok    example config shipped"; pass=$((pass + 1)); } \
    || { echo "FAIL  no example config in $WORK/f1"; fail=$((fail + 1)); }
attempt "$WORK/f1/uping" /nonexistent.toml
check "fetched binary runs" nonzero "$rc" "loading configuration" "$out"

echo "== fetch, a pinned tag"
attempt sh deploy/install.sh --version v0.1.1 --fetch-only "$WORK/f2"
check "--version v0.1.1" zero "$rc" "release v0.1.1" "$out"

echo "== the pipeline form: the script arrives on stdin"
rm -rf "$WORK/f3"
attempt sh -s -- --fetch-only "$WORK/f3" < deploy/install.sh
check "script from stdin" zero "$rc" "sha256" "$out"

echo "== refusals"
attempt sh deploy/install.sh --version v9.9.9 --fetch-only "$WORK/r1"
check "an unpublished tag fails" nonzero "$rc" "cannot download" "$out"

mkdir -p "$WORK/tamper/latest/download"
cp "$WORK/$NAME" "$WORK/tamper/latest/download/"
printf '%064d  %s\n' 0 "$NAME" > "$WORK/tamper/latest/download/$NAME.sha256"
attempt env UPING_BASE_URL=file://$WORK/tamper sh deploy/install.sh --fetch-only "$WORK/r2"
check "a tampered sha256 is refused" nonzero "$rc" "sha256 mismatch" "$out"

mkdir -p "$WORK/nosha/latest/download"
cp "$WORK/$NAME" "$WORK/nosha/latest/download/"
attempt env UPING_BASE_URL=file://$WORK/nosha sh deploy/install.sh --fetch-only "$WORK/r3"
check "a missing sha256 is refused" nonzero "$rc" "no published checksum" "$out"

mkdir -p "$WORK/textpkg/latest/download" "$WORK/textsrc"
printf 'not an elf\n' > "$WORK/textsrc/uping"
tar -C "$WORK/textsrc" -czf "$WORK/textpkg/latest/download/$NAME" uping
( cd "$WORK/textpkg/latest/download" && sha256sum "$NAME" > "$NAME.sha256" )
attempt env UPING_BASE_URL=file://$WORK/textpkg sh deploy/install.sh --fetch-only "$WORK/r4"
check "a non-ELF payload is refused" nonzero "$rc" "is not an ELF binary" "$out"

attempt sh deploy/install.sh --binary "$WORK/textsrc/uping" --version v0.1.1
check "--binary with --version is refused" nonzero "$rc" "exclusive" "$out"

echo "== machine types, via a stubbed uname"
mkdir -p "$WORK/fakebin"
printf '#!/bin/sh\ncase $1 in -s) echo Darwin ;; *) echo x86_64 ;; esac\n' > "$WORK/fakebin/uname"
chmod +x "$WORK/fakebin/uname"
attempt env PATH="$WORK/fakebin:$PATH" sh deploy/install.sh --fetch-only "$WORK/r5"
check "non-Linux is refused with a reason" nonzero "$rc" "systemd service on Linux" "$out"

printf '#!/bin/sh\ncase $1 in -s) echo Linux ;; *) echo riscv64 ;; esac\n' > "$WORK/fakebin/uname"
attempt env PATH="$WORK/fakebin:$PATH" sh deploy/install.sh --fetch-only "$WORK/r6"
check "an unpublished machine type is refused" nonzero "$rc" "no release asset is published for machine type riscv64" "$out"

printf '#!/bin/sh\ncase $1 in -s) echo Linux ;; *) echo aarch64 ;; esac\n' > "$WORK/fakebin/uname"
attempt env PATH="$WORK/fakebin:$PATH" sh deploy/install.sh --fetch-only "$WORK/r7"
check "aarch64 asks for the aarch64 asset" nonzero "$rc" "uping-aarch64-unknown-linux-gnu.tar.gz" "$out"

echo "== no root, no --fetch-only"
attempt sh deploy/install.sh
check "installing as non-root stops with the sudo hint" nonzero "$rc" "run as root" "$out"

echo "== help"
attempt sh deploy/install.sh --help
check "--help" zero "$rc" "--fetch-only DIR" "$out"

printf '\n%d ok, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
