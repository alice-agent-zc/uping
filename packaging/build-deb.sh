#!/bin/sh
# Build the .deb in the distribution the release targets.
#
#   packaging/build-deb.sh [image]
#
# The container only compiles; `cargo deb` runs on the host afterwards, because
# packaging is architecture-independent once the binary exists. A .deb built on
# a newer glibc than the target machine's would not run, which is the whole
# reason for the container: the release workflow uses ubuntu-24.04, so that is
# the default image here (pass debian:12 for a wider baseline).
#
# The Rust toolchain and the crate cache live under target/deb-cargo/, which is
# git-ignored, so a second run does not reinstall them.
set -eu

# Non-interactive shells do not source ~/.cargo/env.
PATH="$HOME/.cargo/bin:$PATH"
export PATH

IMAGE=${1:-ubuntu:24.04}
TARGET=${UPING_DEB_TARGET:-x86_64-unknown-linux-gnu}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

command -v docker >/dev/null 2>&1 || {
    echo "build-deb.sh: docker is required to build in $IMAGE" >&2
    exit 1
}
command -v cargo-deb >/dev/null 2>&1 || {
    echo "build-deb.sh: cargo-deb is required (cargo install cargo-deb)" >&2
    exit 1
}

echo "building uping for $TARGET in $IMAGE" >&2
docker run --rm \
    -v "$ROOT:/src" \
    -v "$ROOT/target/deb-cargo:/cargo" \
    -w /src \
    -e CARGO_HOME=/cargo \
    -e RUSTUP_HOME=/cargo/rustup \
    -e CARGO_BUILD_JOBS=2 \
    -e CARGO_TERM_COLOR=never \
    -e TARGET="$TARGET" \
    "$IMAGE" sh -euc '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends \
            ca-certificates curl build-essential cmake perl pkg-config
        if [ ! -x /cargo/bin/rustup ]; then
            curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
                | sh -s -- -y --profile minimal --default-toolchain 1.100.0
        fi
        . /cargo/env
        cargo build --release --locked --target "$TARGET"
    '

cargo deb --no-build --target "$TARGET"
deb=$(ls -1t "$ROOT"/target/debian/uping_*.deb | head -1)
echo "built $deb" >&2
