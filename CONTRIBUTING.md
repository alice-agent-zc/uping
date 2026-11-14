# Contributing

Thanks for looking. This file is the technical counterpart to the
[README](README.md): what you need in order to build uping, run its tests, try it
locally, and run it as an ordinary user.

## Prerequisites

uping is a single Rust binary. Building it needs:

- A Rust toolchain — edition 2021, any reasonably recent stable.
- A C toolchain (`cc` / `gcc` / `clang`) — the TLS and compression libraries it
  links against are C.
- **CMake.** Pingora's HTTP stack pins `flate2` to the `zlib-ng` backend, and
  `libz-ng-sys` builds that backend with CMake at compile time. Without `cmake`
  on `PATH` the build stops several crates deep, with an error that never
  mentions CMake.
- OpenSSL development headers (`libssl-dev` on Debian/Ubuntu).

TLS is on the **OpenSSL** backend deliberately: dynamic per-SNI certificate
selection — one listener, many domains — only exists for OpenSSL/BoringSSL in
Pingora. The rustls backend logs a warning and ignores the callback.

The ACME client uses `rustls` with the `ring` provider, not `aws-lc`, so the
build does not need that toolchain.

## Build and test

```sh
cargo build --release
cargo test
```

The suite runs without root, without network and without a certificate checked
into the tree:

- config parsing and validation, including static roots, IPv6 listeners and
  certificate modes;
- host routing, path routing, the per-IP limiters, SNI resolution;
- static-file traversal and symlink guards;
- a throwaway ACME **CA over TLS** (`tests/acme_e2e.rs`) that exercises a real
  first start: account creation, http-01 token publication and fetch, order
  finalization, and the written `cert/<domain>/` pair;
- `--check` against a corpus of bad configs (`tests/config_check.rs`);
- end-to-end raw TCP forwarding and static serving against the real binary.

Run the formatting and lint gates before opening a PR:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Running it locally

`test.config.toml` is set up to run unprivileged: it listens on
`127.0.0.1:8088` / `:8443` and proxies to whatever is on `127.0.0.1:8080`.

It expects a `test.local` certificate at `certs/test.local.crt` and
`certs/test.local.key`. **No certificates are committed to this repository** —
generate your own. `certs/` is gitignored, so nothing you put there can end up in
a commit:

```sh
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/test.local.key \
  -out certs/test.local.crt \
  -subj "/CN=test.local" \
  -addext "subjectAltName=DNS:test.local"
```

Then, in one terminal a throwaway backend, and in another uping:

```sh
python3 -m http.server 8080
cargo run -- test.config.toml
```

```sh
curl -k  --resolve test.local:8443:127.0.0.1 https://test.local:8443/
curl -i  --resolve test.local:8088:127.0.0.1 http://test.local:8088/     # -> 301
```

`-k` because your certificate is self-signed, and `--resolve` because
`test.local` is not in DNS — the TLS handshake needs a hostname (SNI) to choose
a certificate for.

For a static root, point `root = "…"` at a directory and drop `upstream`; for
ACME, `keys = "auto"` and a name that resolves to the host.

## Running it as a service

uping does **not** run as root. The only root-level thing it does is bind `:80`
and `:443`, and that is one capability — `CAP_NET_BIND_SERVICE` — not an
identity. Install it as a user service:

```sh
cargo build --release
sudo setcap 'cap_net_bind_service=+ep' target/release/uping
mkdir -p ~/.config/systemd/user
cp uping.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now uping
loginctl enable-linger "$USER"        # start at boot, not only at login
```

The repository's `uping.service` assumes the source checkout at `~/uping` and a
config at `~/uping/config.toml`; adjust `WorkingDirectory` / `ExecStart` if your
paths differ. The capability is stored on the binary and is **lost on every
rebuild** — re-apply it after `cargo build --release`.

Certificates live under the config directory: `~/uping/cert/<domain>/` in this
layout, `auto`-managed. For `keys = "manual"`, point `pub_key`/`priv_key` at any
readable pair — a certbot copy under the same tree is fine, but uping will not
reload it until restart.

The deployment script and its certbot hook were removed in v0.2.1. They belonged
to the root-owned `/etc/uping` layout; ACME now does the renewal in-process. The
apt layout (`/etc/uping/config.toml`, `/bin/uping`, `/etc/uping/cert`) is planned
for the v0.3 release, and a package will carry its own unit.

## Project layout

```
src/
  main.rs          # bootstrap, wiring, run, --check
  config.rs        # TOML schema + validation
  tls.rs           # SNI certificate resolver (live, renewals replace entries)
  acme.rs          # ACME account, http-01 orders, storage, renewal thread
  static_files.rs  # safe path resolution + streamed file responses
  limits.rs        # per-IP rate + connection limiters
  proxy.rs         # HTTPS proxy, HTTP redirect + ACME challenge path
  stream.rs        # experimental raw TCP forwarder
tests/
  config_check.rs  # the bad-config corpus for --check
  acme_e2e.rs      # a fake ACME CA, TLS, real first start
  static_e2e.rs    # static serving through the real binary
  stream_e2e.rs    # raw TCP forwarding through the real binary
uping.service      # user unit
```

## Before you open a pull request

- `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test` are clean.
- New behaviour comes with a test; keep the diff scoped.
- Anything touching `[[stream]]` should remember it is labelled experimental in
  the README and the startup log.
