# Contributing

Thanks for looking. This file is the technical counterpart to the
[README](README.md): what you need in order to build uping, run its tests, try it
locally, and deploy it as a service.

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

## Build and test

```sh
cargo build --release
cargo test
```

The tests cover config parsing and validation, host routing, the per-IP
limiters, and SNI certificate resolution. They need no network, no certificates
on disk, and no root.

## Running it locally

`test.config.toml` is set up to run unprivileged: it listens on
`127.0.0.1:8088` / `:8443` and proxies to whatever is on `127.0.0.1:8080`.

It expects a `test.local` certificate at `certs/test.local.crt` and
`certs/test.local.key`. **No certificates are committed to this repository** —
generate your own. `certs/` is gitignored, so nothing you put there can end up
in a commit:

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

## Deploying as a service

uping does **not** run as root. The only root-level thing it does is bind `:80`
and `:443`, and that is one capability — `CAP_NET_BIND_SERVICE` — not an
identity. The unit runs as the dedicated `uping` user; the process holds no
other privilege and cannot regain any (`NoNewPrivileges=yes`,
`CapabilityBoundingSet=` one bit wide).

The deployment is one script. It carries the unit and the certbot hook, creates
the user and the directories, installs binary and config, starts the service,
and then checks what it did:

```sh
cargo build --release
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/raonagos/uping/main/deploy/install.sh \
  | sudo sh -s -- --binary target/release/uping --config config.toml
```

Re-run it to upgrade: it keeps `/etc/uping/config.toml` unless `--config` says
otherwise, and saves the unit it replaces as `uping.service.bak.<timestamp>`.
`sudo sh deploy/install.sh --verify-only` re-runs just the checks, changes
nothing, and exits non-zero on anything that still needs root — the unit's user,
the ambient capability, the config and every certificate read *as the service
user*, the live process's uid and capability mask, and who holds `:80`/`:443`.

Two things the unit does not give the user, because it must not:

- **The config** is `root:uping 0640` — readable, not writable, by the proxy.
- **The certificates.** `/etc/letsencrypt/live/*/privkey.pem` is mode `0600`
  root-owned and reissued underneath you, so the proxy never reads it: a
  certbot deploy hook copies the two files it needs into
  `/etc/uping/certs/<lineage>/` as `root:uping 0640` and restarts the service.
  Point `pub_key`/`priv_key` at that copy.

The installer drops that hook at `/usr/local/lib/uping/install-cert.sh` and
links it into `/etc/letsencrypt/renewal-hooks/deploy/`, where certbot runs it
after any renewal — including the ones its own timer starts. For a lineage that
already exists, run it once by hand:

```sh
sudo RENEWED_LINEAGE=/etc/letsencrypt/live/example.com /usr/local/lib/uping/install-cert.sh
```

```toml
[[server]]
domain   = "example.com"
pub_key  = "/etc/uping/certs/example.com/fullchain.pem"
priv_key = "/etc/uping/certs/example.com/privkey.pem"
upstream = "127.0.0.1:8080"
```

### Moving an existing root install

The same script is the migration. Publish the certificates the unprivileged
user will read, point the config at those copies, keep a copy of the old one,
then run the installer:

```sh
sudo cp -a /etc/uping/config.toml /etc/uping/config.toml.before-unprivileged
sudo RENEWED_LINEAGE=/etc/letsencrypt/live/example.com /usr/local/lib/uping/install-cert.sh
# edit pub_key/priv_key per [[server]] to /etc/uping/certs/<domain>/…
curl --proto '=https' --tlsv1.2 -sSf <install.sh url> | sudo sh -s -- --binary ./uping
curl -skI --resolve example.com:443:127.0.0.1 https://example.com/
```

Rollback is the saved unit and a `daemon-reload`, plus
`config.toml.before-unprivileged`. Nothing else on the host is changed.

### Not using systemd

`AmbientCapabilities` needs systemd. Without it, grant the binary the one
capability directly (`libcap2-bin`), and run it as `uping`:

```sh
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/uping
```

The capability lives on the file and is **lost on every rebuild** — re-apply it
after each `install`, or prefer the unit.

## Project layout

```
src/
  main.rs    # bootstrap, wiring, run
  config.rs  # TOML schema + validation
  tls.rs     # SNI certificate resolver
  limits.rs  # per-IP rate + connection limiters
  proxy.rs   # HTTPS proxy + HTTP redirect
```

## Before you open a pull request

- `cargo test` and `cargo clippy --all-targets` are clean.
- New behaviour comes with a test; keep the diff scoped.
