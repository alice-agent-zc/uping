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
identity. The unit in [`deploy/uping.service`](deploy/uping.service) declares it
and runs as the dedicated `uping` user; the process holds no other privilege and
cannot regain any (`NoNewPrivileges=yes`, `CapabilityBoundingSet=` one bit wide).

```sh
cargo build --release
sudo install -m 0755 target/release/uping /usr/local/bin/uping
sudo useradd --system --no-create-home --shell /usr/sbin/nologin uping
sudo install -d -o root -g uping -m 0750 /etc/uping /etc/uping/certs
sudo install -o root -g uping -m 0640 config.toml /etc/uping/config.toml
sudo install -m 0644 deploy/uping.service /etc/systemd/system/uping.service
sudo install -m 0755 deploy/install-cert.sh /usr/local/lib/uping/install-cert.sh
sudo systemctl daemon-reload && sudo systemctl enable --now uping
```

Two things the unit does not give the user, because it must not:

- **The config** is `root:uping 0640` — readable, not writable, by the proxy.
- **The certificates.** `/etc/letsencrypt/live/*/privkey.pem` is mode `0600`
  root-owned and reissued underneath you, so the proxy never reads it: a
  certbot deploy hook copies the two files it needs into
  `/etc/uping/certs/<lineage>/` as `root:uping 0640` and restarts the service.
  Point `pub_key`/`priv_key` at that copy.

```sh
sudo certbot renew --deploy-hook /usr/local/lib/uping/install-cert.sh
# and once by hand for the lineage that already exists:
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

The service can be re-pointed without a window longer than a restart:

```sh
sudo cp -a /etc/uping/config.toml /etc/uping/config.toml.pre-unprivileged
sudo useradd --system --no-create-home --shell /usr/sbin/nologin uping
sudo install -m 0644 deploy/uping.service /etc/systemd/system/uping.service
# copy each domain's certs where the hook would put them, then edit the two
# paths per [[server]] block as above
sudo systemctl daemon-reload && sudo systemctl restart uping
```

`deploy/check-privileges.sh` is the acceptance: run it as root before and after
and it names every remaining thing that needs root — the unit's user, the
ambient capability, the config and every certificate's readability *as the
service user*, the live process's uid and capability mask, and who holds the
`:80`/`:443` sockets. It changes nothing.

```sh
sudo ./deploy/check-privileges.sh
curl -skI --resolve example.com:443:127.0.0.1 https://example.com/
```

Rollback is the old unit and a `daemon-reload`: `config.toml.pre-unprivileged`
plus the unit as it was. Nothing else on the host was changed.

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
