# Contributing and architecture

This is the developer manual. The user manual — every config field, defaults,
examples, certificate modes, private sites and DNS — is the
[README](README.md).

## Prerequisites

uping is a single Rust binary. Building it needs:

- A Rust toolchain — edition 2021, any reasonably recent stable.
- A C toolchain (`cc` / `gcc` / `clang`) — TLS and compression are C libraries.
- **CMake.** The HTTP stack pins `flate2` to the `zlib-ng` backend, and
  `libz-ng-sys` builds that backend with CMake. Without `cmake` on `PATH` the
  build stops several crates deep, with an error that never mentions CMake.
- **Perl.** `pingora-openssl` enables `openssl/vendored`, so `openssl-sys`
  compiles OpenSSL from its C sources during the build (Perl's `Configure`
  plus the C toolchain). System `libssl-dev` headers are not needed, and the
  resulting binary links libcrypto statically: `ldd` on the Linux build shows
  only libc, libm and libgcc.

TLS is on the **OpenSSL** backend deliberately: dynamic per-SNI certificate
selection — one listener, many domains — only exists for OpenSSL/BoringSSL in
the proxy stack. The ACME client uses `rustls` with the `ring` provider, not
`aws-lc`, so it adds no second crypto build chain.

## Build and test

```sh
cargo build --release
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

The suite needs no root, no network and no certificate checked into the tree:

- config parsing, validation, listener groups, IPv4/IPv6, certificate modes,
  per-server limits/health, absolute paths;
- host/path routing, prefix stripping, the per-domain limiters, SNI resolution
  and fullchain chains;
- static-file traversal and symlink guards, directory redirects with
  `strip_prefix`;
- `--check` against a corpus of bad configs (`tests/config_check.rs`);
- a throwaway ACME **CA over TLS** (`tests/acme_e2e.rs`) that drives a real
  first start: account, http-01 publication/fetch, finalization, written pair;
- a route end-to-end test (`tests/route_e2e.rs`): two domains, routes in
  `routes = [...]`;
- a per-server listener test (`tests/listen_e2e.rs`): its own socket answers,
  the global one returns `421`;
- health checks (`tests/health_e2e.rs`): a backend dies → `503`, comes back →
  `200`, and a TCP-only listener is not a healthy TLS upstream;
- upstream TLS (`tests/upstream_tls_e2e.rs`): private CA, verify opt-out, and a
  wrong SNI failing the handshake;
- a private site (`tests/private_http_e2e.rs`): `serve_http = false` is `404` on
  :80 and still works on :443;
- `--dns-zone` (`tests/dns_zone_e2e.rs`): records, a wildcard refusal, and the
  `--check` conflict;
- the local CA (`src/internal_ca.rs` unit tests): an Ed25519 root and leaf that
  chains, `alt_names` in the same leaf, a second run that reuses the pair, a
  pair signed by another root replaced, a half root pair refused, and `/root.crt`
  over HTTP;
- a SIGHUP config-swap test: new root, invalid TOML, listener change;
- end-to-end static serving and raw TCP forwarding.

## Architecture

`src/` is deliberately small and split by responsibility:

```
src/
  main.rs          # CLI, bootstrap, wiring, --check, --dns-zone
  config.rs        # TOML schema, validation, listener groups, paths
  sighup.rs        # SIGHUP -> swap routes/certs/limits/domains
  tls.rs           # SNI resolver; renewals replace entries live
  acme.rs          # account, http-01 orders, storage, renewal thread
  internal_ca.rs   # keys = "internal": zone-scoped CA, leaves, TLS root endpoint
  static_files.rs  # safe path resolution + streamed files
  health.rs        # upstream probes, 503 when a backend is down
  limits.rs        # per-IP, per-domain rate + connection limiters
  proxy.rs         # HTTPS proxy, HTTP redirect + ACME challenge path
  stream.rs        # raw TCP forwarder
tests/
  config_check.rs  # bad-config corpus and --check
  (internal_ca.rs)  # root/leaf generation, SANs, reuse, half-root refusal
  acme_e2e.rs      # fake ACME CA over TLS, real first start
  route_e2e.rs     # routes inside their server
  listen_e2e.rs    # a per-server listener and its 421 isolation
  health_e2e.rs    # backend down -> 503, recovered -> 200
  upstream_tls_e2e.rs  # private CA, verify opt-out, wrong-SNI failure
  private_http_e2e.rs  # serve_http = false on :80, HTTPS still served
  dns_zone_e2e.rs      # --dns-zone records and refusals
  sighup_e2e.rs    # SIGHUP, bad config, listener warning
  static_e2e.rs    # static serving through the real binary
  stream_e2e.rs    # raw TCP through the real binary
uping.service      # user unit for a ~/uping checkout
```

### Config

`config.rs` is the schema and the whole validation pass. The invariants that
matter to a contributor:

- `[[server]]` is the only server form.
- Routes are **only** the inline `routes = [...]` array inside their server.
  There is no global route table: a route cannot drift to another domain.
- Every path is resolved against the config file's directory unless it is
  absolute. `index` is a bare file name, not a path.
- The HTTP sockets are `[listen] ipv4`/`ipv6` plus, for each ACME server with
  an explicit `https_listen`/`https_listen6`, the same IP on `[listen] http`.
  `Config::http_addrs` owns that derivation; http-01 always uses the HTTP port.
- A server and a route need exactly one of `upstream` / `root`.
- `keys` is inferred when omitted: no key paths → `auto`; both → `manual`.
  `auto` and `internal` are the only ACME modes and require `serve_http = true`.
- `per_ip_conns_per_sec` is host-wide; a per-server value is an error. The
  request rate and body cap are per server.
- Unknown fields are refused, so a typo cannot silently become a default.

All defaults and examples are in the [README](README.md); do not duplicate that
table here.

### TLS

The proxy stack dropped `TlsSettings::add_cert`, so a multi-domain listener picks
its certificate during the handshake through the `TlsAccept` callback. The
resolver starts with no certificate installed; the callback supplies the leaf,
chain and key. `fallback_cert` exists because scanners connect without SNI: it
is a listener-wide choice made before a domain exists, not a per-server field.

### ACME

`CertManager` owns the certificate files, the account and the renewal thread.
An order is http-01 only: create/load an account, order, publish the token
through the challenge store, wait for the CA, write the pair atomically, then
install it into the live resolver. The startup path binds the HTTP address
itself (`obtain_missing`); a `SIGHUP` uses the already-running listener
(`obtain_missing_live`).

The HTTP challenge listener follows an ACME server's explicit
`https_listen`/`https_listen6` onto the same IP at `[listen] http`; see
`Config::http_addrs`. That is what lets a private site on the rupa VPN answer
http-01 on `10.8.0.1:80` without a second address setting.

Startup issuance is best effort: `obtain_missing` returns whether every pair
was obtained, and a failure is logged rather than returned as an error — even a
temporary `:80` listener that cannot bind is now a warning. A failed startup
order delays the renewal thread's first pass by an hour; a clean start checks
after 30 seconds. This is deliberate: an exited process under a supervisor
would be restarted every few seconds and exhaust the failed-authorization rate
limit. Do not turn an order failure back into a fatal startup error.

The local CA has no account and no directory. `ca_bundle` (when `[acme]` uses a
custom server) is the trust anchor for uping's connection to the ACME server;
client trust is separate and is the operator's responsibility.

### Limits

`RequestLimiter` keeps one fixed-size estimator table per domain (bounded by
the config, not by client traffic) and shares the counters across config swaps.
`ConnLimiter` runs at TCP accept and is host-wide. `max_body_bytes` is checked
on `Content-Length` and again while streaming a chunked body; the effective
value is carried in `ProxyCtx`.

### Health

One background thread reads the live route table, checks each upstream against
its own interval, and probes only what is due. The `SIGHUP` path primes the new
table synchronously, so the first request after a config swap never sees an
unresolved address. A down backend is answered with a static `503` page and
`Retry-After`, with no host or upstream echoed back.

### Config swap

The `SIGHUP` handler re-reads the same file and validates the whole candidate
before touching live state. Routes, limits, health, `[tls] fallback_cert`, manual
certificates and listener domain sets are applied live. `[listen]`,
`https_listen`/`https_listen6`, `[[stream]]`, `[acme]` and `[internal]`
require a restart and are reported as such.

### Local CA

`keys = "internal"` never talks to a network. `internal_ca.rs` generates the root
on first use and signs leaves for one zone only, `[internal] domain`: a name
outside it is rejected when the config loads and again at issuance, so the CA
cannot accidentally vouch for someone else's name. Ed25519 by default,
`alt_names` in the SAN list, renewed before expiry on the same hourly loop as
ACME. Files are written atomically (`.<name>.tmp-<pid>` then rename) with `0644`
for the chain and `0600` for the key. A missing half of the root pair is refused
rather than regenerated: a new root would strand every client that installed the
old one.

`serve_root` is a URL, not an address: the endpoint's host gets a leaf from the
same CA, so it presents a certificate chaining to the root it serves. The
listener resolves the host (normally the VPN address), binds the first address
that accepts it (IPv4 first), and serves only `GET|HEAD /root.crt` over TLS.
Resolution and binding are best-effort: a host that is not up yet is a warning,
like any other listener.

Generation is in-process through the `openssl` crate — the same libcrypto the
proxy already uses for TLS. No shell command, no `step-ca`, no `certbot`, no
ACME client. `PKey::generate_ed25519` is the default; `EcKey::generate` covers
P-256 and `Rsa::generate` RSA-2048. An `X509Builder` sets CN/O, the SAN list,
critical Basic Constraints (CA for the root, end-entity for the leaf), Key Usage
and the `serverAuth` EKU. Ed25519 is signed with `MessageDigest::null()` —
OpenSSL signs the message itself and rejects a digest there — while P-256 and
RSA use SHA-256. `rcgen` was not pulled in: it would be a second X.509
implementation for no gain, and OpenSSL is already linked and already required
by pingora's dynamic SNI callbacks.
Resolution and binding are best-effort, because the VPN address may arrive
after uping starts.

### Failure isolation

A domain is not the process. A missing manual pair, an unwritable CA directory,
a CA that refuses an order and a listener address that does not exist yet are all
`log::warn` and skip that domain or socket; the other domains keep serving. The
listener probe in `main.rs` mirrors pingora's own socket (`SO_REUSEADDR`) because
pingora panics on a failed bind, which would take every listener of that service
down with it.

### Streams

`[[stream]]` is a `ServerApp` listener that copies bytes both ways and forwards
half-close. It is stable since v0.4: what it does is one listener per entry, no
TLS termination, and the upstream owns the protocol. `tests/stream_e2e.rs`
drives the compiled binary for the raw forward, the half-close drain, a dead
upstream and a `0.0.0.0` bind.

## Running it locally

`test.config.toml` listens on `127.0.0.1:8088`/`:8443` and proxies to
`127.0.0.1:8080`. `keys = "internal"` makes uping create its own CA and leaf
under `cert/internal/` on first start, so there is nothing to generate first:

```sh
python3 -m http.server 8080        # in one terminal
cargo run -- test.config.toml      # in another
```

```sh
curl -k  --resolve test.local:8443:127.0.0.1 https://test.local:8443/
curl -i  --resolve test.local:8088:127.0.0.1 http://test.local:8088/   # 301
```

`-k` because the leaf is signed by the local CA (trust
`cert/internal/ca/root.crt` to drop it), `--resolve` because `test.local` is not
in DNS (the handshake needs an SNI hostname).

## Deployment

Two supported shapes, same binary:

* **The Debian package** (next section) for the standard directories:
  `/usr/bin/uping`, `/etc/uping/config.toml`, `/var/lib/uping`, a system unit
  with an ambient bind capability. `dpkg -i` also creates the service user and
  a working loopback default.
* **The `~/uping` checkout**, for a single-user host or a development machine:
  `target/release/uping` with `config.toml` and `cert/` beside it. The binary
  carries `CAP_NET_BIND_SERVICE` via `setcap`, which a rebuild drops, so
  re-apply it. `uping.service` in the repository root is the user unit for this
  shape; it can order itself after `rupa.service` when both run in the same
  user manager.

Use one shape per host for a given port.

## Debian package

`cargo deb` reads `[package.metadata.deb]` from `Cargo.toml`. The files it
installs live in `packaging/`:

```
packaging/uping.service         system unit: User=uping, ambient bind capability
packaging/uping.tmpfiles.conf   creates /var/lib/uping, owner uping, mode 0750
packaging/uping.8               man page; cargo-deb installs it gzipped as
                                /usr/share/man/man8/uping.8.gz
packaging/config.toml.default   the working default installed on a fresh install
config.toml.example              commented template (shipped as /usr/share/uping/...)
packaging/www/index.html        the page the default serves on https://localhost:8443
packaging/README.Debian         install, paths, upgrade and purge notes
packaging/debian/postinst       user, data dir, default config, enable and start
packaging/debian/prerm          stops the unit on remove
packaging/debian/postrm         disables the unit; keeps /etc and /var/lib
```

The `packaging/debian/` maintainer scripts are the only shell in the tree. That
is not a choice: dpkg runs those files itself, and they are what makes `dpkg -i`
create the user, the default configuration and the enabled service. Everything
else (build, test, release) is plain commands in this document.

Four rules shape it:

* **`dpkg -i` is the whole install.** The postinst creates the user and group
  (`adduser` if present, `useradd`/`groupadd` otherwise — minimal containers
  have neither adduser nor systemd-tmpfiles), the data directory, a working
  default configuration, then enables and starts the unit. It distinguishes a
  fresh install from an upgrade with `$2` (empty on a fresh install): a fresh
  install starts the default, an upgrade only `try-restart`s a unit that is
  already enabled, so a service the admin disabled stays disabled.
* **An existing configuration is never replaced.** The package does not ship
  `/etc/uping/config.toml` in its archive; the postinst copies
  `config.toml.default` there only when the file is absent. There is no
  conffile prompt, and a reinstall cannot clobber a real configuration.
* **No `setcap`.** The unit carries `AmbientCapabilities=CAP_NET_BIND_SERVICE`
  and a bounding set with nothing else, so the capability survives binary
  upgrades — unlike an xattr on the file, which a rebuild silently drops.
* **Functional files are not under `/usr/share/doc` or `/usr/share/man`.**
  Ubuntu and Debian ship dpkg path excludes that drop both trees (only
  `copyright` survives under doc), so the default and example configs live in
  `/usr/share/uping/`. The man page is installed in the standard
  `/usr/share/man/man8/` and is simply absent on images that exclude man pages;
  `man uping` is the standard path, not a promise that every image has it.

The default config is loopback-only on purpose: `127.0.0.1:8080`/`:8443`, a
static page from `/usr/share/uping/www`, and a `localhost` leaf from the local
CA. Installing a package must not bind `:80`/`:443`, contact an ACME server, or
compete with a webserver that is already running.

The `.deb` must be built where the target glibc lives: this host's is newer
than the release runner's, so the compile happens inside the release image and
`cargo deb --no-build` runs on the host afterwards.

```sh
docker run --rm -v "$PWD:/src" -w /src \
    -e CARGO_HOME=/src/target/deb-cargo \
    -e RUSTUP_HOME=/src/target/deb-cargo/rustup \
    -e CARGO_BUILD_JOBS=2 ubuntu:24.04 sh -euc '
        apt-get update -qq
        apt-get install -y -qq ca-certificates curl build-essential cmake perl
        curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --profile minimal --default-toolchain 1.100.0
        . "$CARGO_HOME/env"
        cargo build --release --locked --target x86_64-unknown-linux-gnu'
cargo deb --no-build --target x86_64-unknown-linux-gnu
dpkg-deb -c target/debian/uping_*.deb      # file list and modes
dpkg-deb -I target/debian/uping_*.deb      # control fields
```

Test the package in the image it targets, not on the build host:

```sh
docker run --rm -v "$PWD/target/debian:/debs:ro" ubuntu:24.04 sh -euc '
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends /debs/uping_*.deb
    id uping && test -f /etc/uping/config.toml
    runuser -u uping -- /usr/bin/uping --check /etc/uping/config.toml
    dpkg-deb -c /debs/uping_*.deb | grep -q usr/share/man/man8/uping.8.gz
    dpkg -P uping >/dev/null && test -f /etc/uping/config.toml'
```

That covers the parts that only exist after dpkg ran: the user and group, the
data directory, the default `/etc/uping/config.toml` with a passing `--check`,
the man page in the archive, and a purge that keeps the CA. To watch the
installed default serve its page, add `curl` and run:

```sh
docker run --rm -v "$PWD/target/debian:/debs:ro" ubuntu:24.04 sh -euc '
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends /debs/uping_*.deb curl
    runuser -u uping -- /usr/bin/uping /etc/uping/config.toml &
    sleep 2
    curl -fsS --resolve localhost:8443:127.0.0.1 \
        --cacert /var/lib/uping/internal/ca/root.crt https://localhost:8443/ \
        | grep "uping is running"'
```

For a wider baseline, use `debian:12` instead of `ubuntu:24.04` in the build
command: the package then depends on glibc 2.36 rather than 2.38. The release
workflow uses `ubuntu:24.04` for both the tarball and the package so the two
assets agree.

## Release

Publishing is tag-driven. A tag names the exact commit that becomes the
release, so the asset and the crate cannot drift from the source:

```sh
git tag v0.4.0
git push origin v0.4.0
```

Two workflows run on `v*` tags:

- `.github/workflows/release.yml` — builds the Linux binary, runs the tests,
  packages `uping-<target>.tar.gz` + `.sha256` and the
  `uping_<version>_amd64.deb`, and creates/updates the GitHub release. It uses
  the built-in `GITHUB_TOKEN`; `permissions: contents: write` is already set, so
  there is no secret to add.
- `.github/workflows/crates.yml` — publishes the crate to crates.io. It needs
  **`CARGO_REGISTRY_TOKEN`**, holding a crates.io API token scoped to `uping`.
  Put it in the GitHub Environment named **`crates.io`** (Settings →
  Environments → crates.io → Environment secrets), or as a repository secret.
  The release workflow does not use that environment; it only needs the
  built-in token. `cargo publish` compiles the tagged tree in a scratch
  directory, so a broken tag fails there instead of publishing something that
  does not build.

Both workflows also expose a `workflow_dispatch` input named `tag` to rebuild
an existing tag. The tag must match `Cargo.toml`'s version.

## Before you open a pull request

- `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test` are clean.
- New behaviour comes with a test; keep the diff scoped.
- Config changes update the README (defaults and examples) and
  `config.toml.example`. `config.toml` itself is git-ignored: it is the local,
  machine-specific copy.
- `[[stream]]` is stable since v0.4; changing its config shape is a normal
  breaking-change decision, not an experiment.
