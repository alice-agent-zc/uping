# Contributing and architecture

This is the developer manual. The user manual — every config field, defaults,
examples, certificate modes, private sites and DNS — is the
[README](README.md).

## Prerequisites

uping is a single Rust binary. Building it needs:

- A Rust toolchain — edition 2021, any reasonably recent stable.
- A C toolchain (`cc` / `gcc` / `clang`) — TLS and compression are C libraries.
- **CMake.** Pingora's HTTP stack pins `flate2` to the `zlib-ng` backend, and
  `libz-ng-sys` builds that backend with CMake. Without `cmake` on `PATH` the
  build stops several crates deep, with an error that never mentions CMake.
- OpenSSL development headers (`libssl-dev` on Debian/Ubuntu).

TLS is on the **OpenSSL** backend deliberately: dynamic per-SNI certificate
selection — one listener, many domains — only exists for OpenSSL/BoringSSL in
Pingora. The ACME client uses `rustls` with the `ring` provider, not `aws-lc`,
so it adds no second crypto build chain.

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
- a SIGHUP reload test (`tests/reload_e2e.rs`): new root, invalid TOML, listener
  change;
- end-to-end static serving and raw TCP forwarding.

## Architecture

`src/` is deliberately small and split by responsibility:

```
src/
  main.rs          # CLI, bootstrap, wiring, --check, --dns-zone
  config.rs        # TOML schema, validation, listener groups, paths
  reload.rs        # SIGHUP -> swap routes/certs/limits/domains
  tls.rs           # SNI resolver; renewals replace entries live
  acme.rs          # account, http-01 orders, storage, renewal thread
  static_files.rs  # safe path resolution + streamed files
  health.rs        # upstream probes, 503 when a backend is down
  limits.rs        # per-IP, per-domain rate + connection limiters
  proxy.rs         # HTTPS proxy, HTTP redirect + ACME challenge path
  stream.rs        # experimental raw TCP forwarder
tests/
  config_check.rs  # bad-config corpus and --check
  acme_e2e.rs      # fake ACME CA over TLS, real first start
  route_e2e.rs     # routes inside their server
  listen_e2e.rs    # a per-server listener and its 421 isolation
  health_e2e.rs    # backend down -> 503, recovered -> 200
  upstream_tls_e2e.rs  # private CA, verify opt-out, wrong-SNI failure
  private_http_e2e.rs  # serve_http = false on :80, HTTPS still served
  dns_zone_e2e.rs      # --dns-zone records and refusals
  reload_e2e.rs    # SIGHUP, bad config, listener warning
  static_e2e.rs    # static serving through the real binary
  stream_e2e.rs    # raw TCP through the real binary
uping.service      # user unit
```

### Config

`config.rs` is the schema and the whole validation pass. The invariants that
matter to a contributor:

- `[[server]]` is the only server form; `[server."domain"]` is refused with a
  clear error instead of being silently normalized.
- Routes are **only** the inline `routes = [...]` array inside their server.
  There is no global route table: a route cannot drift to another domain.
- Every path is resolved against the config file's directory unless it is
  absolute. `index` is a bare file name, not a path.
- A server and a route need exactly one of `upstream` / `root`.
- `keys` is inferred when omitted: no key paths → `auto`; both → `manual`.
  `auto` and `internal` are the only ACME modes and require `serve_http = true`.
- `per_ip_conns_per_sec` is host-wide; a per-server value is an error. The
  request rate and body cap are per server.
- Unknown fields are refused, so a typo cannot silently become a default.

All defaults and examples are in the [README](README.md); do not duplicate that
table here.

### TLS

Pingora 0.9 dropped `TlsSettings::add_cert`, so a multi-domain listener picks
its certificate during the handshake through the `TlsAccept` callback. The
resolver starts with no certificate installed; the callback supplies the leaf,
chain and key. `fallback_cert` exists because scanners connect without SNI: it
is a listener-wide choice made before a domain exists, not a per-server field.

### ACME

`CertManager` owns the certificate files, the account and the renewal thread.
An order is http-01 only: create/load an account, order, publish the token
through the challenge store, wait for the CA, write the pair atomically, then
install it into the live resolver. The startup path binds the HTTP address
itself (`obtain_missing`); a reload uses the already-running listener
(`obtain_missing_live`).

Two profiles exist: the public `[acme]` directory and the private
`[acme.internal]` directory. The account file is hashed by directory URL, so
public and private CAs never share one. `ca_bundle` is the trust anchor for
uping's connection to the ACME server; client trust is separate and is the
operator's responsibility.

### Limits

`RequestLimiter` keeps one fixed-size estimator table per domain (bounded by
the config, not by client traffic) and shares the counters across reloads.
`ConnLimiter` runs at TCP accept and is host-wide. `max_body_bytes` is checked
on `Content-Length` and again while streaming a chunked body; the effective
value is carried in `ProxyCtx`.

### Health

One background thread reads the live route table, checks each upstream against
its own interval, and probes only what is due. The reload path primes the new
table synchronously, so the first request after a reload never sees an
unresolved address. A down backend is answered with a static `503` page and
`Retry-After`, with no host or upstream echoed back.

### Reload

`Reloader` re-reads the same file and validates the whole candidate before
touching live state. Routes, limits, health, `[tls] fallback_cert`, manual
certificates and listener domain sets are applied live. `[listen]`,
`https_listen`/`https_listen6`, `[[stream]]`, `[acme]` and `[acme.internal]`
require a restart and are reported as such.

### Streams

`[[stream]]` is a Pingora `ServerApp` listener that copies bytes both ways and
forwards half-close. It is experimental: keep that label in config, docs and
error messages.

## Running it locally

`test.config.toml` listens on `127.0.0.1:8088`/`:8443` and proxies to
`127.0.0.1:8080`. It expects a `test.local` pair in `certs/`:

```sh
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/test.local.key \
  -out certs/test.local.crt \
  -subj "/CN=test.local" \
  -addext "subjectAltName=DNS:test.local"
```

Then, in one terminal a throwaway backend and in another uping:

```sh
python3 -m http.server 8080
cargo run -- test.config.toml
```

```sh
curl -k  --resolve test.local:8443:127.0.0.1 https://test.local:8443/
curl -i  --resolve test.local:8088:127.0.0.1 http://test.local:8088/   # 301
```

`-k` for the self-signed cert, `--resolve` because `test.local` is not in DNS
(the handshake needs an SNI hostname).

## Deployment

`uping.service` assumes a source checkout at `~/uping` and
`~/uping/config.toml`; edit `WorkingDirectory`/`ExecStart` if yours differs.
Certificates and the ACME account live under `~/uping/cert/`, so no root-owned
directory is involved.

```sh
cargo build --release
sudo setcap 'cap_net_bind_service=+ep' target/release/uping
mkdir -p ~/.config/systemd/user
cp uping.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now uping
loginctl enable-linger "$USER"
```

The capability is on the binary and is **lost on every rebuild**; re-apply
`setcap` after `cargo build --release`.

The planned apt layout — `/etc/uping/config.toml`, `/bin/uping`,
`/etc/uping/cert` — is for the future apt release.

## Release

Publishing is tag-driven. A tag names the exact commit that becomes the
release, so the asset and the crate cannot drift from the source:

```sh
git tag v0.3.0
git push origin v0.3.0
```

Two workflows run on `v*` tags:

- `.github/workflows/release.yml` — builds the Linux binary, runs the tests,
  packages `uping-<target>.tar.gz` + `.sha256`, and creates/updates the GitHub
  release. It uses the built-in `GITHUB_TOKEN`; `permissions: contents: write`
  is already set, so there is no secret to add.
- `.github/workflows/crates.yml` — publishes the crate to crates.io. It needs
  **`CARGO_REGISTRY_TOKEN`**, holding a crates.io API token scoped to `uping`.
  Put it in the GitHub Environment named **`publish`** (Settings →
  Environments → publish → Environment secrets), or as a repository secret;
  both jobs run in that environment, so you can add required reviewers there
  before anything is published. `cargo publish` compiles the tagged tree in a
  scratch directory, so a broken tag fails there instead of publishing
  something that does not build.

Both workflows also expose a `workflow_dispatch` input named `tag` to rebuild
an existing tag. The tag must match `Cargo.toml`'s version.

## Before you open a pull request

- `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test` are clean.
- New behaviour comes with a test; keep the diff scoped.
- Config changes update the README (defaults and examples) and `config.toml`.
- Anything touching `[[stream]]` keeps it labelled experimental.
