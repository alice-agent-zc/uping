# Contributing and reference

This is the detailed manual: build, test, every config field, certificate
handling, IPv6, reload semantics and deployment. The [README](README.md) is the
short overview.

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

- config parsing, validation, listener groups, IPv4/IPv6, certificate modes;
- host/path routing, the per-IP limiters, SNI resolution and fullchain chains;
- static-file traversal and symlink guards;
- `--check` against a corpus of bad configs (`tests/config_check.rs`);
- a throwaway ACME **CA over TLS** (`tests/acme_e2e.rs`) that drives a real
  first start: account, http-01 publication/fetch, finalization, written pair;
- a route end-to-end test (`tests/route_e2e.rs`): two domains, one route each;
- a per-server listener test (`tests/listen_e2e.rs`): its own socket answers,
  the global one returns `421`;
- a SIGHUP reload test (`tests/reload_e2e.rs`): new root, invalid TOML, listener
  change;
- end-to-end static serving and raw TCP forwarding.

## Configuration

`config.toml` in the current directory is the default; pass another path as the
first argument. Every relative path — manual key files, static roots,
`cert_dir` — is resolved from the directory that holds the config file, not from
the current directory.

```toml
# Optional. One address per family, one port per protocol.
[listen]
ipv4  = "0.0.0.0"        # default; any IPv4 address
ipv6  = ""               # e.g. "2607:f1c0:f031:4500::1"; empty = no IPv6
http  = 80               # default
https = 443              # default

# Optional. Used by keys = "auto".
[acme]
email             = "ops@example.com"   # optional, but you lose expiry warnings
staging           = false
cert_dir          = "cert"              # <config dir>/cert/<domain>/
renew_before_days = 30                  # clamped to 1..=89
directory         = ""                  # custom ACME directory URL
ca_bundle         = ""                  # PEM root for a private ACME CA

# Optional. Any limit set to 0 is off.
[limits]
per_ip_rps           = 300
per_ip_conns_per_sec = 100
max_body_bytes       = 10485760

# Optional.
[tls]
fallback_cert = true

# Array form: the domain is a field.
[[server]]
domain   = "www.example.com"
keys     = "auto"                 # default when no key paths are given
upstream = "127.0.0.1:8080"

# Optional. This domain gets its own HTTPS listener instead of the global one.
# The port defaults to `[listen] https`; both families are independent.
listen  = "203.0.113.10"
listen6 = "[2001:db8::10]:8443"

[[server]]
domain = "static.example.com"
root   = "public"                 # instead of upstream
index  = "index.html"             # the default

# Map form: the table key is the domain. Routes nested below it belong to it.
[server."mcp.example.com"]
upstream = "127.0.0.1:9000"

[[server."mcp.example.com".route]]
path     = "/api"
upstream = "127.0.0.1:8081"
strip_prefix = false

[[server."mcp.example.com".route]]
path         = "/assets"
root         = "public/assets"
strip_prefix = true
```

Both server forms are accepted and mean the same thing:

| form | domain comes from | routes |
|---|---|---|
| `[[server]]` + `domain = "..."` | the `domain` field | `[[server.route]]` |
| `[server."..."]` | the table key | `[[server."...".route]]` |

The map form is recommended when a domain has several routes: the table key
names the domain, so a route cannot be attached to the wrong server by the
order of the blocks. A `domain` field is optional in the map form; if present it
must equal the table key. Two servers may not share a domain — the loader
refuses the duplicate instead of silently keeping one.

A server and a route each need **exactly one** of `upstream` or `root`.
Unknown fields are refused, so a typo cannot silently become a default.

### Listeners and IPv6

`[listen]` is the host-wide default. Each family gets **one** address, and each
protocol **one** port — there is no wildcard syntax and no address list:

```toml
[listen]
ipv4  = "203.0.113.10"
ipv6  = "2607:f1c0:f031:4500::1"
http  = 80
https = 443
```

`ipv6` is written bare (no brackets, no port); empty means "do not listen on
IPv6". An address the host does not own fails at bind time with
`Cannot assign requested address` — uping cannot infer which IPv6 address you
meant from an IPv4 one.

A `[[server]]` may override its **HTTPS** listener with `listen` / `listen6`:

```toml
[[server]]
domain   = "www.example.com"
upstream = "127.0.0.1:8080"
listen   = "203.0.113.10"          # IPv4, default port = [listen] https
listen6  = "[2001:db8::10]:8443"   # IPv6 with an explicit port
```

- The port is optional; when omitted it is `[listen] https`.
- An IPv6 address with an explicit port **must** be bracketed —
  `2001:db8::10:8443` is itself a valid IPv6 address, so the port would be
  swallowed into it.
- Overriding one family does not imply the other: `listen` alone means IPv4
  only, `listen6` alone means IPv6 only, both means both.
- Each distinct combination is its own HTTPS listener and its own DNS entry
  point. A domain is only answered on its own sockets; a request for it on the
  global listener gets `421 Misdirected Request`.
- HTTP is not per-server: it stays on `[listen] ipv4/ipv6` port 80, because that
  is where the ACME http-01 challenge answers and where the redirect lives.

An overlap (e.g. a server overriding to `0.0.0.0:443` while the global listener
already binds it) is refused when the config loads, with both sides named.

### Certificate modes

| `keys` | Meaning |
|---|---|
| omitted, no `pub_key`/`priv_key` | **`auto`** — obtain and renew through ACME |
| omitted, both key paths given | **`manual`** — read the two PEM files |
| `"auto"` | ACME; `pub_key`/`priv_key` optionally override *where* the pair is written |
| `"manual"` | Both PEM paths are required; uping never writes them |

Manual pairs are read at startup and on reload; restart after replacing a manual
file. An `auto` renewal is installed into the live resolver immediately.

### Let's Encrypt / ACME

`keys = "auto"` uses the **http-01** challenge, so the configured HTTP listener
must be reachable from the internet on port 80.

- First start, certificate missing: uping binds the HTTP address itself for the
  length of the order, answers the token, then releases the port before Pingora
  starts. Nothing else may hold `:80` during that moment.
- Afterwards the ordinary HTTP listener answers
  `/.well-known/acme-challenge/<token>` and redirects everything else.
- Files: `{config dir}/cert/<domain>/fullchain.pem` and `privkey.pem` (key
  `0600`), atomically replaced. The account is
  `cert/acme-account-<hash>.json`, hashed by directory URL so production and
  staging do not collide.
- Renewal is checked hourly; a pair inside `renew_before_days` is reissued and
  swapped into the live SNI resolver. No restart, no dropped connection.
- `staging = true` uses Let's Encrypt staging. `directory` points at another
  ACME server; `ca_bundle` adds its PEM root (step-ca, an internal CA, or the
  test CA). Creating an account means accepting that CA's terms.
- Adding an `auto` domain in a reload requests its certificate in the
  background through the already-running HTTP listener.

Use `uping --check config.toml` first: it parses the whole load path, writes
nothing, contacts no CA, and reports how many certificates a start would
request. Do not point `auto` at a name that does not resolve to the host.

### Static files

`root` replaces `upstream`; both is an error. Requests are resolved under the
canonical root, so `..`, `%2e%2e` and a symlink pointing outside are refused. A
directory without its trailing slash gets `301`; `index` is served for a
directory. A missing file is `404` and never falls through to a proxy.

`GET` and `HEAD` are served; other methods get `405`. Bodies are streamed in
64 KiB chunks with `Content-Type` from the extension and
`X-Content-Type-Options: nosniff`. A zero-byte file terminates cleanly.

### Path routing

A route belongs to exactly one server. It is nested under that server — either
in the array form (`[[server.route]]`) or under the domain key in the map form
(`[[server."example.com".route]]`). There is no shared/global route table.

`[[server.route]]` serves one prefix of that domain; the server's own
`upstream`/`root` stays the catch-all.

- The longest matching prefix wins; prefixes match whole segments (`/mcp` covers
  `/mcp` and `/mcp/sse`, not `/mcpx`).
- `strip_prefix = true` removes the prefix before forwarding/resolving, keeping
  the query string.
- `path = "/"` is rejected: use the server's catch-all.

### Limits

| Setting | Where | Over budget |
|---|---|---|
| `per_ip_conns_per_sec` | TCP accept, pre-TLS | connection dropped |
| `per_ip_rps` | after HTTP parse | `429 Too Many Requests` |
| `max_body_bytes` | `Content-Length` + streamed body | `413 Payload Too Large` |

Both rate limiters use a fixed-size estimator table, so many source IPs cannot
grow memory without bound. Windows are one second and fixed: a client straddling
a boundary can briefly reach twice its budget. A reload changes the budget but
keeps the counters.

### Headers

Client headers are forwarded unchanged except hop-by-hop fields (RFC 9110,
including `Connection`-nominated fields); nominating `Host` or an
`X-Forwarded-*` field is rejected. The original `Host` is preserved. uping adds
`X-Forwarded-For` (appended to an existing chain), `X-Forwarded-Proto: https`
and `X-Forwarded-Host`. Response headers and body framing are streamed back
unchanged.

### Raw TCP forwarding — experimental

`[[stream]]` binds a port and copies bytes to one upstream — SMTP, IMAP, MySQL,
anything not HTTP. It is **experimental**: config and behaviour may change.

```toml
[[stream]]
name     = "smtp"
listen   = "0.0.0.0:25"
upstream = "127.0.0.1:10025"
connect_timeout_ms = 5000
```

One listener per entry; duplicate sockets are a config error. Half-close is
forwarded so the upstream can drain. There is no idle timeout (IMAP IDLE needs
long silence) and no TLS termination — terminate it in the upstream.

## Reloading

`systemctl --user reload uping` sends `SIGHUP`; uping re-reads the same config
and validates the whole path first.

Applied live:

- `[[server]]`, `[[server.route]]`, upstreams, static roots, indexes;
- `[limits]` budgets (counters are kept);
- `[tls] fallback_cert`;
- manual certificates already on disk, and existing `auto` ones;
- which domains each already-bound HTTPS listener may answer;
- a newly added `auto` domain is requested in the background through the
  running HTTP listener.

Requires a restart, reported as such in the log while the rest is applied:

- `[listen]`, `listen`/`listen6` (adding, removing or moving a socket) and
  `[[stream]]` — Pingora's listeners/forwarders are fixed;
- `[acme]` (email, staging, directory, `cert_dir`, renewal window) — the renewal
  thread owns them; mixing old and new would split where certificates are read
  and written.

A config that fails to load is logged (`reload failed, keeping the running
configuration`) and changes nothing. A reload never replaces the process; check
the PID stays the same.

Manual alternative:

```sh
kill -HUP "$(pgrep -u "$USER" -x uping)"
```

## Running it as a service

uping runs as an ordinary user. The only privileged thing is binding ports below
1024, one file capability — `CAP_NET_BIND_SERVICE` — not root.

```sh
cargo build --release
sudo setcap 'cap_net_bind_service=+ep' target/release/uping
mkdir -p ~/.config/systemd/user
cp uping.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now uping
loginctl enable-linger "$USER"        # start at boot, not only at login
```

`uping.service` assumes a source checkout at `~/uping` and
`~/uping/config.toml`; edit `WorkingDirectory`/`ExecStart` if yours differs.
Certificates and the ACME account live under `~/uping/cert/`, so no root-owned
directory is involved. The capability is on the binary and is **lost on every
rebuild**; re-apply `setcap` after `cargo build --release`.

The old installer and certbot hook were removed in v0.2.1: ACME renews
in-process. For `manual`, point `pub_key`/`priv_key` at any readable pair; a
certbot copy under the same tree is fine, but uping reloads it only on reload or
restart.

The planned apt layout — `/etc/uping/config.toml`, `/bin/uping`,
`/etc/uping/cert` — is for the future crates.io/apt release.

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

## Project layout

```
src/
  main.rs          # bootstrap, wiring, run, --check
  config.rs        # TOML schema, server forms, listener groups, validation
  reload.rs        # SIGHUP -> swap routes/certs/limits/domain sets
  tls.rs           # SNI resolver; renewals replace entries live
  acme.rs          # account, http-01 orders, storage, renewal thread
  static_files.rs  # safe path resolution + streamed files
  limits.rs        # per-IP rate + connection limiters
  proxy.rs         # HTTPS proxy, HTTP redirect + ACME challenge path
  stream.rs        # experimental raw TCP forwarder
tests/
  config_check.rs  # bad-config corpus and --check
  acme_e2e.rs      # fake ACME CA over TLS, real first start
  route_e2e.rs     # one route per domain
  listen_e2e.rs    # a per-server listener and its 421 isolation
  reload_e2e.rs    # SIGHUP, bad config, listener warning
  static_e2e.rs    # static serving through the real binary
  stream_e2e.rs    # raw TCP through the real binary
uping.service      # user unit
```

## Before you open a pull request

- `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test` are clean.
- New behaviour comes with a test; keep the diff scoped.
- Anything touching `[[stream]]` must keep it labelled experimental.
