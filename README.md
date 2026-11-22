# uping

A tiny, TOML-configured reverse proxy. Point a domain at a local service, let
uping obtain the certificate, done. It also serves a directory without a
backend, works over IPv4 and IPv6, and applies a new config on `SIGHUP` — no
restart for a config change.

## Status — v0.4.0

- ✅ HTTPS reverse proxy with SNI, one certificate per domain
- ✅ Let's Encrypt (`keys = "auto"`), and `keys = "internal"`: uping's own CA,
  no ACME server, no step-ca, Ed25519 by default
- ✅ Static files (`root`) and path routing (`routes = [...]`)
- ✅ One `[listen]` for the host, plus per-domain `https_listen` / `https_listen6`
- ✅ Private sites on a VPN address, `serve_http = false`, and `uping --dns-zone`
- ✅ ACME http-01 follows an explicit `https_listen` onto the same IP at `:80`
- ✅ HTTP → HTTPS redirect, per-IP connection limits, request/body caps
  overridable per domain
- ✅ Upstream health checks (`503` at once when a backend dies), per-domain
  intervals, and HTTPS to the backend with a private CA, SNI and verify opt-out
- ✅ Live config swap on `SIGHUP`
- ✅ `.deb` for Debian/Ubuntu: `dpkg -i` creates the user, a working default on
  loopback, `man uping`, and enables the service
- ⚠️ `[[stream]]` raw TCP forwarding is **experimental** — the mail/database
  relay. `routes` is HTTP path routing, not the mail feature.

Not here: changing listeners or `[[stream]]` without a restart, load balancing,
upstream mutual TLS, DNS-01, and wildcard SANs (SNI resolution is exact).

## Quick start

`config.toml` is local and git-ignored; [`config.toml.example`](config.toml.example)
is the tracked template. Copy it once, then edit the copy:

```toml
# config.toml
[acme]
email = "ops@rao-nagos.pf"

[[server]]
domain   = "www.rao-nagos.pf"
upstream = "127.0.0.1:8080"
```

```sh
cp config.toml.example config.toml
$EDITOR config.toml
```

The examples assume a checkout at `~/uping`, with `config.toml` at its root.
Certificates and the ACME account live under `~/uping/cert`.

## Build and run with setcap

uping runs as an ordinary user. The only privileged operation is binding ports
below 1024; a capability on the binary grants it:

```sh
cargo build --release
sudo setcap 'cap_net_bind_service=+ep' target/release/uping
./target/release/uping --check config.toml
./target/release/uping config.toml
```

The capability lives on the binary and is lost on every rebuild; re-apply
`setcap` after `cargo build --release`. The repository ships
[`uping.service`](uping.service), a user unit for this `~/uping` checkout; it
can order itself after `rupa.service` when both run in the same user manager.
For build/test notes, architecture and the release procedure, see
**[CONTRIBUTING.md](CONTRIBUTING.md)**.

Every path in `config.toml` is relative to the directory that holds it, here
`~/uping`. The default `cert_dir = "cert"` therefore writes:

```text
~/uping/cert/<domain>/fullchain.pem
~/uping/cert/<domain>/privkey.pem
~/uping/cert/acme-account-<hash>.json
```

The private key and ACME account are written `0600`; the chain is public and
written `0644`. Keep the config and certificate directory private:

```sh
chmod 600 config.toml
mkdir -p cert && chmod 700 cert
```

To apply an edited configuration without dropping connections:

```sh
pkill -HUP -x uping
```

The new file is validated first; an invalid file changes nothing. Changes to
`[listen]`, `https_listen`/`https_listen6`, `[[stream]]`, `[acme]` or
`[internal]` need a restart instead: restart it through your user service
manager.

To upgrade, rebuild and re-apply `setcap`; the configuration and `cert/` stay
in place.

`./target/release/uping --dns-zone config.toml` prints hosts records for a VPN
resolver.

## Debian package

The repository also builds a `.deb` for the system deployment, and installing
it is one command:

```sh
packaging/build-deb.sh                 # compiles in ubuntu:24.04, then cargo-deb
sudo dpkg -i target/debian/uping_*.deb
```

That is the whole install. The post-installation script creates the
unprivileged `uping` user and group, `/var/lib/uping`, a **working default**
`/etc/uping/config.toml` (loopback only, a static page on
`https://localhost:8443` signed by uping's own CA), installs `man uping`, and
enables and starts `uping.service`. Nothing has to be created by hand.

```sh
man uping
systemctl status uping
sudo curl --cacert /var/lib/uping/internal/ca/root.crt https://localhost:8443/
```

Point it at your domains when you are ready:

```sh
sudo editor /etc/uping/config.toml
sudo -u uping /usr/bin/uping --check /etc/uping/config.toml
sudo systemctl restart uping
```

The package never overwrites a `/etc/uping/config.toml` that is already there:
the default is written only when the file is absent, on install and on upgrade.
`/var/lib/uping` holds the local CA and the leaves, and `apt purge` keeps both
it and `/etc/uping` on purpose, because deleting the CA would silently untrust
every client.

The container in `build-deb.sh` is what makes the binary portable: it compiles
in the release's glibc (Ubuntu 24.04), and `packaging/build-deb.sh debian:12`
builds against an older baseline.

| Path | Contents |
|---|---|
| `/usr/bin/uping` | the binary |
| `/usr/lib/systemd/system/uping.service` | unit, ambient capability, no `setcap` |
| `/usr/lib/tmpfiles.d/uping.conf` | creates `/var/lib/uping` |
| `/usr/share/man/man8/uping.8` | `man uping` |
| `/usr/share/uping/` | default and example config, static landing page |
| `/usr/share/doc/uping/` | README, README.Debian, copyright |
| `/etc/uping/config.toml` | your configuration |
| `/var/lib/uping/` | CA, leaves, writable state |

## Paths

Every path in the file is resolved from the directory that holds `config.toml`.
With the checkout layout that directory is `~/uping`. An absolute path is used
exactly as written:

```toml
root      = "/srv/www"                             # absolute
root      = "public"                               # ~/uping/public
cert_dir  = "cert"                                 # ~/uping/cert
pub_key   = "cert/www.rao-nagos.pf/fullchain.pem"  # ~/uping/cert/...
```

This applies to `root`, `pub_key`, `priv_key`, `cert_dir`, `upstream_ca` and
`[acme] ca_bundle`. `index` is a plain file name, not a path.

## What each table does

All tables and fields are optional unless marked required. Defaults are shown.

### `[listen]` — host-wide sockets

| Field | Default | Meaning |
|---|---|---|
| `ipv4` | `"0.0.0.0"` | The IPv4 address to bind |
| `ipv6` | omitted | One IPv6 address; omitted means no IPv6 listener |
| `http` | `80` | HTTP port (redirect + ACME http-01) |
| `https` | `443` | Default HTTPS port |

```toml
[listen]
ipv4  = "203.0.113.10"
ipv6  = "2607:f1c0:f031:4500::1"
http  = 80
https = 443
```

`ipv6` is written bare (no brackets, no port). `ipv6 = ""` is an error; omit it
to disable IPv6. A server can override its HTTPS socket with `https_listen` /
`https_listen6`; HTTP stays host-wide because it is where ACME http-01 answers
and where the redirect lives.

For an ACME server with an explicit `https_listen` / `https_listen6`, uping
also binds the same IP on `[listen] http`. A private site on `10.8.0.1:443`
therefore gets `10.8.0.1:80` automatically for http-01. A derived socket already
covered by a wildcard or the same address is not added twice.

### `[limits]` — abuse protection

| Field | Default | Over budget |
|---|---|---|
| `per_ip_rps` | `300` | `429 Too Many Requests` |
| `per_ip_conns_per_sec` | `100` | connection dropped before TLS |
| `max_body_bytes` | `10485760` (10 MiB) | `413 Payload Too Large` |

`0` disables a limit (or makes `max_body_bytes` unlimited). Windows are one
second and fixed. A server can override the per-domain limits:

```toml
[[server]]
domain = "api.rao-nagos.pf"
upstream = "127.0.0.1:9000"
limits = { per_ip_rps = 1220, max_body_bytes = 0 }
```

`per_ip_conns_per_sec` stays in `[limits]`: it runs at TCP accept, before the
`Host` header exists, so it cannot be attributed to a domain. Setting it in a
server table is a config error, not silently ignored.

### `[health]` — upstream liveness

| Field | Default | Meaning |
|---|---|---|
| `interval_ms` | `5000` | Probe period; `0` disables the active probe |
| `timeout_ms` | `2000` | TCP/TLS connect timeout |
| `failures` | `2` | Consecutive failures before a backend is down |

A down backend is answered with `503` immediately. With `interval_ms = 0` there
is no active probe, but the address is still resolved (and refreshed every
minute); an unresolvable backend still gets `503`.

A server can override the table, and a route inherits then overrides it again:

```toml
[[server]]
domain = "slow.rao-nagos.pf"
upstream = "127.0.0.1:8080"
health = { interval_ms = 10000, timeout_ms = 1500, failures = 3 }

[[server]]
domain = "no-503.rao-nagos.pf"
upstream = "127.0.0.1:8081"
health = false          # resolve, but never preemptively answer 503
```

Omitted fields keep the inherited value. A settings table re-enables the gate.

### `[tls]` — listener-wide TLS behaviour

| Field | Default | Meaning |
|---|---|---|
| `fallback_cert` | `true` | Use the first certificate when SNI is absent or unknown |

```toml
[tls]
fallback_cert = true
```

When a client opens TLS, it sends an SNI hostname (the site it wants). If SNI
is absent (old client, raw-IP scanner) or unknown, there is no domain to choose
a certificate for. `fallback_cert = true` presents the first configured
server's certificate so the handshake completes; the HTTP layer then answers
404/421. It does **not** make that certificate valid for the unknown name: a
client that verifies the hostname still rejects it. `fallback_cert = false`
fails the handshake instead. The setting is listener-wide because the decision
happens before any domain exists.

### `[acme]` — public ACME / Let's Encrypt

| Field | Default | Meaning |
|---|---|---|
| `email` | `""` | Contact address; empty means no expiry warning |
| `staging` | `false` | Use Let's Encrypt staging (untrusted test certs) |
| `directory` | `""` | Custom ACME directory; empty means Let's Encrypt |
| `ca_bundle` | `""` | PEM root for the ACME server; empty means system roots |
| `cert_dir` | `"cert"` | `<cert_dir>/<domain>/{fullchain,privkey}.pem` |
| `renew_before_days` | `30` | Renewal window, clamped to `1..=89` |

`keys = "auto"` uses this profile. It uses **http-01**, so the domain must
resolve publicly and port 80 must be reachable by the CA.

A failed order never stops uping. DNS not ready, port 80 unreachable, or a CA
rate limit is logged, the other domains are still tried, and the process starts
with the certificates it already has. Those missing domains fail the TLS
handshake until a retry succeeds; the HTTP listener stays up to answer the next
challenge. A failed startup order is retried after one hour (not seconds), so a
rejection cannot turn into a restart loop that burns the CA's
failed-authorization budget.

### `[internal]` — uping's own CA

`keys = "internal"` no longer depends on any CA server. On first start uping
generates a root pair under `ca_dir` and signs each domain's leaf itself; a leaf
is renewed locally before it expires and swapped into the live listener without
a restart. Nothing is fetched, so there is no http-01, no port 80 and no
requirement that the CA resolve or reach the host.

| Field | Default | Meaning |
|---|---|---|
| `ca_dir` | `"cert/internal/ca"` | `root.crt` (0644) + `root.key` (0600) |
| `cert_dir` | `"cert/internal"` | `<cert_dir>/<domain>/{fullchain,privkey}.pem` |
| `common_name` | `"uping local CA"` | root subject CN; not a hostname |
| `organization` | `"uping"` | root subject O |
| `ca_days` | `3650` | root lifetime, clamped to `leaf_days..=7300` |
| `leaf_days` | `397` | leaf lifetime, clamped to `1..=825` |
| `renew_before_days` | `30` | renew a leaf with fewer days left |
| `key_type` | `"ed25519"` | `ed25519`, `p256` or `rsa2048` |
| `serve_root` | `""` | plain HTTP address that publishes `/root.crt`; empty means off |

The files use the ACME names, in their own subtree, so nothing an ACME run
already wrote is read or overwritten:

```text
~/uping/cert/internal/ca/root.crt                       0644  <- install on clients
~/uping/cert/internal/ca/root.key                       0600
~/uping/cert/internal/app.vpn.rao-nagos.pf/fullchain.pem
~/uping/cert/internal/app.vpn.rao-nagos.pf/privkey.pem  0600
```

The root is created once and never regenerated behind your back. If only one of
`root.crt` / `root.key` survives, startup logs the pair as inconsistent and
skips those domains, rather than minting a root every client would reject
(remove both files to deliberately create a new CA). `alt_names = [...]` on a
server adds SANs to the same leaf.

#### How the certificates are made

No external tool, no daemon, no package to install. uping calls the **OpenSSL
library it already links for TLS**, through the `openssl` Rust crate: the same
process generates the key pair (`PKey::generate_ed25519`, or EC/RSA according to
`key_type`), builds the X.509 structures (subject, SANs, basic constraints, key
usage, `serverAuth` EKU), signs them and writes the PEM files. Nothing is
shelled out — there is no call to the `openssl` command, to `step`, to `certbot`
or to any CA.

The released binary carries OpenSSL statically: `pingora-openssl` enables
`openssl/vendored`, so libcrypto is compiled into the executable (the Linux
build reports OpenSSL 3.6.3 and `ldd` shows no `libssl`). Installing uping is
still one binary and one config file; building it needs a C toolchain, CMake
and Perl for that vendored OpenSSL build, but no system `libssl-dev` and no
step-ca.

On each client, once:

```sh
curl -o /usr/local/share/ca-certificates/uping-local-ca.crt \
  http://10.8.0.1:9000/root.crt
sudo update-ca-certificates
```

`serve_root` publishes that one file over plain HTTP on the address you name —
typically the rupa VPN address. It is best-effort: an address that does not
exist yet (the tunnel is not up) is logged and skipped, and every other listener
keeps running.

The check the old `[acme.internal]` profile could not avoid still exists: the
**client** has to install the root once. What disappears is the second daemon —
no step-ca, no account, no ACME directory, no port 80.

## `[[server]]` — every shape

`[[server]]` is the only server form.

### 1. Minimal reverse proxy

```toml
[[server]]
domain   = "www.rao-nagos.pf"
upstream = "127.0.0.1:8080"
```

`keys` is inferred: no key paths → `auto`; both `pub_key` and `priv_key` →
`manual`.

### 2. Static site

```toml
[[server]]
domain = "static.rao-nagos.pf"
root   = "public"            # absolute or relative to config.toml
index  = "index.html"        # default
```

Exactly one of `upstream` and `root` must be set.

### 3. Several backends for one domain

```toml
[[server]]
domain   = "www.rao-nagos.pf"
upstream = "127.0.0.1:8080"  # catch-all
routes = [
  { path = "/mcp", upstream = "127.0.0.1:8081" },
  { path = "/assets", root = "public/assets", strip_prefix = true },
]
```

- The longest matching prefix wins; prefixes match whole segments (`/mcp`
  covers `/mcp` and `/mcp/sse`, not `/mcpx`).
- `strip_prefix = true` removes the prefix before forwarding or resolving. With
  `root = "public/assets"` and `path = "/assets"`, `/assets/app.css` becomes
  `public/assets/app.css`. Without it, the same request would look for
  `public/assets/assets/app.css`.
- The query string is kept; `/assets` becomes `/`.
- `path = "/"` is rejected: use the server's catch-all.

`routes` is the **only** route form: an array of inline tables.

### 4. Own HTTPS listener

```toml
[[server]]
domain        = "app.rao-nagos.pf"
upstream      = "127.0.0.1:8080"
https_listen  = "203.0.113.10"          # IPv4, default port = [listen] https
https_listen6 = "[2001:db8::10]:8443"   # IPv6 with an explicit port
```

The IPv6 address with a port must be bracketed. Overriding one family does not
imply the other. Each distinct combination becomes its own HTTPS listener; the
domain is not answered on the other listeners (`421 Misdirected Request`).
`[listen] http` is not per-server.

### 5. No HTTP vhost

```toml
[[server]]
domain     = "private.rao-nagos.pf"
keys       = "manual"
pub_key    = "cert/private.rao-nagos.pf/fullchain.pem"
priv_key   = "cert/private.rao-nagos.pf/privkey.pem"
upstream   = "127.0.0.1:8080"
serve_http = false
```

`serve_http = false` removes the domain from port 80: a request for it there is
`404`, not a redirect. It is refused with an ACME mode because http-01 needs
port 80; use `keys = "internal"` (uping's own CA) or `keys = "manual"` with an
externally issued pair.

### 6. HTTPS to the backend

```toml
[[server]]
domain          = "www.rao-nagos.pf"
upstream        = "10.0.0.5:8443"
upstream_tls    = true
upstream_sni    = "app.internal"          # default: upstream host, or the domain for an IP
upstream_ca     = "certs/internal-ca.pem" # replaces the system roots
upstream_verify = true                    # false accepts any cert: private nets only
```

`upstream_ca` is the trust anchor for the **backend**; it is unrelated to
`[acme] ca_bundle`. The same fields are available on a route.

### 7. Per-domain limits and health

```toml
[[server]]
domain   = "api.rao-nagos.pf"
upstream = "127.0.0.1:9000"
limits   = { per_ip_rps = 1220, max_body_bytes = 0 }
health   = { interval_ms = 10000, failures = 3 }
```

### 8. Manual certificates

```toml
[[server]]
domain   = "manual.rao-nagos.pf"
keys     = "manual"
pub_key  = "cert/manual.rao-nagos.pf/fullchain.pem"
priv_key = "cert/manual.rao-nagos.pf/privkey.pem"
upstream = "127.0.0.1:8080"
```

Both paths are required. uping reads them at startup and on `SIGHUP`; renew
them yourself (certbot, an ACME client, a paid CA, …) and send `SIGHUP`.

### 9. Private site with the local CA

```toml
[internal]
serve_root = "10.8.0.1:9000"   # optional: publish /root.crt over plain HTTP

[[server]]
domain       = "site1.internal.rao-nagos.pf"
keys         = "internal"
alt_names    = ["vpn.rao-nagos.pf"]
upstream     = "127.0.0.1:8080"
https_listen = "10.8.0.1"      # the rupa VPN address
serve_http   = false           # no :80 at all, and no http-01 to answer
```

This is automatic leaf issuance and renewal with no CA server on the network.
The **client** trusts the root once (fetch it from `serve_root`, or copy
`cert/internal/ca/root.crt`); the leaves rotate underneath that trust. The name
may exist only in your internal DNS. See [Private names, rupa and
DNS](#private-names-rupa-and-dns).

### 10. Explicit `keys = "auto"`

```toml
[[server]]
domain   = "www.rao-nagos.pf"
keys     = "auto"
upstream = "127.0.0.1:8080"
```

`auto` is already the default without key paths. `pub_key` / `priv_key` may
optionally override where the pair is written.

### Server, route and stream defaults

| `[[server]]` field | Default |
|---|---|
| `domain` | required |
| `keys` | `auto` without key paths; `manual` with both; `internal` for a local leaf |
| `pub_key`, `priv_key` | `""` (manual requires both; refused with `internal`) |
| `alt_names` | `[]` (extra SANs, `internal` only) |
| `upstream`, `root` | `""` (exactly one required) |
| `https_listen`, `https_listen6` | `""` (use the global HTTPS group) |
| `serve_http` | `true` |
| `health` | `true` |
| `limits` | none (inherit `[limits]`) |
| `index` | `"index.html"` |
| `routes` | `[]` |
| `upstream_tls` | `false` |
| `upstream_sni` | `""` |
| `upstream_verify` | `true` |
| `upstream_ca` | `""` |

| `routes` entry | Default |
|---|---|
| `path` | required |
| `upstream`, `root` | `""` (exactly one required) |
| `health` | inherits the server |
| `index` | `"index.html"` |
| `strip_prefix` | `false` |
| `upstream_tls` | `false` |
| `upstream_sni` | `""` |
| `upstream_verify` | `true` |
| `upstream_ca` | `""` |

| `[[stream]]` field | Default |
|---|---|
| `name` | `""` (label falls back to `listen`) |
| `listen`, `upstream` | required |
| `connect_timeout_ms` | `5000`, clamped to `100..=30000` |

## `[[stream]]` — experimental raw TCP

```toml
[[stream]]
name     = "smtp"
listen   = "0.0.0.0:25"
upstream = "127.0.0.1:10025"
connect_timeout_ms = 5000   # default 5000, clamped 100..30000
```

One listener per entry; duplicate sockets are a config error. Half-close is
forwarded. There is no idle timeout and no TLS termination — terminate it in
the upstream.

## Private names, rupa and DNS

A VPS that also runs rupa can host services that exist only inside the tunnel.
uping does **not** serve DNS; the rupa-side resolver owns that. It renders the
records its config already knows:

```sh
uping --dns-zone config.toml
# uping --dns-zone: one record per configured domain and family.
# 10.8.0.1 site1.internal.rao-nagos.pf
```

- The address comes from the site's `https_listen` / `https_listen6`, or from
  `[listen] ipv4` / `ipv6` when there is no override.
- A wildcard (`0.0.0.0`, `::`) is refused: a DNS record must name a real
  address. Set a concrete `https_listen` (the rupa VPN address).
- Load it with dnsmasq `addn-hosts=`, CoreDNS `hosts`, or `/etc/hosts`.
  Do **not** use `local=/rao-nagos.pf/` for a subdomain of a public zone; that
  would capture the whole public zone. `addn-hosts=` alone is enough, or
  `local=/internal.rao-nagos.pf/` if you are authoritative for that subdomain.
- Clients set their DNS to the rupa resolver.

### Trust model for private names

`keys = "internal"` means "uping signs this name itself", not "this private name
becomes publicly trusted". The possible combinations are:

| Goal | Public DNS | Root on clients | uping |
|---|---|---|---|
| Public name, public trust | A record + port 80 | no (public root) | `keys = "auto"` |
| Public name, DNS-01 | TXT record; A may be private | no | not implemented; external ACME client + `keys = "manual"` |
| Private name, automatic leaf | no (internal DNS) | **yes** (`root.crt`) | `keys = "internal"` |
| Fully manual | no | yes | `keys = "manual"` |

A publicly trusted root will not sign `.internal`, `.localhost`, unqualified
names or private IPs. A public CA only signs names it can validate publicly.
There is no setup that gives public trust + private DNS + zero client
installation.

For `keys = "internal"`:

1. Let uping create `cert/internal/ca/root.crt` on first start.
2. Publish it with `serve_root = "10.8.0.1:9000"`, or copy the file out of band.
3. Install that root once on each client.
4. Add one `[[server]]` per name with `keys = "internal"`; one root covers all of
   them, and each leaf renews automatically.

The certificate is for the **name**, not the IP. The A record may point to
`10.8.0.1`; the client resolves the name, connects to the private IP, and
trusts the leaf because it trusts uping's root. No IP SAN is needed.

`.localhost` is special and not suitable for remote clients. A subdomain you own,
such as `site1.internal.rao-nagos.pf` or `vpn.rao-nagos.pf`, is the least
surprising choice. `alt_names` lets one leaf cover the bare and the `www` name;
a wildcard SAN is refused because SNI resolution is an exact match.

## `uping --dns-zone`

`--dns-zone` never writes DNS. It prints `hosts(5)` records — one line per
configured domain and family — for dnsmasq, CoreDNS or `/etc/hosts`:

```sh
./target/release/uping --dns-zone config.toml | sudo tee /etc/dnsmasq.d/uping.hosts
# dnsmasq.conf: addn-hosts=/etc/dnsmasq.d/uping.hosts
#                interface=<rupa-interface>
#                bind-interfaces
```

On the client, `DNS = 10.8.0.1` in the rupa config. Public names keep resolving
through the forwarder; your internal names only exist in the tunnel.

## License

Apache-2.0 — see [LICENSE](LICENSE).
