# uping

A tiny, TOML-configured reverse proxy for the 90% of cases where nginx is
overkill. Built on Cloudflare's [Pingora](https://github.com/cloudflare/pingora).

Point a domain at a local service, let uping obtain the certificate, done. It
also serves a directory without a backend, works over IPv4 and IPv6, and
reloads its config with `systemctl --user reload` — no restart for a config
change.

## Status — v0.3.0

- ✅ HTTPS reverse proxy with SNI, one certificate per domain
- ✅ Let's Encrypt (`keys = "auto"`) and private ACME CAs, including step-ca
  (`keys = "internal"`)
- ✅ Static files (`root`) and path routing (`routes = [...]`)
- ✅ One `[listen]` for the host, plus per-domain `https_listen` / `https_listen6`
- ✅ Private sites on a VPN address, `serve_http = false`, and `uping --dns-zone`
- ✅ HTTP → HTTPS redirect, per-IP connection limits, request/body caps
  overridable per domain
- ✅ Upstream health checks (`503` at once when a backend dies), per-domain
  intervals, and HTTPS to the backend with a private CA, SNI and verify opt-out
- ✅ Live config reload on `SIGHUP`
- ⚠️ `[[stream]]` raw TCP forwarding is **experimental** — the mail/database
  relay. `routes` is HTTP path routing, not the mail feature.

Not here: hot-reload of listeners or `[[stream]]`, load balancing, upstream
mutual TLS, DNS-01.

## Quick start

```toml
# config.toml
[acme]
email = "ops@example.com"

[[server]]
domain   = "www.example.com"
upstream = "127.0.0.1:8080"
```

```sh
cargo build --release
sudo setcap 'cap_net_bind_service=+ep' target/release/uping
./target/release/uping --check config.toml   # validate, bind nothing
./target/release/uping config.toml
./target/release/uping --dns-zone config.toml  # hosts records for a VPN resolver
```

For the systemd user unit, build/test notes, architecture and release
procedure, see **[CONTRIBUTING.md](CONTRIBUTING.md)**.

## Paths

Every path in the file is resolved from the directory that holds `config.toml`.
An absolute path is used exactly as written:

```toml
root      = "/srv/www"                 # absolute
root      = "public"                   # <config dir>/public
cert_dir  = "/etc/uping/cert"          # absolute
pub_key   = "cert/app/fullchain.pem"   # <config dir>/cert/app/fullchain.pem
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
domain = "api.example.com"
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
domain = "slow.example.com"
upstream = "127.0.0.1:8080"
health = { interval_ms = 10000, timeout_ms = 1500, failures = 3 }

[[server]]
domain = "no-503.example.com"
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

### `[acme.internal]` — private ACME CA (step-ca)

```toml
[acme.internal]                    # [acme.step-ca] is an accepted alias
directory = "https://step-ca.internal/acme/acme/directory"
ca_bundle = "/etc/uping/cert/step-ca-root.pem"
```

| Field | Default | Meaning |
|---|---|---|
| `directory` | required | The provisioner's ACME directory URL |
| `ca_bundle` | inherits `[acme] ca_bundle` | PEM root that signs the ACME server |

`keys = "internal"` (alias `"step-ca"`) selects this profile. It still uses
**http-01**: the private CA must reach the domain on port 80, and
`serve_http = true` is required. `staging` does not apply to this profile.
Accounts are stored per directory URL, so public and private CAs never share
one.

**Important:** `ca_bundle` is the trust anchor for uping → ACME server. It is
**not** pushed to clients. Clients must trust the private CA root themselves
(install the same root once in the OS/browser/MDM). Without that, the issued
certificate is not trusted, no matter what uping does.

## `[[server]]` — every shape

`[[server]]` is the only server form. The `[server."domain"]` map form was
removed; it now fails with an error that says to use `[[server]]` + `domain`.

### 1. Minimal reverse proxy

```toml
[[server]]
domain   = "www.example.com"
upstream = "127.0.0.1:8080"
```

`keys` is inferred: no key paths → `auto`; both `pub_key` and `priv_key` →
`manual`.

### 2. Static site

```toml
[[server]]
domain = "static.example.com"
root   = "public"            # absolute or relative to config.toml
index  = "index.html"        # default
```

Exactly one of `upstream` and `root` must be set.

### 3. Several backends for one domain

```toml
[[server]]
domain   = "www.example.com"
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

`routes` is the **only** route form: an array of inline tables. The old
`[[server.route]]` and `[[server."domain".route]]` forms are gone.

### 4. Own HTTPS listener

```toml
[[server]]
domain        = "app.example.com"
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
domain     = "private.example.com"
keys       = "manual"
pub_key    = "cert/private.example.com/fullchain.pem"
priv_key   = "cert/private.example.com/privkey.pem"
upstream   = "127.0.0.1:8080"
serve_http = false
```

`serve_http = false` removes the domain from port 80: a request for it there is
`404`, not a redirect. It is refused with any ACME mode because http-01 needs
port 80; use `keys = "manual"` (or a private ACME CA that can reach :80).

### 6. HTTPS to the backend

```toml
[[server]]
domain          = "www.example.com"
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
domain   = "api.example.com"
upstream = "127.0.0.1:9000"
limits   = { per_ip_rps = 1220, max_body_bytes = 0 }
health   = { interval_ms = 10000, failures = 3 }
```

### 8. Manual certificates

```toml
[[server]]
domain   = "manual.example.com"
keys     = "manual"
pub_key  = "cert/manual.example.com/fullchain.pem"
priv_key = "cert/manual.example.com/privkey.pem"
upstream = "127.0.0.1:8080"
```

Both paths are required. uping reads them at startup and on reload; renew them
yourself (certbot, step-ca, a paid CA, …) and reload.

### 9. Private site with step-ca

```toml
[acme.internal]
directory = "https://step-ca.internal/acme/acme/directory"
ca_bundle = "/etc/uping/cert/step-ca-root.pem"

[[server]]
domain       = "site1.internal.rao-nagos.pf"
keys         = "internal"
upstream     = "127.0.0.1:8080"
https_listen = "10.8.0.1"       # wg0
# serve_http = true (default): step-ca validates via http-01
```

This is automatic leaf issuance and renewal, but the **client** must trust the
step-ca root. You install that root once per client; you do not install each
leaf. The private CA can validate a name that only exists in your internal DNS:
no public zone change is required, provided step-ca can resolve the name and
reach the host on port 80. See [Private names, WireGuard and
DNS](#private-names-wireguard-and-dns).

### 10. Explicit `keys = "auto"`

```toml
[[server]]
domain   = "www.example.com"
keys     = "auto"
upstream = "127.0.0.1:8080"
```

`auto` is already the default without key paths. `pub_key` / `priv_key` may
optionally override where the pair is written.

### The map form was removed

```toml
# No longer accepted:
# [server."legacy.example.com"]
# upstream = "127.0.0.1:8080"

# Write this instead:
[[server]]
domain   = "legacy.example.com"
upstream = "127.0.0.1:8080"
```

### Server, route and stream defaults

| `[[server]]` field | Default |
|---|---|
| `domain` | required |
| `keys` | `auto` without key paths; `manual` with both |
| `pub_key`, `priv_key` | `""` (manual requires both) |
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

## Private names, WireGuard and DNS

A VPS that also runs WireGuard can host services that exist only inside the
tunnel. uping does **not** serve DNS; the WireGuard-side resolver owns that. It
renders the records its config already knows:

```sh
uping --dns-zone config.toml
# uping --dns-zone: one record per configured domain and family.
# 10.8.0.1 site1.internal.rao-nagos.pf
```

- The address comes from the site's `https_listen` / `https_listen6`, or from
  `[listen] ipv4` / `ipv6` when there is no override.
- A wildcard (`0.0.0.0`, `::`) is refused: a DNS record must name a real
  address. Set a concrete `https_listen` (the `wg0` address).
- Load it with dnsmasq `addn-hosts=`, CoreDNS `hosts`, or `/etc/hosts`.
  Do **not** use `local=/rao-nagos.pf/` for a subdomain of a public zone; that
  would capture the whole public zone. `addn-hosts=` alone is enough, or
  `local=/internal.rao-nagos.pf/` if you are authoritative for that subdomain.
- Clients set their DNS to the WireGuard resolver.

### Trust model for private names

`keys = "internal"` means "use this private ACME CA", not "make a private name
publicly trusted". The possible combinations are:

| Goal | Public DNS | Root on clients | uping |
|---|---|---|---|
| Public name, public trust | A record + port 80 | no (public root) | `keys = "auto"` |
| Public name, DNS-01 | TXT record; A may be private | no | not implemented; external ACME client + `keys = "manual"` |
| Private name, automatic leaf | no (internal DNS) | **yes** (step-ca root) | `keys = "internal"` |
| Fully manual | no | yes | `keys = "manual"` |

A publicly trusted root will not sign `.internal`, `.localhost`, unqualified
names or private IPs. A public CA only signs names it can validate publicly.
There is no setup that gives public trust + private DNS + zero client
installation.

For step-ca:

1. Run step-ca on (or reachable from) the WireGuard network, with a root CA.
2. Configure its ACME provisioner and its DNS so it resolves the private names
   (the internal resolver, or `/etc/hosts`).
3. Keep `serve_http = true` so http-01 can answer on port 80.
4. Install the step-ca **root** once on each client.
5. Add one `[[server]]` per name with `keys = "internal"`; one root covers all
   of them, and each leaf renews automatically.

The certificate is for the **name**, not the IP. The A record may point to
`10.8.0.1`; the client resolves the name, connects to the private IP, and
trusts the leaf because it trusts the step-ca root. No IP SAN is needed.

`.localhost` is special and not suitable for remote clients. `.internal` works
if the private CA's policy allows it. A subdomain you own, such as
`site1.internal.rao-nagos.pf` or `vpn.rao-nagos.pf`, is the least surprising
choice.

## `uping --dns-zone`

`--dns-zone` never writes DNS. It prints `hosts(5)` records — one line per
configured domain and family — for dnsmasq, CoreDNS or `/etc/hosts`:

```sh
uping --dns-zone config.toml > /etc/dnsmasq.d/uping.hosts
# dnsmasq.conf: addn-hosts=/etc/dnsmasq.d/uping.hosts
#                interface=wg0
#                bind-interfaces
```

On the client, `DNS = 10.8.0.1` in the WireGuard config. Public names keep
resolving through the forwarder; your internal names only exist in the tunnel.

## Reload or restart

```sh
systemctl --user reload uping     # SIGHUP: config changes, no dropped conn
systemctl --user restart uping    # a new binary, or a listener/[[stream]] change
```

A reload applies `[[server]]`, `routes`, upstreams, static roots, indexes,
limits, health settings, `[tls] fallback_cert`, manual certificates and the
domain sets of already-bound listeners. A bad config changes nothing. Changing
`[listen]`, `https_listen`/`https_listen6`, `[[stream]]`, `[acme]` or
`[acme.internal]` requires a restart.

## Running it as a service

uping runs as an ordinary user. The only privileged thing is binding ports
below 1024 — `CAP_NET_BIND_SERVICE`, not root:

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

## License

Apache-2.0 — see [LICENSE](LICENSE).
