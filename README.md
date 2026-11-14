# uping

A tiny, TOML-configured reverse proxy for the 90% of cases where nginx is
overkill. Built on Cloudflare's [Pingora](https://github.com/cloudflare/pingora).

Point a domain at a local service, let uping obtain the certificate, done. Plain
HTTP is automatically redirected to HTTPS, static directories can be served
without a backend, IPv6 is a flag away, and clients that misbehave are capped.

## Status — v0.2.1

- ✅ Reverse proxy: `domain` → `upstream` over HTTPS (TLS termination)
- ✅ **Automatic certificates** (`keys = "auto"`): Let's Encrypt via ACME
  http-01, first issuance and renewal, without certbot
- ✅ **Static files** (`root = "…"`): per domain or per path prefix
- ✅ **IPv6**: a literal listener address, or `[listen] ipv6 = true` for the
  common wildcard case
- ✅ **Automatic HTTP → HTTPS redirect** (301), while still answering the ACME
  challenge path in the clear
- ✅ TLS with **SNI**: one listener, one cert per domain
- ✅ **Path routing** (`[[server.route]]`, `[[route]]`)
- ✅ **Abuse protection**: per-IP connection rate, per-IP request rate, request
  body cap
- ✅ **Forwarded headers**: `X-Forwarded-For` / `-Proto` / `-Host`
- ⚠️ **Experimental: raw TCP forwarding** (`[[stream]]`) — the mail/database
  relay. See below; its config and behaviour may still change.
- ✅ Simple flat TOML config

Deliberately *not* here (candidates for later): config hot-reload, load
balancing, health checks, upstream TLS.

### What changed in v0.2.1

- **`keys = "auto"`** obtains and renews a certificate with ACME http-01.
  Certificates live under `{config dir}/cert/<domain>/`, the ACME account beside
  them. Renewal is checked hourly and swapped into the running listener; no
  restart. `keys = "manual"` keeps the two-file behaviour.
- **`root`** on a `[[server]]` or a route serves static files instead of
  proxying. Traversal and symlink escapes are refused, MIME types are set, and
  directory requests get their trailing slash.
- **IPv6** listeners: write `"[::]:443"`, or set `[listen] ipv6 = true` to turn
  `0.0.0.0` into the dual-stack `[::]`.
- **`deploy/` is gone.** The installer and the certbot hook belonged to the
  root-owned `/etc/uping` layout; uping now runs as an ordinary user with
  `CAP_NET_BIND_SERVICE` and a user systemd unit. `uping.service` is at the
  repository root. The apt layout (`/etc/uping/config.toml`, `/bin/uping`,
  `/etc/uping/cert`) is planned for the crates.io/apt release.
- **`[[stream]]` is marked experimental.**

## Config

```toml
# Optional. Defaults to 0.0.0.0:80 / 0.0.0.0:443.
# An IPv6 literal works directly: https = "[::]:443".
# ipv6 = true turns the wildcard into the dual-stack [::]:port, and adds
# [::1]:port beside a 127.0.0.1 listener.
# [listen]
# http  = "0.0.0.0:80"
# https = "0.0.0.0:443"
# ipv6  = false

# Optional. Let's Encrypt, used by keys = "auto".
# [acme]
# email             = "ops@example.com"   # optional, but you lose expiry warnings
# staging           = false               # staging certs are not trusted by browsers
# cert_dir          = "cert"              # relative to config.toml, or absolute
# renew_before_days = 30                  # clamped to 1..=89
# directory         = ""                  # custom ACME directory URL
# ca_bundle         = ""                  # PEM root for a private ACME CA

# Optional. Abuse protection. Any limit set to 0 is switched off.
# [limits]
# per_ip_rps          = 300        # requests/sec per IP, then 429
# per_ip_conns_per_sec = 100       # new TCP conns/sec per IP, then dropped
# max_body_bytes      = 10485760   # 10 MiB, then 413

# Optional. TLS behaviour.
# [tls]
# fallback_cert = true

[[server]]
domain   = "www.example.com"
keys     = "auto"                 # the default when no key paths are given
upstream = "127.0.0.1:8080"

# A static site, no backend at all.
[[server]]
domain = "static.example.com"
root   = "public"                 # relative to config.toml
index  = "index.html"             # the default

# Optional. How one path prefix is served; the longest prefix wins.
# [[server.route]]
# path     = "/api"
# upstream = "127.0.0.1:8081"
#
# [[server.route]]
# path         = "/assets"
# root         = "public/assets"
# strip_prefix = true             # /assets/app.css -> public/assets/app.css
```

`config.toml` in the current directory is the built-in default; pass another
path as the first argument to override it. Every relative path in the file is
resolved from the directory that holds it — not from the current directory.

### Certificate modes

| `keys` | Meaning |
|--------|---------|
| omitted, no `pub_key`/`priv_key` | **`auto`** — obtain and renew through ACME |
| omitted, both key paths given | **`manual`** — read the two PEM files, renew them yourself |
| `"auto"` | ACME; `pub_key`/`priv_key` optionally override *where* the pair is written |
| `"manual"` | The two PEM files are required; uping never writes them |

A `manual` pair is read once at startup; restart to pick up a renewed file. An
`auto` renewal is loaded into the live SNI resolver immediately.

### Let's Encrypt

`keys = "auto"` uses the ACME **http-01** challenge, which means the CA must
reach the configured HTTP listener from the internet on port 80:

- On the first start, if the certificate does not exist yet, uping binds the
  HTTP address itself for the length of the order, answers the token, then
  releases the port before Pingora starts. Nothing else may hold `:80` during
  that moment.
- After startup, the ordinary HTTP listener answers
  `/.well-known/acme-challenge/<token>` in the clear and redirects everything
  else to HTTPS.
- Certificates are written atomically to
  `{config dir}/cert/<domain>/{fullchain,privkey}.pem` (`privkey` is `0600`).
- The account credentials live beside them as
  `cert/acme-account-<hash>.json`, hashed by directory URL so production and
  staging never mix.
- Renewal is checked once an hour and reissues when fewer than
  `renew_before_days` remain. The new pair is swapped into the running listener;
  there is no restart and no dropped connection.
- `staging = true` uses Let's Encrypt staging. `directory` points at another
  ACME server; `ca_bundle` adds the PEM root that signs it (step-ca, an internal
  CA, the test CA in this repository's suite).
- Creating an account through a CA means accepting that CA's terms of service.

Do not put `keys = "auto"` on a name that does not resolve to this host: the CA
will fail the challenge. Use `--check` first; it parses everything and tells you
how many certificates a start would request, without touching the network.

### Static files

`root` replaces `upstream`; giving both is a config error. The final path is
canonicalised and must stay under the root, so `..`, `%2e%2e` and a symlink
pointing outside are all refused. A directory request without its trailing
slash gets a `301`; `index` is served for a directory. A missing file is a
`404`, never a fall-through to a proxy.

Supported methods are `GET` and `HEAD`; anything else gets `405`. Files are
streamed in 64 KiB chunks, with `Content-Type` from the extension and
`X-Content-Type-Options: nosniff`.

### IPv6

Two ways, both explicit:

```toml
[listen]
https = "[::]:443"          # this listener only, IPv6 (often dual-stack)
```

```toml
[listen]
http  = "0.0.0.0:80"
https = "0.0.0.0:443"
ipv6  = true                # both become [::]:port, one dual-stack socket
```

`ipv6 = true` also adds `[::1]:port` beside `127.0.0.1:port`. A concrete IPv4
address such as `10.0.0.1` is left alone — write the IPv6 address you actually
want. On Linux `[::]` is dual-stack by default; if the host sets
`net.ipv6.bindv6only=1`, list both families explicitly instead.

Upstreams accept the usual bracketed form, `[::1]:8080`, and `X-Forwarded-For`
carries the client's IPv6 address unchanged.

## Path routing

A `[[server.route]]` sends one path prefix of that domain to another backend;
the server's own `upstream` (or `root`) stays the catch-all. A top-level
`[[route]]` says the same thing once for several domains.

| Field          | On            | Meaning                                                        |
|----------------|---------------|----------------------------------------------------------------|
| `path`         | both          | Prefix to match, e.g. `/mcp`. Never `/` — that is the catch-all. |
| `upstream`     | both          | `host:port` for requests under `path`.                          |
| `root`         | both          | Static directory for requests under `path` (instead of `upstream`). |
| `strip_prefix` | both          | Remove `path` before forwarding/resolving (default `false`).    |
| `hosts`        | `[[route]]` only | Domains it serves. Empty or `["*"]` = every `[[server]]`.     |

```toml
[[route]]
path     = "/mcp"
upstream = "127.0.0.1:8081"
hosts    = ["www.example.com", "api.example.com"]   # omit for all domains
```

On an identical prefix the domain's own `[[server.route]]` wins over a
top-level one; a `hosts` entry naming no configured domain is a startup error.

## Raw TCP forwarding — experimental

> **Experimental in v0.2.1.** This is the mail/database relay: one port in, one
> upstream out. It is useful and tested, but its configuration and semantics
> may still change before it is declared stable.

HTTPS is not the only thing worth proxying. `[[stream]]` binds a port and copies
every byte to one upstream — SMTP, IMAP, MySQL, anything that is not HTTP. The
usual reason to want it: the service already listens on a loopback port, and it
should be reachable from outside without a second firewall hole.

```toml
[[stream]]
name     = "smtp"                 # log label, optional, falls back to `listen`
listen   = "0.0.0.0:25"
upstream = "127.0.0.1:10025"      # the port the service really listens on
connect_timeout_ms = 5000         # default 5000, clamped to 100..=30000
```

- One listener per entry; two entries on the same address are a config error.
- A client that half-closes still gets the upstream's drain — SMTP and IMAP
  both rely on this.
- Upstream refused or slow → the client is closed and exactly one line is
  logged. No retry, no hang past `connect_timeout_ms`.
- **No idle timeout**, on purpose: IMAP IDLE and idle database sessions are long
  by design.
- `[[stream]]` does not read TLS. Terminate it in the upstream.

`server.route` is **not** the mail relay: it routes HTTP paths, and exists for
projects like `raonagos/aaa`.

## Abuse protection

Two layers, both counted per client IP over a fixed one-second window, both
backed by a fixed-size estimator table — so the limiter itself cannot be turned
into a memory-exhaustion vector by a client that controls many source IPs.

| Setting                | Where it acts          | Over budget          |
|------------------------|------------------------|----------------------|
| `per_ip_conns_per_sec` | TCP accept, pre-TLS    | connection dropped   |
| `per_ip_rps`           | after HTTP parse       | `429 Too Many Requests` |
| `max_body_bytes`       | `Content-Length` + streamed body | `413 Payload Too Large` |

The defaults are deliberately generous: a normal page load pulls dozens of
assets at once and must not trip them. They stop a single-source flood, not a
burst of a few hundred requests. Tune to taste; set `0` to disable.

A fixed window means a client straddling the boundary can briefly reach twice
its budget. Chatty-but-legitimate traffic is unaffected.

## Headers

Request headers from the client are forwarded to the backend **unchanged**,
except:

- **Hop-by-hop** fields (`Connection`, `Transfer-Encoding`, `Keep-Alive`, …)
  are stripped, as RFC 9110 requires — they describe one connection, not the
  request. `Connection`-nominated extension fields are stripped too, and
  nominating `Host` or an `X-Forwarded-*` field is rejected outright.
- The original **`Host`** is preserved, so the backend sees the public
  hostname, not the upstream address.

uping then **adds**:

- `X-Forwarded-For` — the client IP, **appended** to any existing chain
- `X-Forwarded-Proto: https`
- `X-Forwarded-Host` — the `Host` the client sent

Response headers from the backend are forwarded back unchanged (hop-by-hop
again excepted), including status code and body framing. Bodies are streamed,
not buffered.

## Running it

uping runs as an ordinary user. The only privileged thing it does is bind ports
below 1024, and that is one file capability — `CAP_NET_BIND_SERVICE` — not an
identity. There is no root daemon and no installer.

```sh
cargo build --release
sudo setcap 'cap_net_bind_service=+ep' target/release/uping
```

The capability lives on the binary and is **lost on every rebuild**; re-apply it.
Then install the user unit:

```sh
mkdir -p ~/.config/systemd/user
cp uping.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now uping
loginctl enable-linger "$USER"     # start at boot, not only at login
```

The unit in this repository assumes the source checkout (`~/uping`) and a config
at `~/uping/config.toml`; edit `WorkingDirectory`/`ExecStart` if yours differs.
Certificates and the ACME account live under `~/uping/cert/`, so no root-owned
directory is involved.

To try it without installing anything, `test.config.toml` uses high ports:

```sh
cargo run -- test.config.toml
```

The planned apt layout — `/etc/uping/config.toml`, `/bin/uping`,
`/etc/uping/cert` — is for the v0.3 crates.io/apt release.

## Notes

- An `auto` certificate is renewed and reloaded in place. A `manual` one is read
  at startup; restart after replacing the files.
- Upstream connections are plain HTTP. A per-server `upstream_tls` toggle is a
  natural later addition.
- `uping --check [config.toml]` validates the whole load path — addresses, cert
  files, static roots, routes — without binding a socket or touching the
  network.

## License

Apache-2.0 — see [LICENSE](LICENSE).
