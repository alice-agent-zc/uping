# uping

A tiny, TOML-configured reverse proxy for the 90% of cases where nginx is
overkill. Built on Cloudflare's [Pingora](https://github.com/cloudflare/pingora).

Point a domain at a local service, let uping obtain the certificate, done. It
also serves a directory without a backend, works over IPv4 and IPv6, and
reloads its config with `systemctl --user reload` — no restart for a config
change.

## Status — v0.3.0

- ✅ HTTPS reverse proxy with SNI, one cert per domain
- ✅ Let's Encrypt certificates (`keys = "auto"`) and automatic renewal
- ✅ Static files (`root`) and path routing, each route tied to its domain
- ✅ One `[listen]` for the host, plus per-domain `listen` / `listen6`
- ✅ Private sites: `listen` on a VPN address and `http = false` to stay off
  port 80, plus `uping --dns-zone` for the VPN resolver's records
- ✅ HTTP → HTTPS redirect, per-IP request/connection limits, body cap
- ✅ Upstream health checks (`503` at once when a backend dies) and HTTPS to
  the backend, with a private CA, SNI and an explicit verify opt-out
- ✅ Live config reload on `SIGHUP`
- ⚠️ `[[stream]]` raw TCP forwarding is **experimental** — the mail/database
  relay. `server.route` is HTTP path routing, not the mail feature.

Not here: hot-reload of listeners or `[[stream]]`, load balancing, upstream
mutual TLS. Those need a restart (or are future work).

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

A static site is the same block with `root = "public"` instead of `upstream`.
For a second service on another address, add `listen = "203.0.113.10"` to it;
the `[listen]` section covers everything else.

For the systemd user unit, every option, the certificate layout, ACME details,
IPv6, reload semantics and the experimental stream relay, see
**[CONTRIBUTING.md](CONTRIBUTING.md)**.

## Reload or restart?

```sh
systemctl --user reload uping     # SIGHUP: config changes, no dropped conn
systemctl --user restart uping    # a new binary, or a listener/[[stream]] change
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
