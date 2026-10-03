# uping

A tiny, TOML-configured reverse proxy for the 90% of cases where nginx is overkill.
Built on Cloudflare's [Pingora](https://github.com/cloudflare/pingora).

Point a domain at a local service, hand it a cert, done. Plain HTTP is
automatically redirected to HTTPS.

## Status — v0.1.0

Deliberately minimal. What's in:

- ✅ Reverse proxy: `domain` → `upstream` over HTTPS (TLS termination)
- ✅ **Automatic HTTP → HTTPS redirect** (301)
- ✅ TLS with **SNI**: one listener, one cert per domain
- ✅ Simple flat TOML config

Deliberately *not* in v0.1.0 (candidates for later): ACME/Let's Encrypt,
config hot-reload, load balancing, health checks, WebSocket-specific tuning.

## Config

```toml
# Optional. Defaults to 0.0.0.0:80 / 0.0.0.0:443.
# [listen]
# http  = "0.0.0.0:80"
# https = "0.0.0.0:443"

[[server]]
domain   = "www.example.com"
pub_pem  = "certs/www.example.com/fullchain.pem"
priv_pem = "certs/www.example.com/privkey.pem"
upstream = "127.0.0.1:8080"
```

| Field      | Meaning                                                           |
|------------|-------------------------------------------------------------------|
| `domain`   | Public hostname. Matched against TLS SNI **and** the `Host` header.|
| `pub_pem`  | PEM certificate — leaf first, then intermediates (fullchain).       |
| `priv_pem` | PEM private key.                                                   |
| `upstream` | Where to forward traffic, `host:port`. Plain HTTP to the backend.  |

Add one `[[server]]` block per domain. All domains share the single `:443`
listener; the right certificate is chosen per-connection via SNI.

## Build & run

```sh
cargo build --release
sudo ./target/release/uping config.toml
```

Binding `:80`/`:443` needs root or `CAP_NET_BIND_SERVICE`:

```sh
sudo setcap 'cap_net_bind_service=+ep' ./target/release/uping
```

Or set custom ports under `[listen]` to run unprivileged (see `test.config.toml`).

## Notes

- TLS uses the **OpenSSL** backend. (Dynamic per-SNI certificate selection —
  i.e. multiple domains — is only supported on OpenSSL/BoringSSL in Pingora;
  the rustls backend ignores it.)
- Certificates are loaded **once at startup**. Restart to pick up new certs.
- Upstream connections are plain HTTP. A per-server `upstream_tls` toggle is a
  natural v0.2 addition.

## Project layout

```
src/
  main.rs    # bootstrap, wiring, run
  config.rs  # TOML schema + validation
  tls.rs     # SNI certificate resolver
  proxy.rs   # HTTPS proxy + HTTP redirect
```
