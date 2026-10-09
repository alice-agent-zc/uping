# uping

A tiny, TOML-configured reverse proxy for the 90% of cases where nginx is
overkill. Built on Cloudflare's [Pingora](https://github.com/cloudflare/pingora).

Point a domain at a local service, hand it a cert, done. Plain HTTP is
automatically redirected to HTTPS, and clients that misbehave are capped.

## Status — v0.1.1

- ✅ Reverse proxy: `domain` → `upstream` over HTTPS (TLS termination)
- ✅ **Automatic HTTP → HTTPS redirect** (301)
- ✅ TLS with **SNI**: one listener, one cert per domain
- ✅ **Abuse protection**: per-IP connection rate (TCP level), per-IP request
  rate, and a request body size cap
- ✅ **Forwarded headers**: `X-Forwarded-For` / `-Proto` / `-Host`
- ✅ Simple flat TOML config

Deliberately *not* here (candidates for later): ACME/Let's Encrypt, config
hot-reload, load balancing, health checks.

### What changed in v0.1.1

- **Config keys renamed**: `pub_pem`/`priv_pem` → **`pub_key`/`priv_key`**.
  The old names are no longer accepted (you get a TOML parse error).
- **Empty / unknown SNI no longer fails loudly.** A client connecting by raw IP
  sends no SNI (RFC 6066 forbids an IP literal there), and v0.1.0 answered that
  with `no certificate available for SNI` plus an OpenSSL handshake error on
  every scan. Now the first configured certificate is served as a fallback, so
  the handshake completes and the log stays quiet. Turn it off with
  `[tls] fallback_cert = false` if you want strict SNI-only behaviour.
- **Unknown `Host` now gets a `404`** instead of a `500` from the proxy.
- **Abuse protection** (see below).

## Config

```toml
# Optional. Defaults to 0.0.0.0:80 / 0.0.0.0:443.
# [listen]
# http  = "0.0.0.0:80"
# https = "0.0.0.0:443"

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
pub_key  = "certs/www.example.com/fullchain.pem"
priv_key = "certs/www.example.com/privkey.pem"
upstream = "127.0.0.1:8080"
```

| Field      | Meaning                                                             |
|------------|---------------------------------------------------------------------|
| `domain`   | Public hostname. Matched against TLS SNI **and** the `Host` header.  |
| `pub_key`  | PEM certificate — leaf first, then intermediates (fullchain).        |
| `priv_key` | PEM private key.                                                    |
| `upstream` | Where to forward traffic, `host:port`. Plain HTTP to the backend.    |

Add one `[[server]]` block per domain. All domains share the single `:443`
listener; the right certificate is chosen per-connection via SNI.

`config.toml` in the current directory is the built-in default; pass another
path as the first argument to override it.

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

So a backend that needs to know the request arrived over HTTPS can read
`X-Forwarded-Proto`, and one that builds absolute URLs should honour
`X-Forwarded-Host`.

## Running it

uping is distributed as source. It wants a certificate + key per domain, and
the right to bind `:80` and `:443` (root or `CAP_NET_BIND_SERVICE`):

```sh
cargo build --release
sudo ./target/release/uping config.toml
```

Building has a few prerequisites that are not part of a default Rust install —
CMake in particular. **[CONTRIBUTING.md](CONTRIBUTING.md)** covers those, the
systemd unit, and how to try uping out without root.

## Notes

- Certificates are loaded **once at startup**. Restart to pick up new certs.
- Upstream connections are plain HTTP. A per-server `upstream_tls` toggle is a
  natural v0.2 addition.

## License

Apache-2.0 — see [LICENSE](LICENSE).
