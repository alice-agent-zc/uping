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

The expected deployment is root on a small VPS, in front of a local service:

```sh
cargo build --release
sudo install -m 0755 target/release/uping /usr/local/bin/uping
sudo install -d -m 0755 /etc/uping
sudo install -m 0644 config.toml /etc/uping/config.toml   # your real config
```

Save the unit below as `/etc/systemd/system/uping.service`, then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now uping
journalctl -u uping -f
```

It runs as root deliberately: it must bind `:80`/`:443` and read mode-`0600`
private keys such as `privkey.pem`. To avoid that, bind high ports under
`[listen]` and grant the binary just the one capability it needs:

```sh
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/uping
```

(Reading the certificate is then your problem — `privkey.pem` from Let's
Encrypt is mode 0600 and root-owned.)

<details>
<summary><code>/etc/systemd/system/uping.service</code></summary>

```ini
[Unit]
Description=uping reverse proxy
Documentation=https://github.com/raonagos/uping
# We need a working DNS/network before resolving upstreams like "localhost:42617".
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/uping /etc/uping/config.toml

# Pingora runs its own worker threads; the main process stays in the foreground
# and handles SIGTERM cleanly, so on-failure restarts are enough.
Restart=on-failure
RestartSec=2
KillSignal=SIGTERM
TimeoutStopSec=10

# uping must bind :80/:443 and read /etc/letsencrypt/live/.../privkey.pem
# (mode 0600, root-only), so it runs as root. This is the intended deployment.
User=root
Group=root

# Logs go to the journal:  journalctl -u uping -f
StandardOutput=journal
StandardError=journal
SyslogIdentifier=uping

# Uncomment for verbose per-request logging:
#Environment=RUST_LOG=info

# --- Hardening (safe for uping) ---
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
# ProtectSystem=strict makes / read-only; these two give back exactly what we need.
ReadWritePaths=/var/log
ReadOnlyPaths=/etc/letsencrypt /etc/uping

[Install]
WantedBy=multi-user.target
```

</details>

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
