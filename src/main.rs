//! uping — a tiny TOML-configured reverse proxy on Cloudflare Pingora.
//!
//! v0.1.1: read a config, load certs, serve HTTPS (SNI) on :443, redirect plain
//! HTTP to HTTPS on :80, and keep a lid on abusive clients.

mod config;
mod limits;
mod proxy;
mod tls;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use log::{info, warn};
use pingora::listeners::ConnectionFilter;
use pingora::listeners::tls::TlsSettings;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;

use crate::config::{Config, Server as ConfigServer};
use crate::limits::{ConnLimiter, RequestLimiter};
use crate::proxy::{HttpsProxy, RedirectProxy};
use crate::tls::SniResolver;

/// Build the `domain -> upstream` routing table, lowercasing domains so that
/// `EXAMPLE.com` and `example.com` hit the same upstream.
fn build_routes(servers: &[ConfigServer]) -> HashMap<String, String> {
    servers
        .iter()
        .map(|s| (s.domain.to_ascii_lowercase(), s.upstream.clone()))
        .collect()
}

fn main() -> Result<()> {
    env_logger::init();

    // Usage: uping [config.toml]
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".into());
    let cfg = Config::load(&config_path)
        .with_context(|| format!("loading configuration from `{config_path}`"))?;

    // domain -> upstream
    let routes = Arc::new(build_routes(&cfg.servers));

    // Pre-load all cert/key pairs for SNI selection.
    let resolver = SniResolver::from_servers(&cfg.servers, cfg.tls.fallback_cert)
        .context("loading TLS certificates")?;

    let mut server = Server::new(None).context("creating Pingora server")?;
    server.bootstrap();

    // Shared between the :80 and :443 listeners, so one client cannot use two
    // ports to get two connection budgets.
    let conn_filter: Arc<dyn ConnectionFilter> =
        Arc::new(ConnLimiter::new(cfg.limits.per_ip_conns_per_sec));

    // --- HTTPS (TLS termination + reverse proxy) ---
    let mut https_service = http_proxy_service(
        &server.configuration,
        HttpsProxy::new(
            routes,
            RequestLimiter::new(cfg.limits.per_ip_rps),
            cfg.limits.max_body_bytes,
        ),
    );
    https_service.set_connection_filter(conn_filter.clone());
    let tls_settings =
        TlsSettings::with_callbacks(Box::new(resolver)).context("building TLS settings")?;
    https_service.add_tls_with_settings(&cfg.listen.https, None, tls_settings);
    server.add_service(https_service);
    info!("HTTPS listening on {}", cfg.listen.https);

    // --- HTTP (redirect to HTTPS) ---
    let mut http_service = http_proxy_service(&server.configuration, RedirectProxy);
    http_service.set_connection_filter(conn_filter);
    http_service.add_tcp(&cfg.listen.http);
    server.add_service(http_service);
    info!(
        "HTTP listening on {} (redirecting to HTTPS)",
        cfg.listen.http
    );

    for s in &cfg.servers {
        info!("  {} -> {}", s.domain, s.upstream);
    }

    if cfg.limits.per_ip_conns_per_sec == 0 {
        warn!("per-IP connection limiting is disabled (per_ip_conns_per_sec = 0)");
    } else {
        info!(
            "limits: {} conn/s and {} req/s per IP",
            cfg.limits.per_ip_conns_per_sec, cfg.limits.per_ip_rps
        );
    }
    if cfg.limits.per_ip_rps == 0 {
        warn!("per-IP request limiting is disabled (per_ip_rps = 0)");
    }
    match cfg.limits.max_body_bytes {
        0 => warn!("request body size limiting is disabled (max_body_bytes = 0)"),
        n => info!("limits: request bodies capped at {n} bytes"),
    }
    if !cfg.tls.fallback_cert {
        info!("TLS: no fallback certificate; unknown or missing SNI will fail the handshake");
    }

    if cfg.listen.http.ends_with(":80") || cfg.listen.https.ends_with(":443") {
        warn!("binding to ports 80/443 usually requires root or CAP_NET_BIND_SERVICE");
    }

    server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(domain: &str, upstream: &str) -> ConfigServer {
        ConfigServer {
            domain: domain.to_string(),
            pub_key: "certs/test.local.crt".to_string(),
            priv_key: "certs/test.local.key".to_string(),
            upstream: upstream.to_string(),
        }
    }

    #[test]
    fn routes_are_keyed_by_lowercased_domain() {
        let servers = vec![
            server("Test.Local", "127.0.0.1:8080"),
            server("API.Example.COM", "127.0.0.1:9000"),
        ];
        let routes = build_routes(&servers);

        assert_eq!(routes.len(), 2);
        assert_eq!(routes.get("test.local").map(String::as_str), Some("127.0.0.1:8080"));
        assert_eq!(routes.get("api.example.com").map(String::as_str), Some("127.0.0.1:9000"));
        assert!(!routes.contains_key("Test.Local"));
    }

    #[test]
    fn later_entries_win_on_duplicate_domains() {
        let servers = vec![
            server("test.local", "127.0.0.1:8080"),
            server("TEST.LOCAL", "127.0.0.1:9090"),
        ];
        let routes = build_routes(&servers);

        assert_eq!(routes.len(), 1);
        assert_eq!(routes["test.local"], "127.0.0.1:9090");
    }
}
