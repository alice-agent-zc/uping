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
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::ConnectionFilter;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;

use crate::config::Config;
use crate::limits::{ConnLimiter, RequestLimiter};
use crate::proxy::{HttpsProxy, PathRoute, RedirectProxy, RouteTable, SiteRoutes};
use crate::tls::SniResolver;

/// Build the `domain -> routes` table, lowercasing domains so that
/// `EXAMPLE.com` and `example.com` hit the same upstream. A later `[[server]]`
/// for a domain replaces an earlier one wholesale, routes included.
///
/// Each server gets its own routes plus the top-level `[[route]]` entries whose
/// `hosts` cover it, resolved by [`Config::routes_for`].
fn build_routes(cfg: &Config) -> RouteTable {
    let mut sites = HashMap::new();
    for s in &cfg.servers {
        let routes = cfg.routes_for(s).into_iter().map(PathRoute::from_config);
        sites.insert(
            s.domain.to_ascii_lowercase(),
            SiteRoutes::new(s.upstream.clone(), routes),
        );
    }
    RouteTable::new(sites)
}

fn main() -> Result<()> {
    env_logger::init();

    // Usage: uping [config.toml]
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".into());
    let cfg = Config::load(&config_path)
        .with_context(|| format!("loading configuration from `{config_path}`"))?;

    // domain -> upstreams
    let routes = Arc::new(build_routes(&cfg));
    info!(
        "{} path route(s) across {} domain(s)",
        routes.route_count(),
        cfg.servers.len()
    );

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
        for r in cfg.routes_for(s) {
            info!(
                "  {}{} -> {}{}",
                s.domain,
                r.prefix(),
                r.upstream,
                if r.strip_prefix {
                    " (prefix stripped)"
                } else {
                    ""
                }
            );
        }
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
        warn!(
            "a port below 1024 needs CAP_NET_BIND_SERVICE, not root: systemd units \
             declare `AmbientCapabilities=CAP_NET_BIND_SERVICE` (see deploy/uping.service)"
        );
    }

    server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Server as ConfigServer;

    fn server(domain: &str, upstream: &str) -> ConfigServer {
        ConfigServer {
            domain: domain.to_string(),
            pub_key: "certs/test.local.crt".to_string(),
            priv_key: "certs/test.local.key".to_string(),
            upstream: upstream.to_string(),
            routes: Vec::new(),
        }
    }

    /// A config holding only the parts `build_routes` reads.
    fn config(servers: Vec<ConfigServer>, routes: Vec<crate::config::Route>) -> Config {
        Config {
            listen: Default::default(),
            limits: Default::default(),
            tls: Default::default(),
            servers,
            routes,
        }
    }

    #[test]
    fn routes_are_keyed_by_lowercased_domain() {
        let servers = vec![
            server("Test.Local", "127.0.0.1:8080"),
            server("API.Example.COM", "127.0.0.1:9000"),
        ];
        let routes = build_routes(&config(servers, Vec::new()));

        assert_eq!(
            routes.get("test.local").unwrap().resolve("/").upstream,
            "127.0.0.1:8080"
        );
        assert_eq!(
            routes.get("api.example.com").unwrap().resolve("/").upstream,
            "127.0.0.1:9000"
        );
        assert!(routes.get("Test.Local").is_none());
    }

    #[test]
    fn routes_from_the_config_reach_the_table() {
        let mut s = server("aaa.local", "127.0.0.1:8080");
        s.routes = vec![crate::config::Route {
            path: "/assets/".to_string(),
            upstream: "127.0.0.1:8085".to_string(),
            strip_prefix: true,
            hosts: Vec::new(),
        }];
        let routes = build_routes(&config(vec![s], Vec::new()));

        assert_eq!(routes.route_count(), 1);
        let hit = routes.get("aaa.local").unwrap().resolve("/assets/app.css");
        assert_eq!(hit.upstream, "127.0.0.1:8085");
        assert_eq!(hit.strip, Some("/assets"));
    }

    #[test]
    fn a_global_route_reaches_every_server_in_the_table() {
        let servers = vec![
            server("a.example", "127.0.0.1:8080"),
            server("b.example", "127.0.0.1:8090"),
        ];
        let global = crate::config::Route {
            path: "/mcp".to_string(),
            upstream: "127.0.0.1:9000".to_string(),
            strip_prefix: false,
            hosts: Vec::new(),
        };
        let routes = build_routes(&config(servers, vec![global]));

        assert_eq!(routes.route_count(), 2);
        for domain in ["a.example", "b.example"] {
            let hit = routes.get(domain).unwrap().resolve("/mcp/v1");
            assert_eq!(hit.upstream, "127.0.0.1:9000", "{domain}");
        }
    }

    #[test]
    fn later_entries_win_on_duplicate_domains() {
        let servers = vec![
            server("test.local", "127.0.0.1:8080"),
            server("TEST.LOCAL", "127.0.0.1:9090"),
        ];
        let routes = build_routes(&config(servers, Vec::new()));

        assert_eq!(
            routes.get("test.local").unwrap().resolve("/").upstream,
            "127.0.0.1:9090"
        );
    }
}
