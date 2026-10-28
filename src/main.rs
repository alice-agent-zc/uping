//! uping — a tiny TOML-configured reverse proxy on Cloudflare Pingora.
//!
//! v0.1.1: read a config, load certs, serve HTTPS (SNI) on :443, redirect plain
//! HTTP to HTTPS on :80, and keep a lid on abusive clients.

mod config;
mod limits;
mod proxy;
mod stream;
mod tls;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use log::{info, warn};
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::ConnectionFilter;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use pingora::services::listening::Service;

use crate::config::Config;
use crate::limits::{ConnLimiter, RequestLimiter};
use crate::proxy::{HttpsProxy, PathRoute, RedirectProxy, RouteTable, SiteRoutes};
use crate::stream::StreamForwarder;
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

const USAGE: &str = "usage: uping [config.toml] [--check|--dry-run]";

/// A parsed command line: one optional config path and one flag.
struct Args {
    path: String,
    check: bool,
}

/// Hand-parsed: two shapes and one flag do not justify a dependency, and a
/// parser is itself a thing that can reject a valid invocation.
///
/// Both `uping --check [path]` and `uping [path] --check` are accepted.
fn parse_args(raw: impl Iterator<Item = String>) -> Result<Args> {
    let mut path: Option<String> = None;
    let mut check = false;

    for arg in raw {
        match arg.as_str() {
            "--check" | "--dry-run" => check = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other if other.starts_with('-') => {
                anyhow::bail!("unknown option `{other}`; {USAGE}")
            }
            other => {
                if path.replace(other.to_string()).is_some() {
                    anyhow::bail!(
                        "unexpected argument `{other}`: at most one config path; {USAGE}"
                    );
                }
            }
        }
    }

    Ok(Args {
        path: path.unwrap_or_else(|| "config.toml".into()),
        check,
    })
}

/// Run [`check_config`] and exit: `0` with one line on stdout, `1` with the
/// whole cause chain on stderr.
fn run_check(path: &str) -> ! {
    match check_config(path) {
        Ok(line) => {
            println!("{line}");
            std::process::exit(0)
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1)
        }
    }
}

/// Validate the config without touching the network, binding nothing and
/// needing no privilege.
///
/// It runs the load path the server would — [`Config::load`], then
/// [`SniResolver::from_servers`] — because the failures that take production
/// down happen *before* a socket exists: a malformed address, a cert that
/// cannot be read or parsed. A check that skipped the certs would pass the
/// config that killed the service on 2026-10-25.
fn check_config(path: &str) -> Result<String> {
    let cfg = Config::load(path).with_context(|| format!("loading configuration from `{path}`"))?;

    // Same condition as `main`: an empty `[[server]]` list loads no TLS.
    if !cfg.servers.is_empty() {
        SniResolver::from_servers(&cfg.servers, cfg.tls.fallback_cert)
            .context("loading TLS certificates")?;
    }

    let routes = build_routes(&cfg).route_count();
    Ok(format!(
        "ok: {} [[server]], {} [[stream]], {routes} route(s) · {path}",
        cfg.servers.len(),
        cfg.streams.len()
    ))
}

fn main() -> Result<()> {
    let args = parse_args(std::env::args().skip(1))?;
    if args.check {
        run_check(&args.path);
    }

    env_logger::init();

    let config_path = args.path;
    let cfg = Config::load(&config_path)
        .with_context(|| format!("loading configuration from `{config_path}`"))?;

    // domain -> upstreams
    let routes = Arc::new(build_routes(&cfg));
    info!(
        "{} path route(s) across {} domain(s)",
        routes.route_count(),
        cfg.servers.len()
    );

    let mut server = Server::new(None).context("creating Pingora server")?;
    server.bootstrap();

    if cfg.servers.is_empty() {
        info!("no [[server]] entries: HTTP and HTTPS listeners are not started");
    } else {
        // Pre-load all cert/key pairs for SNI selection.
        let resolver = SniResolver::from_servers(&cfg.servers, cfg.tls.fallback_cert)
            .context("loading TLS certificates")?;

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
    }

    // --- Raw TCP streams ---
    // One listener per [[stream]]. The upstream is whatever holds the port on
    // loopback; uping neither starts nor watches it.
    for s in &cfg.streams {
        let forwarder = StreamForwarder::new(s);
        info!(
            "stream {} listening on {} -> {}",
            forwarder.label(),
            s.listen,
            forwarder.upstream()
        );
        let mut service = Service::new(format!("stream:{}", forwarder.label()), forwarder);
        service.add_tcp(&s.listen);
        server.add_service(service);
    }

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

    let privileged_http = !cfg.servers.is_empty()
        && (cfg.listen.http.ends_with(":80") || cfg.listen.https.ends_with(":443"));
    let privileged_stream = cfg.streams.iter().any(|s| {
        s.listen
            .trim()
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .is_some_and(|p| p < 1024)
    });
    if privileged_http || privileged_stream {
        warn!(
            "a port below 1024 needs CAP_NET_BIND_SERVICE, not root: the systemd unit \
             declares `AmbientCapabilities=CAP_NET_BIND_SERVICE` (see deploy/install.sh)"
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
            streams: Vec::new(),
        }
    }

    fn args(raw: &[&str]) -> Result<Args> {
        parse_args(raw.iter().map(|s| s.to_string()))
    }

    #[test]
    fn the_check_flag_is_accepted_before_or_after_the_path() {
        for raw in [&["--check", "a.toml"][..], &["a.toml", "--check"][..]] {
            let parsed = args(raw).expect("check flag should parse");
            assert!(parsed.check);
            assert_eq!(parsed.path, "a.toml");
        }
    }

    #[test]
    fn the_check_flag_alone_reads_config_toml() {
        let parsed = args(&["--check"]).unwrap();
        assert!(parsed.check);
        assert_eq!(parsed.path, "config.toml");
    }

    #[test]
    fn no_flag_means_serve() {
        let parsed = args(&["a.toml"]).unwrap();
        assert!(!parsed.check);
        assert_eq!(parsed.path, "a.toml");
    }

    #[test]
    fn an_unknown_option_and_a_second_path_are_rejected() {
        assert!(args(&["--nope"]).is_err());
        assert!(args(&["a.toml", "b.toml"]).is_err());
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
