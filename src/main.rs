//! uping — a tiny TOML-configured reverse proxy.
//!
//! v0.3 reads a config, obtains or loads one certificate per domain, serves
//! HTTPS (SNI) on the global and per-domain listeners, redirects plain HTTP to
//! HTTPS, and keeps a lid on abusive clients. A `[[server]]` or route may also
//! serve a directory directly (`root`), forward to a TLS backend, and is probed
//! for liveness so a dead backend is a fast `503`. `[[stream]]` raw TCP
//! forwarding is experimental.

mod acme;
mod config;
mod health;
mod limits;
mod proxy;
mod sighup;
mod static_files;
mod stream;
mod tls;

use std::collections::HashSet;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use log::{info, warn};
use pingora::apps::HttpServerOptions;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::ConnectionFilter;
use pingora::proxy::ProxyServiceBuilder;
use pingora::server::Server;
use pingora::services::listening::Service;

use crate::acme::{CertManager, ChallengeStore};
use crate::config::{Config, GroupKey};
use crate::health::HealthTracker;
use crate::limits::{ConnLimiter, RequestLimiter};
use crate::proxy::{HttpsProxy, RedirectProxy, RouteTable};
use crate::sighup::{Allowed, Reloader};
use crate::stream::StreamForwarder;
use crate::tls::SniResolver;

const USAGE: &str = "usage: uping [config.toml] [--check|--dry-run|--dns-zone]";

/// A parsed command line: one optional config path and one flag.
struct Args {
    path: String,
    check: bool,
    dns_zone: bool,
}

/// Hand-parsed: two shapes and one flag do not justify a dependency, and a
/// parser is itself a thing that can reject a valid invocation.
///
/// Both `uping --check [path]` and `uping [path] --check` are accepted, and the
/// same goes for `--dns-zone`.
fn parse_args(raw: impl Iterator<Item = String>) -> Result<Args> {
    let mut path: Option<String> = None;
    let mut check = false;
    let mut dns_zone = false;

    for arg in raw {
        match arg.as_str() {
            "--check" | "--dry-run" => check = true,
            "--dns-zone" => dns_zone = true,
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

    if check && dns_zone {
        anyhow::bail!("`--check` and `--dns-zone` are different outputs; pick one");
    }

    Ok(Args {
        path: path.unwrap_or_else(|| "config.toml".into()),
        check,
        dns_zone,
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

/// Print the resolver records for this config and exit.
///
/// The format is `hosts(5)` — `IP name`, one line per family — because that is
/// what dnsmasq (`addn-hosts=`), CoreDNS (`hosts`) and `/etc/hosts` all read.
/// uping does not serve DNS: the WireGuard-side resolver owns that, and this
/// command keeps the names in sync with the proxy config.
fn run_dns_zone(path: &str) -> ! {
    match dns_zone(path) {
        Ok(text) => {
            print!("{text}");
            std::process::exit(0)
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1)
        }
    }
}

fn dns_zone(path: &str) -> Result<String> {
    let cfg = Config::load(path).with_context(|| format!("loading configuration from `{path}`"))?;
    let mut records: Vec<(String, std::net::IpAddr)> = Vec::new();
    for server in &cfg.servers {
        let (v4, v6) = server.binds(cfg.listen.https)?;
        let addrs: Vec<std::net::IpAddr> = if v4.is_none() && v6.is_none() {
            let mut all = vec![std::net::IpAddr::V4(cfg.listen.ipv4_addr()?)];
            if let Some(v6) = cfg.listen.ipv6_addr()? {
                all.push(std::net::IpAddr::V6(v6));
            }
            all
        } else {
            [v4, v6]
                .into_iter()
                .flatten()
                .map(|addr| addr.ip())
                .collect()
        };
        for ip in addrs {
            if ip.is_unspecified() {
                anyhow::bail!(
                    "`{}` listens on the wildcard {ip}; set `[listen] ipv4`/`ipv6` \
                     or a per-server `listen`/`listen6` to a concrete address, \
                     otherwise a DNS record would point nowhere",
                    server.domain
                );
            }
            records.push((server.domain.clone(), ip));
        }
    }
    records.sort();
    let mut out = String::from(
        "# uping --dns-zone: one record per configured domain and family.\n\
         # Load with dnsmasq `addn-hosts=`, CoreDNS `hosts`, or /etc/hosts.\n",
    );
    for (domain, ip) in records {
        out.push_str(&format!("{ip} {domain}\n"));
    }
    Ok(out)
}

/// Validate the config without touching the network, binding nothing and
/// needing no privilege.
///
/// It runs the load path the server would — [`Config::load`], then
/// [`SniResolver::from_config`] — because the failures that take production
/// down happen *before* a socket exists: a malformed address, a cert that
/// cannot be read or parsed. A check that skipped the certs would pass the
/// config that killed the service on 2026-10-25.
fn check_config(path: &str) -> Result<String> {
    let cfg = Config::load(path).with_context(|| format!("loading configuration from `{path}`"))?;

    // Same condition as `main`: an empty `[[server]]` list loads no TLS.
    // `from_config` parses every certificate that is already on disk and counts
    // the `auto` ones that do not exist yet. It never touches the network and
    // writes nothing, so `--check` stays a pure read.
    let pending = if cfg.servers.is_empty() {
        0
    } else {
        SniResolver::from_config(&cfg)
            .context("loading TLS certificates")?
            .1
            .len()
    };

    let routes = RouteTable::from_config(&cfg)?.route_count();
    Ok(format!(
        "ok: {} [[server]], {} [[stream]], {routes} route(s), {pending} certificate(s) to request · {path}",
        cfg.servers.len(),
        cfg.streams.len()
    ))
}

fn main() -> Result<()> {
    let args = parse_args(std::env::args().skip(1))?;
    if args.check {
        run_check(&args.path);
    }
    if args.dns_zone {
        run_dns_zone(&args.path);
    }

    env_logger::init();

    let config_path = args.path;
    let cfg = Config::load(&config_path)
        .with_context(|| format!("loading configuration from `{config_path}`"))?;

    // domain -> targets; the outer lock lets a reload swap the whole table.
    let live_routes = Arc::new(RwLock::new(Arc::new(RouteTable::from_config(&cfg)?)));
    info!(
        "{} path route(s) across {} domain(s)",
        live_routes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .route_count(),
        cfg.servers.len()
    );

    // Resolve and probe every backend before the first request can reach it.
    let health = HealthTracker::new();
    {
        let table = live_routes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        health.prime(&table);
    }

    let mut server = Server::new(None).context("creating Pingora server")?;
    server.bootstrap();

    // Load manual pairs and count the `auto` ones that do not exist yet. Both
    // are empty when there is no `[[server]]`, but the SIGHUP handler below
    // still has to exist: the default action for an unhandled SIGHUP is exit.
    let (resolver, pending) = SniResolver::from_config(&cfg).context("loading TLS certificates")?;
    let challenges = ChallengeStore::new();
    let certs = Arc::new(CertManager::new(&cfg, resolver.clone(), challenges.clone()));
    // The renewal thread and the reload thread share this list: a domain added
    // by a SIGHUP must still get its hourly renewal check.
    let renewal_servers = Arc::new(RwLock::new(cfg.servers.clone()));

    // A first start has no HTTP listener yet, so the challenge binds the
    // configured HTTP address briefly and releases it before Pingora starts.
    let http_disabled: Arc<RwLock<Arc<HashSet<String>>>> = Arc::new(RwLock::new(Arc::new(
        cfg.servers
            .iter()
            .filter(|s| !s.serve_http)
            .map(|s| s.domain.to_ascii_lowercase())
            .collect(),
    )));

    let http_addrs: Vec<String> = cfg
        .listen
        .http_addrs()
        .context("reading `[listen]`")?
        .iter()
        .map(|addr| addr.to_string())
        .collect();
    let acme_complete = certs
        .obtain_missing(&pending, &http_addrs)
        .context("preparing TLS certificates")?;
    if !acme_complete {
        warn!(
            "acme: some certificates are still missing; starting without them and \
             retrying in one hour (those domains fail the TLS handshake until then)"
        );
    }

    // Shared between the :80 and :443 listeners, so one client cannot use two
    // ports to get two connection budgets.
    let request_limiter = Arc::new(RequestLimiter::new(cfg.limits.per_ip_rps));
    let conn_limiter = Arc::new(ConnLimiter::new(cfg.limits.per_ip_conns_per_sec));
    let max_body = Arc::new(AtomicUsize::new(cfg.limits.max_body_bytes));
    let conn_filter: Arc<dyn ConnectionFilter> = conn_limiter.clone();

    // One HTTPS service per distinct listener, so a server that overrides
    // `listen`/`listen6` really answers only there. All services share one
    // route table and one certificate resolver; each one carries the set of
    // domains it is allowed to serve.
    let https_groups = cfg.https_groups().context("grouping the HTTPS listeners")?;
    let mut allow_lists: Vec<(GroupKey, Allowed)> = Vec::new();

    if cfg.servers.is_empty() {
        info!("no [[server]] entries: HTTP and HTTPS listeners are not started");
    } else {
        // Bound per-connection memory: rotate H1 keepalives, and close idle H2
        // connections. The H1 idle timeout itself is set per request below.
        let mut server_options = HttpServerOptions::default();
        server_options.keepalive_request_limit = Some(1_000);
        server_options.h2_idle_timeout = Some(Duration::from_secs(300));

        // --- HTTPS (TLS termination + reverse proxy), one service per group ---
        for group in &https_groups {
            let allowed: HashSet<String> = group.domains.iter().cloned().collect();
            let allowed = Arc::new(RwLock::new(Arc::new(allowed)));
            let mut https_service = ProxyServiceBuilder::new(
                &server.configuration,
                HttpsProxy::new(
                    live_routes.clone(),
                    request_limiter.clone(),
                    max_body.clone(),
                    allowed.clone(),
                    health.clone(),
                ),
            )
            .server_options(server_options.clone())
            .build();
            https_service.set_connection_filter(conn_filter.clone());
            for addr in &group.addrs {
                let tls_settings = TlsSettings::with_callbacks(Box::new(resolver.clone()))
                    .context("building TLS settings")?;
                https_service.add_tls_with_settings(&addr.to_string(), None, tls_settings);
                info!("HTTPS listening on {addr} for {}", group.domains.join(", "));
            }
            server.add_service(https_service);
            allow_lists.push((group.key.clone(), allowed));
        }

        // --- HTTP (redirect to HTTPS, plus the ACME challenge path) ---
        // One service for every domain: port 80 is where http-01 has to answer,
        // and a redirect does not need to know which vhost it came from.
        let mut http_service = ProxyServiceBuilder::new(
            &server.configuration,
            RedirectProxy::new(challenges.clone(), http_disabled.clone()),
        )
        .server_options(server_options)
        .build();
        http_service.set_connection_filter(conn_filter);
        for addr in &http_addrs {
            http_service.add_tcp(addr);
            info!("HTTP listening on {addr} (redirecting to HTTPS)");
        }
        server.add_service(http_service);
    }

    // A clean start renews a due pair 30s after pingora owns `:80`; a failed
    // startup order waits an hour, both to let the CA's window pass and to
    // avoid turning a rejection into a retry storm.
    let first_renewal_check = if acme_complete {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(60 * 60)
    };
    certs
        .clone()
        .spawn_renewal(renewal_servers.clone(), first_renewal_check)
        .context("starting certificate renewal")?;

    let reloader = Arc::new(Reloader::new(
        std::path::PathBuf::from(&config_path),
        live_routes.clone(),
        resolver,
        certs,
        request_limiter,
        conn_limiter,
        max_body,
        allow_lists,
        http_disabled,
        renewal_servers,
        health.clone(),
        &cfg,
    )?);
    reloader.spawn().context("starting the reload thread")?;
    health.clone().spawn(live_routes.clone());
    info!("SIGHUP applies a new config");

    // --- Raw TCP streams (experimental in v0.3) ---
    // One listener per [[stream]]. The upstream is whatever holds the port on
    // loopback; uping neither starts nor watches it.
    if !cfg.streams.is_empty() {
        warn!(
            "[[stream]] is experimental: its config, behaviour and support may change \
             before it is declared stable"
        );
    }
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
        let destination = if !s.upstream.trim().is_empty() {
            s.upstream.trim().to_string()
        } else {
            format!("static:{}", s.root.trim())
        };
        info!("  {} -> {destination}", s.domain);
        for r in &s.routes {
            let destination = if !r.upstream.trim().is_empty() {
                r.upstream.trim().to_string()
            } else {
                format!("static:{}", r.root.trim())
            };
            info!(
                "  {}{} -> {destination}{}",
                s.domain,
                r.prefix(),
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
        && cfg
            .listen
            .http_addrs()
            .unwrap_or_default()
            .into_iter()
            .chain(cfg.listen.https_addrs().unwrap_or_default())
            .chain(https_groups.iter().flat_map(|g| g.addrs.iter().copied()))
            .any(|addr| is_privileged(&addr));
    let privileged_stream = cfg
        .streams
        .iter()
        .filter_map(|s| s.listen.parse::<std::net::SocketAddr>().ok())
        .any(|addr| is_privileged(&addr));
    if privileged_http || privileged_stream {
        warn!(
            "a port below 1024 needs CAP_NET_BIND_SERVICE, not root: \
             `sudo setcap 'cap_net_bind_service=+ep' $(command -v uping)`"
        );
    }

    server.run_forever();
}

/// Does this bind address name a port below 1024?
fn is_privileged(addr: &std::net::SocketAddr) -> bool {
    addr.port() < 1024
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HealthOverride, Server as ConfigServer};
    use crate::proxy::Target;

    fn server(domain: &str, upstream: &str) -> ConfigServer {
        ConfigServer {
            domain: domain.to_string(),
            https_listen: String::new(),
            https_listen6: String::new(),
            serve_http: true,
            health: HealthOverride::default(),
            limits: None,
            keys: None,
            pub_key: "certs/test.local.crt".to_string(),
            priv_key: "certs/test.local.key".to_string(),
            upstream: upstream.to_string(),
            upstream_tls: false,
            upstream_sni: String::new(),
            upstream_verify: true,
            upstream_ca: String::new(),
            root: String::new(),
            index: "index.html".to_string(),
            routes: Vec::new(),
        }
    }

    /// A config holding only the parts `build_routes` reads.
    fn config(servers: Vec<ConfigServer>) -> Config {
        Config {
            root_dir: std::env::temp_dir(),
            listen: Default::default(),
            limits: Default::default(),
            tls: Default::default(),
            health: Default::default(),
            acme: Default::default(),
            servers,
            streams: Vec::new(),
        }
    }

    fn upstream(routes: &RouteTable, host: &str, path: &str) -> String {
        match routes.get(host).unwrap().resolve(path).target {
            Target::Proxy(upstream) => upstream.address.to_string(),
            Target::Static(_) => panic!("expected a proxy target for {host}{path}"),
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
    fn the_dns_zone_flag_is_accepted_before_or_after_the_path() {
        for raw in [&["--dns-zone", "a.toml"][..], &["a.toml", "--dns-zone"][..]] {
            let parsed = args(raw).expect("dns-zone flag should parse");
            assert!(parsed.dns_zone);
            assert!(!parsed.check);
            assert_eq!(parsed.path, "a.toml");
        }
    }

    #[test]
    fn check_and_dns_zone_are_mutually_exclusive() {
        assert!(args(&["--check", "--dns-zone", "a.toml"]).is_err());
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
        let routes = RouteTable::from_config(&config(servers)).unwrap();

        assert_eq!(upstream(&routes, "test.local", "/"), "127.0.0.1:8080");
        assert_eq!(upstream(&routes, "api.example.com", "/"), "127.0.0.1:9000");
        assert!(routes.get("Test.Local").is_none());
    }

    #[test]
    fn routes_from_the_config_reach_the_table() {
        let mut s = server("aaa.local", "127.0.0.1:8080");
        s.routes = vec![crate::config::Route {
            path: "/assets/".to_string(),
            upstream: "127.0.0.1:8085".to_string(),
            health: HealthOverride::default(),
            upstream_tls: false,
            upstream_sni: String::new(),
            upstream_verify: true,
            upstream_ca: String::new(),
            root: String::new(),
            index: "index.html".to_string(),
            strip_prefix: true,
        }];
        let routes = RouteTable::from_config(&config(vec![s])).unwrap();

        assert_eq!(routes.route_count(), 1);
        let hit = routes.get("aaa.local").unwrap().resolve("/assets/app.css");
        assert_eq!(hit.strip, Some("/assets"));
        assert_eq!(
            upstream(&routes, "aaa.local", "/assets/app.css"),
            "127.0.0.1:8085"
        );
    }
}
