//! Live configuration reload on `SIGHUP`.
//!
//! `systemctl --user reload uping` sends `SIGHUP`; we re-read the same config
//! file, validate the whole load path, and swap the pieces that can change
//! without rebinding a socket:
//!
//! * domains, upstreams, static roots, indexes, `[[server.route]]`
//! * request rate, connection rate and body-size limits (counters are kept)
//! * `[tls] fallback_cert`
//! * manual certificates and existing `auto` ones (a new `auto` domain is
//!   requested in the background through the already-running HTTP listener)
//! * which domains each already-bound HTTPS listener may answer
//!
//! A bad config is logged and the running config stays untouched: a typo must
//! not take the proxy down. Listeners and `[[stream]]` forwarders cannot be
//! added to a running Pingora service, and `[acme]` is owned by the renewal
//! thread; those changes are reported as requiring a restart while the rest of
//! the config is applied.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use log::{error, info, warn};
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;

use crate::acme::CertManager;
use crate::config::{Config, GroupKey, KeyMode};
use crate::health::HealthTracker;
use crate::limits::{ConnLimiter, RequestLimiter};
use crate::proxy::RouteTable;
use crate::tls::SniResolver;

/// The parts of a config that cannot be changed under a running process.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pinned {
    http: Vec<SocketAddr>,
    groups: Vec<GroupKey>,
    streams: Vec<(String, String, u64)>,
    acme: String,
}

impl Pinned {
    fn of(cfg: &Config) -> Result<Self> {
        Ok(Self {
            http: cfg.listen.http_addrs()?,
            groups: cfg.https_groups()?.into_iter().map(|g| g.key).collect(),
            streams: cfg
                .streams
                .iter()
                .map(|s| (s.listen.clone(), s.upstream.clone(), s.connect_timeout_ms))
                .collect(),
            acme: format!("{:?}", cfg.acme),
        })
    }
}

/// One running HTTPS listener: the sockets it bound and the domains it may
/// answer. The set is swapped on reload; the sockets are not.
pub type Allowed = Arc<RwLock<Arc<HashSet<String>>>>;

/// Everything the reload thread needs to replace the running config.
pub struct Reloader {
    path: PathBuf,
    routes: Arc<RwLock<Arc<RouteTable>>>,
    resolver: SniResolver,
    certs: Arc<CertManager>,
    request_limiter: Arc<RequestLimiter>,
    conn_limiter: Arc<ConnLimiter>,
    max_body: Arc<AtomicUsize>,
    allow_lists: Vec<(GroupKey, Allowed)>,
    /// Domains with `serve_http = false`, swapped on reload.
    http_disabled: Arc<RwLock<Arc<HashSet<String>>>>,
    /// Shared with the renewal thread; swapped on every successful reload.
    renewal_servers: Arc<RwLock<Vec<crate::config::Server>>>,
    /// Probed before the new route table becomes live.
    health: Arc<HealthTracker>,
    /// One worker issues certificates, so a burst of reloads cannot create a
    /// thread per pending domain. The set de-duplicates domains already queued.
    issue_tx: Mutex<mpsc::Sender<Vec<crate::config::Server>>>,
    issue_rx: Mutex<Option<mpsc::Receiver<Vec<crate::config::Server>>>>,
    in_flight: Arc<Mutex<HashSet<String>>>,
    /// What the running process actually has. Kept even when a reload applies
    /// the rest, so a listener change is still reported as pending.
    pinned: Pinned,
}

impl Reloader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: PathBuf,
        routes: Arc<RwLock<Arc<RouteTable>>>,
        resolver: SniResolver,
        certs: Arc<CertManager>,
        request_limiter: Arc<RequestLimiter>,
        conn_limiter: Arc<ConnLimiter>,
        max_body: Arc<AtomicUsize>,
        allow_lists: Vec<(GroupKey, Allowed)>,
        http_disabled: Arc<RwLock<Arc<HashSet<String>>>>,
        renewal_servers: Arc<RwLock<Vec<crate::config::Server>>>,
        health: Arc<HealthTracker>,
        cfg: &Config,
    ) -> Result<Self> {
        let (issue_tx, issue_rx) = mpsc::channel();
        Ok(Self {
            path,
            routes,
            resolver,
            certs,
            request_limiter,
            conn_limiter,
            max_body,
            allow_lists,
            http_disabled,
            renewal_servers,
            health,
            issue_tx: Mutex::new(issue_tx),
            issue_rx: Mutex::new(Some(issue_rx)),
            in_flight: Arc::new(Mutex::new(HashSet::new())),
            pinned: Pinned::of(cfg)?,
        })
    }

    /// Start the signal thread. `SIGHUP` is not used by Pingora (it handles
    /// QUIT, TERM and INT), so there is no conflict.
    pub fn spawn(self: Arc<Self>) -> Result<()> {
        // Register before the thread starts, so a reload sent immediately after
        // startup cannot hit the default SIGHUP action (terminate).
        let mut signals = Signals::new([SIGHUP]).context("listening for SIGHUP")?;

        let receiver = self
            .issue_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .context("the certificate worker was already started")?;
        let certs = self.certs.clone();
        let in_flight = self.in_flight.clone();
        std::thread::Builder::new()
            .name("uping-acme-queue".into())
            .spawn(move || {
                for batch in receiver {
                    let domains: Vec<String> = batch
                        .iter()
                        .map(|s| s.domain.to_ascii_lowercase())
                        .collect();
                    certs.obtain_missing_live(&batch);
                    let mut in_flight = in_flight.lock().unwrap_or_else(|e| e.into_inner());
                    for domain in domains {
                        in_flight.remove(&domain);
                    }
                }
            })
            .context("starting the certificate worker")?;

        std::thread::Builder::new()
            .name("uping-reload".into())
            .spawn(move || {
                for _ in signals.forever() {
                    info!("SIGHUP received; reloading configuration");
                    self.reload();
                }
            })
            .context("starting the reload thread")?;
        Ok(())
    }

    fn reload(&self) {
        if let Err(e) = self.try_reload() {
            error!("reload failed, keeping the running configuration: {e:#}");
        }
    }

    fn try_reload(&self) -> Result<()> {
        let new = Config::load(&self.path)
            .with_context(|| format!("reading `{}`", self.path.display()))?;
        if new.deprecated_server_map {
            warn!(
                "the `[server.\"domain\"]` map form is deprecated; use `[[server]]` with \
                 `domain = \"...\"` instead"
            );
        }
        let next = Pinned::of(&new)?;
        let running = self.pinned.clone();

        // The renewal thread owns the account and certificate directory. Mixing
        // a new `[acme]` with the old thread would write certificates to one
        // place and read them from another, so refuse the whole reload.
        if running.acme != next.acme {
            anyhow::bail!("`[acme]` changes require a restart of the service");
        }
        if running.http != next.http {
            warn!(
                "`[listen] http` changes require a restart; keeping the running listener. \
                 The rest of this reload is applied."
            );
        }
        if running.groups != next.groups {
            warn!(
                "adding, removing or moving `listen`/`listen6` HTTPS listeners require a \
                 restart; keeping the running sockets. The rest of this reload is applied."
            );
        }
        if running.streams != next.streams {
            warn!(
                "`[[stream]]` changes require a restart; keeping the running forwarders. \
                 The rest of this reload is applied."
            );
        }

        // Build and validate the whole candidate before touching live state.
        let (candidate, pending) =
            SniResolver::from_config(&new).context("loading TLS certificates")?;
        let routes = RouteTable::from_config(&new).context("building the route table")?;
        let route_count = routes.route_count();
        let groups = new.https_groups().context("grouping the HTTPS listeners")?;

        // A listener that already exists picks up its new domain set. A group
        // that only appears in the new config has no socket until a restart, so
        // its domains stay unanswered; the warning above said so. A group the
        // new config no longer names keeps its old set on purpose: the running
        // socket is still there until the restart, and its routes decide what
        // actually exists.
        let disabled: HashSet<String> = new
            .servers
            .iter()
            .filter(|s| !s.serve_http)
            .map(|s| s.domain.to_ascii_lowercase())
            .collect();
        *self
            .http_disabled
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Arc::new(disabled);

        for (key, allowed) in &self.allow_lists {
            if let Some(group) = groups.iter().find(|g| &g.key == key) {
                let domains: HashSet<String> = group.domains.iter().cloned().collect();
                *allowed.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(domains);
            }
        }

        self.resolver.adopt(&candidate);
        // Resolve/probe the new backends before they can receive a request.
        self.health.prime(&routes);
        {
            let mut live = self.routes.write().unwrap_or_else(|e| e.into_inner());
            *live = Arc::new(routes);
        }
        *self
            .renewal_servers
            .write()
            .unwrap_or_else(|e| e.into_inner()) = new.servers.clone();
        self.request_limiter.set_budget(new.limits.per_ip_rps);
        self.conn_limiter
            .set_budget(new.limits.per_ip_conns_per_sec);
        self.max_body
            .store(new.limits.max_body_bytes, Ordering::Relaxed);

        let pending_count = pending.len();
        let mut to_issue = Vec::new();
        {
            let mut in_flight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
            for server in pending {
                let domain = server.domain.to_ascii_lowercase();
                if in_flight.insert(domain) {
                    to_issue.push(server);
                }
            }
        }

        if !to_issue.is_empty() {
            let domains: Vec<String> = to_issue.iter().map(|s| s.domain.clone()).collect();
            info!(
                "reload: queueing certificate request(s) for {}",
                domains.join(", ")
            );
            let queued: Vec<String> = to_issue
                .iter()
                .map(|s| s.domain.to_ascii_lowercase())
                .collect();
            let sent = self
                .issue_tx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .send(to_issue);
            if let Err(e) = sent {
                warn!("reload: the certificate worker is gone: {e}");
                let mut in_flight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
                for domain in queued {
                    in_flight.remove(&domain);
                }
            }
        } else if pending_count > 0 {
            info!("reload: certificate request(s) already in progress");
        }

        info!(
            "configuration reloaded: {} [[server]], {route_count} route(s), \
             {} conn/s and {} req/s per IP",
            new.servers.len(),
            new.limits.per_ip_conns_per_sec,
            new.limits.per_ip_rps
        );
        if new.servers.iter().any(|s| s.key_mode() == KeyMode::Auto) && pending_count == 0 {
            info!("reload: all auto certificates are present on disk");
        }
        Ok(())
    }
}
