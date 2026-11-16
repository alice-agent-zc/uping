//! Upstream liveness.
//!
//! One background thread probes every distinct backend in the live route table:
//! a TCP connect, plus a TLS handshake when the upstream is HTTPS. A backend is
//! marked down after `[health] failures` consecutive failed probes and up on the
//! first success. A down backend is answered with `503` immediately instead of
//! waiting for a connect timeout.
//!
//! The thread reads the route table each pass, so a SIGHUP reload is followed
//! without extra wiring; `Reloader` also primes the new table synchronously so
//! the first request after a reload never sees an unresolved address.
//!
//! `interval_ms = 0` disables the active probe. The address is still resolved
//! at startup and on reload, and an unresolvable upstream is still `503`.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use log::{info, warn};

use crate::proxy::{RouteTable, Upstream};

struct State {
    addr: Option<SocketAddr>,
    fails: usize,
    up: bool,
    /// When the last probe (or resolver refresh) finished.
    last_probe: Option<Instant>,
}

impl State {
    fn unknown() -> Self {
        Self {
            addr: None,
            fails: 0,
            up: false,
            last_probe: None,
        }
    }
}

pub struct HealthTracker {
    states: Mutex<HashMap<Arc<str>, State>>,
}

impl HealthTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            states: Mutex::new(HashMap::new()),
        })
    }

    /// The last address that resolved, if any.
    pub fn addr(&self, upstream: &Upstream) -> Option<SocketAddr> {
        let states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        states.get(upstream.key()).and_then(|s| s.addr)
    }

    /// Is this backend currently unavailable? An unprobed backend counts as
    /// down; startup and reload prime the table before serving traffic.
    pub fn down(&self, upstream: &Upstream) -> bool {
        if !upstream.health {
            return false;
        }
        let states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        states.get(upstream.key()).map(|s| !s.up).unwrap_or(true)
    }

    /// Probe the whole table once, blocking. Called before the listeners start
    /// and after a reload builds the new table.
    pub fn prime(&self, table: &RouteTable) {
        for upstream in table.upstreams() {
            self.probe(&upstream);
        }
    }

    /// Start the periodic probe thread. It reads the live table on every pass
    /// and checks each backend against its own `health` interval, so one slow
    /// backend can be probed every 30 s while another is checked every 2 s.
    pub fn spawn(self: Arc<Self>, routes: Arc<RwLock<Arc<RouteTable>>>) {
        let thread = std::thread::Builder::new()
            .name("uping-health".into())
            .spawn(move || loop {
                let table = {
                    let live = routes.read().unwrap_or_else(|e| e.into_inner());
                    live.clone()
                };
                let mut tick = Duration::from_secs(60);
                for upstream in table.upstreams() {
                    tick = tick.min(upstream.health_interval);
                    if self.due(&upstream) {
                        self.probe(&upstream);
                    }
                }
                // A no-op config must not turn this into a busy loop. Cap the
                // sleep so a reload that adds a short interval is noticed soon.
                let tick = tick
                    .min(Duration::from_secs(5))
                    .max(Duration::from_millis(50));
                std::thread::sleep(tick);
            });
        if let Err(e) = thread {
            warn!("health: cannot start the probe thread: {e}");
        }
    }

    /// Has this backend's own interval elapsed since its last pass?
    fn due(&self, upstream: &Upstream) -> bool {
        let states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        states
            .get(upstream.key())
            .and_then(|s| s.last_probe)
            .is_none_or(|at| at.elapsed() >= upstream.health_interval)
    }

    fn probe(&self, upstream: &Upstream) {
        let addrs: Vec<SocketAddr> = match upstream.address.to_socket_addrs() {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                self.record(upstream, None, false, Some(&format!("cannot resolve: {e}")));
                return;
            }
        };
        if addrs.is_empty() {
            self.record(upstream, None, false, Some("resolved to no address"));
            return;
        }

        if !upstream.active_probe {
            self.record(upstream, Some(addrs[0]), true, None);
            return;
        }

        let mut last = None;
        for addr in addrs {
            match probe_connect(upstream, addr, upstream.health_timeout) {
                Ok(()) => {
                    self.record(upstream, Some(addr), true, None);
                    return;
                }
                Err(e) => last = Some((addr, e)),
            }
        }
        match last {
            Some((addr, e)) => self.record(upstream, Some(addr), false, Some(&e.to_string())),
            None => self.record(upstream, None, false, Some("no address to try")),
        }
    }

    fn record(
        &self,
        upstream: &Upstream,
        addr: Option<SocketAddr>,
        healthy: bool,
        why: Option<&str>,
    ) {
        let mut states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        let was_known = states.contains_key(upstream.key());
        let state = states
            .entry(upstream.key().clone())
            .or_insert_with(State::unknown);

        // A failed probe keeps the last good address so a still-running backend
        // is dialled again the moment it recovers; a successful one replaces it.
        if let Some(addr) = addr {
            if healthy || state.addr.is_none() {
                state.addr = Some(addr);
            }
        }
        state.last_probe = Some(Instant::now());
        let down = if healthy {
            state.fails = 0;
            false
        } else {
            state.fails += 1;
            state.fails >= upstream.health_failures.max(1) || !upstream.active_probe
        };

        let changed = !was_known || state.up != !down;
        state.up = !down;
        if changed {
            if down {
                warn!(
                    "health: {} is down{}; answering 503",
                    upstream.address,
                    why.map(|w| format!(" ({w})")).unwrap_or_default()
                );
            } else {
                info!("health: {} is up", upstream.address);
            }
        }
    }
}

/// One probe: TCP connect, then a TLS handshake when the backend is HTTPS.
fn probe_connect(upstream: &Upstream, addr: SocketAddr, timeout: Duration) -> io::Result<()> {
    let tcp = TcpStream::connect_timeout(&addr, timeout)?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    if let Some(connector) = &upstream.probe {
        connector
            .connect(&upstream.sni, tcp)
            .map_err(|e| io::Error::other(e.to_string()))?;
    }
    Ok(())
}
