//! Abuse protection.
//!
//! Two layers, both keyed by client IP:
//!
//! * [`ConnLimiter`] runs at the TCP level, *before* the TLS handshake, and
//!   drops connections that exceed a per-IP connections-per-second budget.
//!   Rejecting here is the cheapest possible defence: no handshake, no
//!   HTTP parsing, no allocation.
//! * [`RequestLimiter`] runs once a request has been parsed and answers
//!   `429 Too Many Requests` when a client IP exceeds its requests-per-second
//!   budget.
//!
//! Both use [`pingora_limits::rate::Rate`], which is a bounded-memory
//! estimator: it keeps a fixed 1024-slot table regardless of how many distinct
//! client IPs show up. That matters — a plain `HashMap<IpAddr, _>` would itself
//! be a memory-exhaustion vector for an attacker who controls a large IP range.
//!
//! Windows are one second wide and reset on a fixed boundary, so a client
//! straddling a boundary can briefly reach twice its budget. That is the same
//! trade-off Pingora's own rate-limiting example makes, and it is fine for
//! stopping a flood.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use log::debug;
use pingora::listeners::ConnectionFilter;
use pingora_limits::rate::Rate;

/// Length of the fixed window every limit is counted over.
const WINDOW: Duration = Duration::from_secs(1);

/// Per-IP HTTP request limiter. A budget of `0` disables it.
pub struct RequestLimiter {
    rate: Rate,
    max_per_window: usize,
}

impl RequestLimiter {
    pub fn new(max_per_window: usize) -> Self {
        Self {
            rate: Rate::new(WINDOW),
            max_per_window,
        }
    }

    /// Count this request and report whether it is within budget.
    pub fn check(&self, ip: &IpAddr) -> bool {
        if self.max_per_window == 0 {
            return true;
        }
        let seen = self.rate.observe(ip, 1);
        seen <= self.max_per_window as isize
    }

    /// The configured budget, for logging.
    pub fn budget(&self) -> usize {
        self.max_per_window
    }
}

/// Per-IP TCP connection limiter, applied before the TLS handshake.
pub struct ConnLimiter {
    rate: Rate,
    max_per_window: usize,
}

impl ConnLimiter {
    pub fn new(max_per_window: usize) -> Self {
        Self {
            rate: Rate::new(WINDOW),
            max_per_window,
        }
    }

    /// Count this connection and report whether it is within budget.
    fn allow(&self, ip: &IpAddr) -> bool {
        if self.max_per_window == 0 {
            return true;
        }
        let seen = self.rate.observe(ip, 1);
        seen <= self.max_per_window as isize
    }
}

// `Rate` is not `Debug`, but `ConnectionFilter: Debug` requires it.
impl std::fmt::Debug for ConnLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnLimiter")
            .field("max_per_window", &self.max_per_window)
            .finish()
    }
}

#[async_trait]
impl ConnectionFilter for ConnLimiter {
    async fn should_accept(&self, addr: Option<&SocketAddr>) -> bool {
        // No peer address means we cannot attribute the connection; let it in
        // rather than fail closed on an accounting gap.
        let Some(addr) = addr else {
            return true;
        };
        let allowed = self.allow(&addr.ip());
        if !allowed {
            debug!(
                "dropping connection from {} (over {} conn/s)",
                addr.ip(),
                self.max_per_window
            );
        }
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn a_zero_budget_disables_the_request_limiter() {
        let limiter = RequestLimiter::new(0);
        for _ in 0..10_000 {
            assert!(limiter.check(&ip(1)));
        }
    }

    #[test]
    fn the_request_limiter_lets_the_budget_through_then_refuses() {
        let limiter = RequestLimiter::new(3);
        assert!(limiter.check(&ip(1)));
        assert!(limiter.check(&ip(1)));
        assert!(limiter.check(&ip(1)));
        assert!(!limiter.check(&ip(1)));
    }

    #[test]
    fn request_budgets_are_per_ip() {
        let limiter = RequestLimiter::new(1);
        assert!(limiter.check(&ip(1)));
        assert!(!limiter.check(&ip(1)));
        // a different client is unaffected
        assert!(limiter.check(&ip(2)));
    }

    #[test]
    fn a_zero_budget_disables_the_connection_limiter() {
        let limiter = ConnLimiter::new(0);
        for _ in 0..10_000 {
            assert!(limiter.allow(&ip(1)));
        }
    }

    #[test]
    fn the_connection_limiter_refuses_past_the_budget() {
        let limiter = ConnLimiter::new(2);
        assert!(limiter.allow(&ip(1)));
        assert!(limiter.allow(&ip(1)));
        assert!(!limiter.allow(&ip(1)));
    }

    #[test]
    fn connection_budgets_are_per_ip() {
        let limiter = ConnLimiter::new(1);
        assert!(limiter.allow(&ip(1)));
        assert!(!limiter.allow(&ip(1)));
        assert!(limiter.allow(&ip(2)));
    }
}
