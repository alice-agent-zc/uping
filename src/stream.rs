//! Raw TCP forwarding — the `[[stream]]` listener (v0.2.0).
//!
//! One `[[stream]]` entry binds one port and pipes every byte to one upstream,
//! with no parsing, no TLS termination and no idle timeout. That is what a mail
//! or JMAP port needs: the TLS inside the stream belongs to the mail server, and
//! an IMAP IDLE session is legitimately silent for half an hour.
//!
//! Uping does **not** own the service behind these upstreams. If it is down,
//! the only duty here is to fail fast, say so once, and release the client
//! — the process stays up and every other listener keeps working.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use log::{info, warn};
use pingora::apps::ServerApp;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::config::Stream as StreamConfig;

/// Byte counts for one forwarded connection.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Copied {
    /// Client -> upstream.
    pub to_upstream: u64,
    /// Upstream -> client.
    pub to_client: u64,
}

/// Forward one configured stream to its upstream.
pub struct StreamForwarder {
    label: String,
    upstream: String,
    connect_timeout: Duration,
}

impl StreamForwarder {
    pub fn new(cfg: &StreamConfig) -> Self {
        StreamForwarder {
            label: cfg.label().to_string(),
            upstream: cfg.upstream.trim().to_string(),
            connect_timeout: Duration::from_millis(cfg.connect_timeout_ms),
        }
    }

    /// The label every line about this forwarder carries.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The address bytes are forwarded to.
    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    /// Connect, then copy both directions until both are done.
    ///
    /// A failed or slow connect releases the client after exactly one warning.
    /// `copy_bidirectional` shuts the peer's write half down when one side sends
    /// EOF, so a client that half-closes still receives everything the upstream
    /// has left to say — SMTP and IMAP both depend on that.
    pub async fn relay<C>(&self, mut client: C) -> Copied
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let mut upstream =
            match tokio::time::timeout(self.connect_timeout, TcpStream::connect(&self.upstream))
                .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    let what = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        "refused"
                    } else {
                        "unreachable"
                    };
                    warn!(
                        "stream {}: upstream {} {}: {}",
                        self.label, self.upstream, what, e
                    );
                    return Copied::default();
                }
                Err(_) => {
                    warn!(
                        "stream {}: upstream {} timed out after {} ms",
                        self.label,
                        self.upstream,
                        self.connect_timeout.as_millis()
                    );
                    return Copied::default();
                }
            };

        match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
            Ok((to_upstream, to_client)) => {
                info!(
                    "stream {}: closed, {} bytes to upstream, {} bytes back",
                    self.label, to_upstream, to_client
                );
                Copied {
                    to_upstream,
                    to_client,
                }
            }
            Err(e) => {
                // A client that hangs up mid-transfer is normal, not an alarm.
                info!("stream {}: copy ended: {}", self.label, e);
                Copied::default()
            }
        }
    }
}

#[async_trait]
impl ServerApp for StreamForwarder {
    async fn process_new(
        self: &Arc<Self>,
        session: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let _ = self.relay(session).await;
        // Never reusable: the connection carried one raw stream, and it is done.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Instant;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    use pingora::protocols::l4::stream::Stream as L4Stream;

    fn forwarder(label: &str, upstream: &str, timeout_ms: u64) -> StreamForwarder {
        let cfg = StreamConfig {
            name: label.to_string(),
            listen: "127.0.0.1:0".to_string(),
            upstream: upstream.to_string(),
            connect_timeout_ms: timeout_ms,
        };
        StreamForwarder::new(&cfg)
    }

    /// An upstream that echoes everything, and on client EOF says one last word
    /// before closing — the SMTP/IMAP shape.
    async fn echo_then_drain(marker: &'static [u8]) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
            let _ = sock.write_all(marker).await;
            let _ = sock.shutdown().await;
        });
        addr
    }

    /// Bind the forwarding port and run `StreamForwarder::process_new` on the
    /// first accepted connection, exactly as pingora's accept loop does.
    async fn spawn_forwarder(fwd: Arc<StreamForwarder>) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (_tx, rx) = watch::channel(false);
            // What pingora's accept loop hands to `ServerApp`: the L4 stream,
            // boxed into `protocols::Stream`.
            let session: Stream = Box::new(L4Stream::from(sock));
            fwd.process_new(session, &rx).await;
        });
        addr
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Both directions, including 200 single-byte writes so no coalescing
    /// assumption can hide a bug, then a half-close that must still drain.
    #[test]
    fn bytes_round_trip_both_ways_and_a_half_close_drains_the_upstream() {
        runtime().block_on(async {
            let upstream = echo_then_drain(b"DRAINED").await;
            let fwd = Arc::new(forwarder("echo", &upstream.to_string(), 2000));
            let front = spawn_forwarder(fwd).await;

            let mut client = TcpStream::connect(front).await.unwrap();

            client.write_all(b"hello").await.unwrap();
            let mut back = [0u8; 5];
            client.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"hello");

            // 200 bytes, one syscall each: no request-level framing exists here,
            // so every byte has to survive on its own.
            for i in 0..200u8 {
                client.write_all(&[i]).await.unwrap();
            }
            let mut dribble = [0u8; 200];
            client.read_exact(&mut dribble).await.unwrap();
            let expected: Vec<u8> = (0..200u8).collect();
            assert_eq!(dribble.to_vec(), expected);

            // Half-close the client and keep reading: the upstream writes its
            // marker only after it sees EOF, so this proves the drain.
            client.shutdown().await.unwrap();
            let mut tail = Vec::new();
            client.read_to_end(&mut tail).await.unwrap();
            assert_eq!(tail, b"DRAINED");
        });
    }

    /// A capture logger, so the dead-upstream contract is asserted on the real
    /// log output rather than on a return value.
    static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static LOGGER: CaptureLogger = CaptureLogger;

    struct CaptureLogger;

    impl log::Log for CaptureLogger {
        fn enabled(&self, _m: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            let mut lines = LINES.lock().unwrap();
            lines.push(format!("{}", record.args()));
        }
        fn flush(&self) {}
    }

    fn install_capture_logger() {
        static ONCE: AtomicUsize = AtomicUsize::new(0);
        if ONCE.swap(1, Ordering::SeqCst) == 0 {
            let _ = log::set_logger(&LOGGER);
            log::set_max_level(log::LevelFilter::Info);
        }
    }

    fn captured(filter: &str) -> Vec<String> {
        LINES
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains(filter))
            .cloned()
            .collect()
    }

    /// Nothing listening upstream: the client is released, one line is logged,
    /// and the whole thing takes less than the connect timeout plus slack.
    #[test]
    fn a_dead_upstream_releases_the_client_with_one_log_line() {
        install_capture_logger();
        runtime().block_on(async {
            // Bind then drop, so the port is free and certainly refuses.
            let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dead_addr = dead.local_addr().unwrap();
            drop(dead);

            let label = "dead-upstream-test";
            let fwd = Arc::new(forwarder(label, &dead_addr.to_string(), 500));
            assert_eq!(fwd.label(), label);
            assert_eq!(fwd.upstream(), dead_addr.to_string());

            let front = spawn_forwarder(fwd).await;
            let mut client = TcpStream::connect(front).await.unwrap();

            let started = Instant::now();
            let mut buf = [0u8; 16];
            let n = client.read(&mut buf).await.unwrap();
            let elapsed = started.elapsed();

            assert_eq!(n, 0, "the client must see EOF, not an error or a hang");
            assert!(
                elapsed < Duration::from_millis(500 * 2),
                "took {elapsed:?}, expected well under the 500 ms connect timeout"
            );

            let expected = format!(
                "stream {label}: upstream {dead_addr} refused: Connection refused (os error 111)"
            );
            // The relay logs before it drops the client, but the client's read
            // can win the race; give the task a moment to land its line.
            for _ in 0..50 {
                if !captured(label).is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let lines = captured(label);
            assert_eq!(lines.len(), 1, "expected exactly one line, got {lines:?}");
            assert_eq!(lines[0], expected);
            eprintln!(
                "dead upstream: {elapsed:?} wall clock, log line: {}",
                lines[0]
            );
        });
    }

    /// The clamps live in the config; here we only prove the forwarder honours
    /// the value it is given, so a 1 ms timeout must be applied, not ignored.
    #[test]
    fn the_connect_timeout_is_honoured() {
        install_capture_logger();
        runtime().block_on(async {
            let label = "timeout-test";
            // 10.255.255.1 is blackholed: SYN goes nowhere.
            let fwd = Arc::new(forwarder(label, "10.255.255.1:9", 120));
            let front = spawn_forwarder(fwd).await;
            let mut client = TcpStream::connect(front).await.unwrap();

            let started = Instant::now();
            let mut buf = [0u8; 4];
            let n = client.read(&mut buf).await.unwrap();
            let elapsed = started.elapsed();

            assert_eq!(n, 0);
            assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
            for _ in 0..50 {
                if !captured(label).is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let lines = captured(label);
            assert_eq!(lines.len(), 1, "expected exactly one line, got {lines:?}");
            assert!(
                lines[0].contains("timed out after 120 ms"),
                "unexpected line: {}",
                lines[0]
            );
            eprintln!("blackholed upstream: {elapsed:?}, log line: {}", lines[0]);
        });
    }
}
