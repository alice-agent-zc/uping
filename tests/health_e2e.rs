//! A backend that dies is detected and answered with `503`, then recovers.
//!
//! The probe interval is short so the test never waits on a production default:
//! what is proven is the contract (`/health` state drives the answer), not the
//! five-second cadence.

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use support::*;

/// A stoppable HTTP backend; stopping it frees the port for a restart.
struct Backend {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Backend {
    fn start() -> Self {
        Self::on_port(free_port())
    }

    fn on_port(port: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("binding the backend");
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 2048];
                        let _ = stream.read(&mut buf);
                        let body = "alive";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            stop,
            handle: Some(handle),
        }
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop();
    }
}

fn config(dir: &Path, http: u16, https: u16, backend: u16) -> String {
    let cert = dir.join("health.local.crt");
    let key = dir.join("health.local.key");
    format!(
        "[listen]\nipv4 = \"127.0.0.1\"\nhttp = {http}\nhttps = {https}\n\
         [health]\ninterval_ms = 100\ntimeout_ms = 200\nfailures = 1\n\
         [[server]]\ndomain = \"health.local\"\nkeys = \"manual\"\n\
         pub_key = \"{}\"\npriv_key = \"{}\"\nupstream = \"127.0.0.1:{backend}\"\n",
        cert.display(),
        key.display(),
    )
}

fn wait_for_count(log: &Path, needle: &str, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        if text.matches(needle).count() >= count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "never saw {count} x `{needle}` in:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_dead_backend_is_503_and_recovers_when_it_returns() {
    let dir = workspace("health-e2e");
    let _ = cert_pair(&dir, "health.local");

    let mut backend = Backend::start();
    let port = backend.port;
    let http = free_port();
    let https = free_port();
    let cfg = dir.join("config.toml");
    write(&cfg, &config(&dir, http, https, port));
    let log = dir.join("health.log");
    let mut server = start(&cfg, &log, https);

    wait_for_log(&log, "is up");
    let (status, text) = curl(https, "health.local", "/", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("alive"), "{text}");

    backend.stop();
    wait_for_log(&log, "is down");
    let (status, text) = curl(https, "health.local", "/", &[]);
    assert_eq!(
        status, "503",
        "a down backend must be answered at once: {text}"
    );

    // Same port, same config: the probe sees it come back.
    let backend = Backend::on_port(port);
    wait_for_count(&log, "is up", 2);
    let (status, text) = curl(https, "health.local", "/", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("alive"), "{text}");

    assert!(
        server.is_alive(),
        "server exited:\n{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );

    drop(server);
    drop(backend);
    let _ = std::fs::remove_dir_all(dir);
}

/// The probe must not be fooled by a TCP-only listener: an HTTPS upstream that
/// cannot complete a handshake is down.
#[test]
fn a_plain_tcp_listener_is_not_a_healthy_tls_upstream() {
    let dir = workspace("health-tls-e2e");
    let _ = cert_pair(&dir, "health.local");

    // A raw TCP listener that accepts and says nothing: TCP up, TLS not.
    let raw = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = raw.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in raw.incoming().flatten() {
            held.push(stream);
        }
    });

    let cert = dir.join("health.local.crt");
    let key = dir.join("health.local.key");
    let http = free_port();
    let https = free_port();
    let cfg = dir.join("config.toml");
    write(
        &cfg,
        &format!(
            "[listen]\nipv4 = \"127.0.0.1\"\nhttp = {http}\nhttps = {https}\n\
             [health]\ninterval_ms = 100\ntimeout_ms = 200\nfailures = 1\n\
             [[server]]\ndomain = \"health.local\"\nkeys = \"manual\"\n\
             pub_key = \"{}\"\npriv_key = \"{}\"\nupstream = \"127.0.0.1:{port}\"\n\
             upstream_tls = true\nupstream_sni = \"health.local\"\nupstream_verify = false\n",
            cert.display(),
            key.display(),
        ),
    );
    let log = dir.join("health-tls.log");
    let mut server = start(&cfg, &log, https);

    wait_for_log(&log, "is down");
    let (status, text) = curl(https, "health.local", "/", &[]);
    assert_eq!(status, "503", "{text}");

    assert!(server.is_alive());
    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}
