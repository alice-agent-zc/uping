//! End-to-end checks against the real `uping` binary.
//!
//! The unit tests in `src/stream.rs` drive the `ServerApp` entry point directly.
//! These spawn the compiled binary with a stream-only config, so what is proven
//! here is the whole chain: config load, `Service::add_tcp`, pingora's accept
//! loop, the forwarder, and the log lines an operator will grep.
//!
//! High ports only: no root on the box that runs this.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Kills the server even when an assertion fails, so no test leaves a listener.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn temp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("uping-e2e-{}-{name}", std::process::id()));
    p
}

/// A port that was bound and is now closed: connecting to it is refused.
fn closed_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
}

/// Start the binary on `cfg` and wait until it reports the listener is up.
fn start(cfg: &Path, log: &Path) -> Server {
    let exe = env!("CARGO_BIN_EXE_uping");
    let out = std::fs::File::create(log).unwrap();
    let err = out.try_clone().unwrap();
    let child = Command::new(exe)
        .arg(cfg)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawning the uping binary");
    let server = Server(child);

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if std::fs::read_to_string(log)
            .map(|s| s.contains("listening on"))
            .unwrap_or(false)
        {
            return server;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!(
        "uping never reported its listener; log:\n{}",
        std::fs::read_to_string(log).unwrap_or_default()
    );
}

/// Wait until `log` holds `needle`, and return the whole file.
fn wait_for_line(log: &Path, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        if text.contains(needle) {
            return text;
        }
        if Instant::now() >= deadline {
            panic!("never saw `{needle}` in:\n{text}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Echo everything back, and on client EOF say one last word before closing.
fn echo_with_drain(listener: TcpListener) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        loop {
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if sock.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
        let _ = sock.write_all(b"DRAINED");
    })
}

fn client(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    let _ = s.set_nodelay(true);
    s
}

#[test]
fn the_binary_forwards_a_raw_stream_and_drains_a_half_close() {
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let upstream = echo_with_drain(echo);

    let front = TcpListener::bind("127.0.0.1:0").unwrap();
    let front_addr = front.local_addr().unwrap();
    drop(front);

    let cfg_path = temp_path("stream.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "[[stream]]\nname = \"e2e\"\nlisten = \"127.0.0.1:{}\"\nupstream = \"{}\"\n\
             connect_timeout_ms = 2000\n",
            front_addr.port(),
            echo_addr
        ),
    )
    .unwrap();
    let log = temp_path("stream.log");

    let _server = start(&cfg_path, &log);

    let mut c = client(front_addr);
    c.write_all(b"hello").unwrap();
    let mut back = [0u8; 5];
    c.read_exact(&mut back).unwrap();
    assert_eq!(&back, b"hello", "the greeting did not come back");

    // 200 bytes, one write each: nothing may assume they coalesce.
    for i in 0..200u8 {
        c.write_all(&[i]).unwrap();
    }
    let mut dribble = [0u8; 200];
    c.read_exact(&mut dribble).unwrap();
    assert_eq!(dribble.to_vec(), (0..200u8).collect::<Vec<u8>>());

    // Half-close, then keep reading: the upstream writes its marker only after
    // it sees the EOF, so this fails unless the drain is forwarded.
    c.shutdown(std::net::Shutdown::Write).unwrap();
    let mut tail = Vec::new();
    c.read_to_end(&mut tail).unwrap();
    assert_eq!(tail, b"DRAINED");

    let text = wait_for_line(&log, "bytes to upstream");
    assert!(
        text.contains("205 bytes to upstream, 212 bytes back"),
        "unexpected byte counts:\n{text}"
    );

    let _ = std::fs::remove_file(&cfg_path);
    let _ = std::fs::remove_file(&log);
    upstream.join().unwrap();
}

#[test]
fn a_dead_upstream_releases_the_client_with_one_log_line() {
    let dead = closed_port();

    let front = TcpListener::bind("127.0.0.1:0").unwrap();
    let front_addr = front.local_addr().unwrap();
    drop(front);

    let cfg_path = temp_path("dead.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "[[stream]]\nname = \"smtp\"\nlisten = \"127.0.0.1:{}\"\nupstream = \"{dead}\"\n\
             connect_timeout_ms = 500\n",
            front_addr.port()
        ),
    )
    .unwrap();
    let log = temp_path("dead.log");

    let _server = start(&cfg_path, &log);

    let mut c = client(front_addr);
    let started = Instant::now();
    let mut buf = [0u8; 16];
    let n = c.read(&mut buf).unwrap();
    let elapsed = started.elapsed();

    assert_eq!(n, 0, "the client must see EOF");
    assert!(
        elapsed < Duration::from_millis(1000),
        "released after {elapsed:?}, over the 500 ms timeout plus slack"
    );

    let expected =
        format!("stream smtp: upstream {dead} refused: Connection refused (os error 111)");
    let text = std::fs::read_to_string(&log).unwrap();
    let hits: Vec<&str> = text.lines().filter(|l| l.contains(&expected)).collect();
    assert_eq!(hits.len(), 1, "expected exactly one line in:\n{text}");

    eprintln!(
        "dead upstream {dead}: client released in {elapsed:?}; log: {}",
        hits[0]
    );

    let _ = std::fs::remove_file(&cfg_path);
    let _ = std::fs::remove_file(&log);
}
