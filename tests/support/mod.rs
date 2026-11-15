//! Shared helpers for the integration tests that spawn the real binary.
#![allow(dead_code)]

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct Server {
    child: Child,
}

impl Server {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

pub fn workspace(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A self-signed pair for `domain`, minted at run time.
pub fn cert_pair(dir: &Path, domain: &str) -> (PathBuf, PathBuf) {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::rsa::Rsa;

    let key = openssl::pkey::PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", domain).unwrap();
    let name = name.build();

    let mut cert = openssl::x509::X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = cert.build();

    let cert_path = dir.join(format!("{domain}.crt"));
    let key_path = dir.join(format!("{domain}.key"));
    std::fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
    std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    (cert_path, key_path)
}

/// Start the binary and wait until the HTTPS port accepts a connection.
pub fn start(cfg: &Path, log: &Path, https: u16) -> Server {
    let out = std::fs::File::create(log).unwrap();
    let err = out.try_clone().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_uping"))
        .arg(cfg)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawning the uping binary");
    let server = Server { child };

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", https)).is_ok() {
            return server;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!(
        "uping never bound its HTTPS listener; log:\n{}",
        std::fs::read_to_string(log).unwrap_or_default()
    );
}

/// `curl -sk` through TLS, with `--resolve` for the test hostname.
pub fn curl(port: u16, host: &str, path: &str, extra: &[&str]) -> (String, String) {
    let url = format!("https://{host}:{port}{path}");
    let resolve = format!("{host}:{port}:127.0.0.1");
    let out = Command::new("curl")
        .args(["-sk", "-i", "--resolve", &resolve])
        .args(extra)
        .arg(url)
        .output()
        .expect("curl is needed for the integration tests");
    assert!(
        out.status.success(),
        "curl failed for {path}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let status = text
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    (status, text)
}

pub fn wait_for_log(log: &Path, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        if text.contains(needle) {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "never saw `{needle}` in:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn write(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
}

pub fn socket(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

pub fn write_file(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(contents).unwrap();
}
