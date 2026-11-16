//! One real first start against a throwaway ACME CA.
//!
//! The CA is a few dozen lines of JSON over a loopback socket: enough of
//! RFC 8555 for `instant-acme` to create an account, place an order, publish an
//! http-01 token, fetch it back from uping's temporary challenge listener, and
//! hand back a certificate. What is proven is the part unit tests cannot reach:
//! the binary's first-start path writes `cert/<domain>/{fullchain,privkey}.pem`
//! and then starts its HTTPS listener on the result.
//!
//! No Let's Encrypt, no network, no root.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openssl::ssl::{SslAcceptor, SslMethod};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn cert_pem() -> String {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::rsa::Rsa;

    let key = openssl::pkey::PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "acme.local").unwrap();
    let name = name.build();

    let mut cert = openssl::x509::X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(90).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    String::from_utf8(cert.build().to_pem().unwrap()).unwrap()
}

/// CA + `localhost` leaf, and an acceptor that presents the chain. The test
/// trusts the CA through `[acme] ca_bundle`, exactly as a private ACME server
/// would be configured.
fn tls_material(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    };
    use openssl::x509::{X509NameBuilder, X509};

    let ca_key = openssl::pkey::PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut ca_name = X509NameBuilder::new().unwrap();
    ca_name.append_entry_by_text("CN", "uping test CA").unwrap();
    let ca_name = ca_name.build();

    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    ca.set_subject_name(&ca_name).unwrap();
    ca.set_issuer_name(&ca_name).unwrap();
    ca.set_pubkey(&ca_key).unwrap();
    ca.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    ca.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    )
    .unwrap();
    ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca = ca.build();

    let leaf_key = openssl::pkey::PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut leaf_name = X509NameBuilder::new().unwrap();
    leaf_name.append_entry_by_text("CN", "localhost").unwrap();
    let leaf_name = leaf_name.build();

    let mut leaf = X509::builder().unwrap();
    leaf.set_version(2).unwrap();
    leaf.set_subject_name(&leaf_name).unwrap();
    leaf.set_issuer_name(&ca_name).unwrap();
    leaf.set_pubkey(&leaf_key).unwrap();
    leaf.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    leaf.set_not_after(&Asn1Time::days_from_now(20).unwrap())
        .unwrap();
    let ctx = leaf.x509v3_context(Some(&ca), None);
    let mut san = SubjectAlternativeName::new();
    san.dns("localhost").ip("127.0.0.1");
    leaf.append_extension(san.build(&ctx).unwrap()).unwrap();
    leaf.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let leaf = leaf.build();

    let ca_path = dir.join("ca.pem");
    let chain_path = dir.join("server-chain.pem");
    let key_path = dir.join("server.key");
    std::fs::write(&ca_path, ca.to_pem().unwrap()).unwrap();
    let mut chain = leaf.to_pem().unwrap();
    chain.extend_from_slice(&ca.to_pem().unwrap());
    std::fs::write(&chain_path, chain).unwrap();
    std::fs::write(&key_path, leaf_key.private_key_to_pem_pkcs8().unwrap()).unwrap();

    (ca_path, chain_path, key_path)
}

fn acceptor(chain: &Path, key: &Path) -> Arc<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder.set_certificate_chain_file(chain).unwrap();
    builder
        .set_private_key_file(key, openssl::ssl::SslFiletype::PEM)
        .unwrap();
    builder.check_private_key().unwrap();
    Arc::new(builder.build())
}

struct State {
    http: SocketAddr,
    verified: bool,
    finalized: bool,
    key_authorization: Option<String>,
    cert: String,
}

struct FakeCa {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    running: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FakeCa {
    fn start(http: SocketAddr, acceptor: Arc<SslAcceptor>, cert: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            http,
            verified: false,
            finalized: false,
            key_authorization: None,
            cert,
        }));
        let running = Arc::new(AtomicBool::new(true));
        let thread_state = state.clone();
        let thread_running = running.clone();

        let thread = std::thread::spawn(move || {
            while thread_running.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        match acceptor.accept(stream) {
                            Ok(tls) => handle(tls, &addr, &thread_state),
                            Err(e) => eprintln!("fake CA: TLS handshake failed: {e}"),
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            state,
            running,
            thread: Some(thread),
        }
    }
}

impl Drop for FakeCa {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn handle<S: Read + Write>(mut stream: S, addr: &SocketAddr, state: &Arc<Mutex<State>>) {
    let Some((method, path)) = read_request(&mut stream) else {
        return;
    };
    let base = format!("https://localhost:{}", addr.port());
    let nonce = "test-replay-nonce";

    let (status, content_type, body, location) = match (method.as_str(), path.as_str()) {
        ("GET", "/directory") | ("POST", "/directory") => (
            200,
            "application/json",
            format!(
                r#"{{"newNonce":"{base}/nonce","newAccount":"{base}/new-account","newOrder":"{base}/order","revokeCert":"{base}/revoke","keyChange":"{base}/key-change"}}"#
            ),
            None,
        ),
        ("HEAD", "/nonce") | ("GET", "/nonce") => (200, "text/plain", String::new(), None),
        ("POST", "/new-account") => (
            201,
            "application/json",
            r#"{"status":"valid"}"#.to_string(),
            Some(format!("{base}/account/1")),
        ),
        ("POST", "/order") => (
            201,
            "application/json",
            order_json(&base),
            Some(format!("{base}/order/1")),
        ),
        ("POST", "/authz/1") => {
            let verified = state.lock().unwrap().verified;
            (200, "application/json", authz_json(&base, verified), None)
        }
        ("POST", "/chall/1") => {
            // The CA's one real job: fetch the token from the listener under
            // test. A failure here is the bug this test exists to catch.
            let token = "uping-test-token";
            let expected = format!("/.well-known/acme-challenge/{token}");
            let fetched = fetch_challenge(state.lock().unwrap().http, &expected);
            let mut locked = state.lock().unwrap();
            locked.verified = fetched
                .as_deref()
                .is_some_and(|body| !body.trim().is_empty());
            locked.key_authorization = fetched;
            (
                200,
                "application/json",
                format!(
                    r#"{{"type":"http-01","url":"{base}/chall/1","status":"processing","token":"{token}"}}"#
                ),
                None,
            )
        }
        ("POST", "/finalize/1") => {
            let mut locked = state.lock().unwrap();
            if locked.verified {
                locked.finalized = true;
                (
                    200,
                    "application/json",
                    format!(
                        r#"{{"status":"valid","identifiers":[{{"type":"dns","value":"acme.local"}}],"authorizations":["{base}/authz/1"],"finalize":"{base}/finalize/1","certificate":"{base}/cert/1"}}"#
                    ),
                    None,
                )
            } else {
                (
                    400,
                    "application/problem+json",
                    r#"{"type":"urn:ietf:params:acme:error:unauthorized","detail":"challenge was never fetched"}"#.to_string(),
                    None,
                )
            }
        }
        ("POST", "/order/1") => {
            let locked = state.lock().unwrap();
            let body = if locked.finalized {
                format!(
                    r#"{{"status":"valid","identifiers":[{{"type":"dns","value":"acme.local"}}],"authorizations":["{base}/authz/1"],"finalize":"{base}/finalize/1","certificate":"{base}/cert/1"}}"#
                )
            } else if locked.verified {
                format!(
                    r#"{{"status":"ready","identifiers":[{{"type":"dns","value":"acme.local"}}],"authorizations":["{base}/authz/1"],"finalize":"{base}/finalize/1"}}"#
                )
            } else {
                order_json(&base)
            };
            (200, "application/json", body, None)
        }
        ("POST", "/cert/1") => {
            let cert = state.lock().unwrap().cert.clone();
            (200, "application/pem-certificate-chain", cert, None)
        }
        _ => (
            404,
            "application/problem+json",
            r#"{"type":"urn:ietf:params:acme:error:malformed","detail":"no such resource"}"#
                .to_string(),
            None,
        ),
    };

    let mut response = format!(
        "HTTP/1.1 {status} x\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nReplay-Nonce: {nonce}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(location) = location {
        response.push_str(&format!("Location: {location}\r\n"));
    }
    response.push_str("\r\n");
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

fn order_json(base: &str) -> String {
    format!(
        r#"{{"status":"pending","identifiers":[{{"type":"dns","value":"acme.local"}}],"authorizations":["{base}/authz/1"],"finalize":"{base}/finalize/1"}}"#
    )
}

fn authz_json(base: &str, valid: bool) -> String {
    let status = if valid { "valid" } else { "pending" };
    format!(
        r#"{{"identifier":{{"type":"dns","value":"acme.local"}},"status":"{status}","challenges":[{{"type":"http-01","url":"{base}/chall/1","status":"{status}","token":"uping-test-token"}}],"wildcard":false}}"#
    )
}

fn fetch_challenge(addr: SocketAddr, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: acme.local\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    let text = String::from_utf8_lossy(&response);
    if !text.starts_with("HTTP/1.1 200") {
        return None;
    }
    let (_, body) = text.split_once("\r\n\r\n")?;
    Some(body.to_string())
}

fn read_request<S: Read>(stream: &mut S) -> Option<(String, String)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_headers_end(&buf) {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            let mut lines = head.lines();
            let mut first = lines.next()?.split_whitespace();
            let method = first.next()?.to_string();
            let path = first.next()?.split('?').next()?.to_string();
            let mut headers = HashMap::new();
            for line in lines {
                if let Some((name, value)) = line.split_once(':') {
                    headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
                }
            }
            let length = headers
                .get("content-length")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let mut body = buf[end + 4..].to_vec();
            while body.len() < length {
                let n = stream.read(&mut chunk).ok()?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(length);
            let _ = body;
            return Some((method, path));
        }
    }
    None
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

#[test]
fn a_first_start_requests_and_stores_a_certificate() {
    let http = free_port();
    let https = free_port();
    let http_addr: SocketAddr = format!("127.0.0.1:{http}").parse().unwrap();

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("acme-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (ca_path, chain, key) = tls_material(&dir);
    let ca = FakeCa::start(http_addr, acceptor(&chain, &key), cert_pem());

    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "[listen]\nipv4 = \"127.0.0.1\"\nhttp = {http}\nhttps = {https}\n\
             [acme]\ndirectory = \"https://localhost:{}/directory\"\n\
             ca_bundle = \"{}\"\nemail = \"ops@acme.local\"\n\
             [[server]]\ndomain = \"acme.local\"\nupstream = \"127.0.0.1:9\"\n",
            ca.addr.port(),
            ca_path.display()
        ),
    )
    .unwrap();

    let log = dir.join("acme.log");
    let out = std::fs::File::create(&log).unwrap();
    let err = out.try_clone().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_uping"))
        .arg(&cfg)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawning the uping binary");
    let server = Server(child);

    let cert_path = dir.join("cert/acme.local/fullchain.pem");
    let key_path = dir.join("cert/acme.local/privkey.pem");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        let installed = text.contains("certificate for acme.local installed");
        if cert_path.is_file() && key_path.is_file() && installed {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        cert_path.is_file() && key_path.is_file(),
        "the certificate pair was not written; log:\n{text}"
    );
    let cert = std::fs::read_to_string(&cert_path).unwrap();
    assert!(cert.contains("BEGIN CERTIFICATE"), "{cert}");
    let key = std::fs::read_to_string(&key_path).unwrap();
    assert!(key.contains("PRIVATE KEY"), "{key}");

    let state = ca.state.lock().unwrap();
    assert!(
        state.verified,
        "the CA never fetched a valid challenge; log:\n{text}"
    );
    assert!(
        state
            .key_authorization
            .as_deref()
            .is_some_and(|body| body.contains("uping-test-token.")),
        "unexpected key authorization: {:?}",
        state.key_authorization
    );
    drop(state);

    // The account credentials are persisted for the next renewal.
    assert!(
        std::fs::read_dir(dir.join("cert"))
            .unwrap()
            .flatten()
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("acme-account-")),
        "no ACME account file was stored"
    );

    assert!(
        text.contains("certificate for acme.local installed"),
        "log:\n{text}"
    );

    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}
