//! The bad-config corpus for `uping --check`.
//!
//! Every case here is a *parse-time* failure: the class that took uping down on
//! 2026-10-25 (`[[stream]] *:443 listen *:443 is not a IP:port address`) before a
//! single socket existed. Sandboxing cannot catch that class; a validation pass
//! and a corpus can. Each test spawns the real binary, so what is proven is the
//! operator's experience: the exit code and the message they will read at 3 a.m.
//!
//! Fixtures are written under `target/test-configs/` — never `/tmp` (the host
//! policy blocks it) and never `/dev/null`. `target/` is disposable; every run
//! rewrites its own fixtures.
//!
//! Two cases deliberately absent, because today's behaviour is a design decision
//! rather than a bug — see the PR body. Two `[[server]]` with the same `domain`
//! ("last wins", asserted by `later_entries_win_on_duplicate_domains` in
//! `src/main.rs`), and an unknown field, which is silently ignored because no
//! struct carries `deny_unknown_fields`. Both need a ruling before a test pins
//! them.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// `[[server]]` with a usable upstream, used as the base of most fixtures.
const SERVER: &str = r#"
[[server]]
domain   = "test.local"
pub_key  = "certs/test.local.crt"
priv_key = "certs/test.local.key"
upstream = "127.0.0.1:8080"
"#;

fn fixtures() -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-configs");
    std::fs::create_dir_all(&dir).expect("create target/test-configs");
    dir
}

fn write(name: &str, body: &str) -> PathBuf {
    let path = fixtures().join(name);
    std::fs::write(&path, body).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    path
}

/// `uping --check <path>`, captured.
fn check(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uping"))
        .arg("--check")
        .arg(path)
        .output()
        .expect("spawning the uping binary")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A refused config: exit 1, `error: ` first, and the message names the offender.
fn assert_refused(name: &str, body: &str, needle: &str) {
    let path = write(name, body);
    let out = check(&path);
    let err = stderr(&out);

    assert_eq!(
        out.status.code(),
        Some(1),
        "{name}: expected exit 1, stdout: {:?}, stderr: {err}",
        stdout(&out)
    );
    assert!(
        err.starts_with("error: "),
        "{name}: stderr must open with `error: `, got: {err}"
    );
    assert!(
        err.contains(needle),
        "{name}: stderr must name `{needle}`, got: {err}"
    );
    assert!(
        stdout(&out).is_empty(),
        "{name}: a refusal must print nothing on stdout, got: {:?}",
        stdout(&out)
    );
}

/// An accepted config: exit 0 and exactly one summary line on stdout.
fn assert_accepted(name: &str, body: &str) -> String {
    let path = write(name, body);
    let out = check(&path);
    let err = stderr(&out);
    let ok = stdout(&out);

    assert_eq!(
        out.status.code(),
        Some(0),
        "{name}: expected exit 0, stdout: {ok:?}, stderr: {err}"
    );
    assert_eq!(
        ok.lines().count(),
        1,
        "{name}: `--check` prints one line, got: {ok:?}"
    );
    assert!(ok.starts_with("ok: "), "{name}: got: {ok:?}");
    ok
}

/// A self-signed pair written under `target/test-configs/`, minted on first use.
///
/// The repository ships no certificates (CONTRIBUTING.md), so the tests make
/// their own — same approach as the unit tests in `src/tls.rs`, but in the trees
/// the policy allows.
fn cert_pair() -> (String, String) {
    static PAIR: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

    PAIR.get_or_init(|| {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::rsa::Rsa;

        let key = openssl::pkey::PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test.local").unwrap();
        let name = name.build();

        let mut cert = openssl::x509::X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = cert.build();

        let dir = fixtures();
        let cert_path = dir.join("test.local.crt");
        let key_path = dir.join("test.local.key");
        std::fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
        std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        (
            cert_path.display().to_string(),
            key_path.display().to_string(),
        )
    })
    .clone()
}

fn server(domain: &str, upstream: &str) -> String {
    let (cert, key) = cert_pair();
    format!(
        "\n[[server]]\ndomain   = \"{domain}\"\npub_key  = \"{cert}\"\npriv_key = \"{key}\"\nupstream = \"{upstream}\"\n"
    )
}

// ---------------------------------------------------------------------------
// The upstream must name one dialable peer.
// ---------------------------------------------------------------------------

/// The gap STEP 1 measured: before this test, `--check` printed `ok` for a
/// config whose `[[server]]` upstream was not an address at all, so the failure
/// surfaced on the first request instead of at deploy time.
#[test]
fn a_server_upstream_that_is_not_an_address_is_refused() {
    assert_refused(
        "upstream-not-an-addr.toml",
        &SERVER.replace("127.0.0.1:8080", "not-an-addr"),
        "not-an-addr",
    );
}

/// `*:443` is a listener. In the upstream slot it means "connect to every
/// interface", which is not an address — the 2026-10-25 failure, other half.
#[test]
fn a_wildcard_upstream_is_refused() {
    assert_refused(
        "upstream-wildcard.toml",
        &SERVER.replace("127.0.0.1:8080", "*:443"),
        "`*` is a listen address",
    );
}

/// An IPv6 literal needs brackets: `::1:443` has no port, `[::1]:443` has one.
#[test]
fn an_unbracketed_ipv6_upstream_is_refused() {
    assert_refused(
        "upstream-v6-bare.toml",
        &SERVER.replace("127.0.0.1:8080", "::1:443"),
        "::1:443",
    );
}

#[test]
fn a_port_above_65535_is_refused() {
    assert_refused(
        "upstream-port-70000.toml",
        &SERVER.replace("127.0.0.1:8080", "127.0.0.1:70000"),
        "bad port `70000`",
    );
}

/// Port 0 on an upstream is never a service. On a listener it would silently
/// bind an ephemeral port, which is the same class of surprise.
#[test]
fn port_zero_is_refused_in_both_slots() {
    assert_refused(
        "upstream-port-0.toml",
        &SERVER.replace("127.0.0.1:8080", "127.0.0.1:0"),
        "port 0",
    );
    assert_refused(
        "listen-port-0.toml",
        "[[stream]]\nlisten = \"0.0.0.0:0\"\nupstream = \"127.0.0.1:10025\"\n",
        "port 0",
    );
}

#[test]
fn a_missing_upstream_is_refused() {
    assert_refused(
        "upstream-missing.toml",
        &SERVER.replace("upstream = \"127.0.0.1:8080\"", "upstream = \"\""),
        "empty `upstream`",
    );
}

/// A hostname is not a bind address: only an IP can be listened on.
#[test]
fn a_hostname_in_a_listen_slot_is_refused() {
    assert_refused(
        "listen-hostname.toml",
        "[[stream]]\nlisten = \"smtp.example:443\"\nupstream = \"127.0.0.1:10025\"\n",
        "smtp.example:443",
    );
}

// ---------------------------------------------------------------------------
// Two listeners cannot share a socket.
// ---------------------------------------------------------------------------

#[test]
fn two_streams_on_one_port_are_refused() {
    assert_refused(
        "stream-duplicate-listen.toml",
        "[[stream]]\nname = \"a\"\nlisten = \"0.0.0.0:2525\"\nupstream = \"127.0.0.1:10025\"\n\
         \n[[stream]]\nname = \"b\"\nlisten = \"*:2525\"\nupstream = \"127.0.0.1:10026\"\n",
        "clashes with [[stream]]",
    );
}

// ---------------------------------------------------------------------------
// The rest of the load path.
// ---------------------------------------------------------------------------

#[test]
fn an_empty_pub_key_is_refused() {
    assert_refused(
        "empty-pub-key.toml",
        &SERVER.replace("certs/test.local.crt", ""),
        "empty `pub_key`",
    );
}

#[test]
fn an_empty_file_is_refused() {
    assert_refused("empty.toml", "", "no [[server]] or [[stream]]");
}

#[test]
fn two_global_routes_that_overlap_in_hosts_are_refused() {
    let (cert, key) = cert_pair();
    let body = format!(
        "\n[[server]]\ndomain = \"a.example\"\npub_key = \"{cert}\"\npriv_key = \"{key}\"\nupstream = \"127.0.0.1:8080\"\n\
         \n[[server]]\ndomain = \"b.example\"\npub_key = \"{cert}\"\npriv_key = \"{key}\"\nupstream = \"127.0.0.1:8090\"\n\
         \n[[route]]\npath = \"/api\"\nupstream = \"127.0.0.1:9001\"\nhosts = [\"a.example\"]\n\
         \n[[route]]\npath = \"/api\"\nupstream = \"127.0.0.1:9002\"\n",
    );
    assert_refused("global-overlap.toml", &body, "overlap");
}

/// The failure only the flag can catch: a config that parses but whose
/// certificate cannot be read. Nothing here touches the network.
#[test]
fn an_unreadable_certificate_is_refused() {
    assert_refused(
        "cert-missing.toml",
        &SERVER.replace("certs/test.local.crt", "/nonexistent/nope.crt"),
        "reading cert",
    );
}

#[test]
fn a_certificate_that_is_not_a_certificate_is_refused() {
    let (_, key) = cert_pair();
    let junk = fixtures().join("junk.crt");
    std::fs::write(&junk, b"-----BEGIN CERTIFICATE-----\nnot base64\n").unwrap();
    let body = format!(
        "\n[[server]]\ndomain = \"test.local\"\npub_key = \"{}\"\npriv_key = \"{key}\"\nupstream = \"127.0.0.1:8080\"\n",
        junk.display()
    );
    assert_refused("cert-junk.toml", &body, "parsing cert");
}

// ---------------------------------------------------------------------------
// The green side: a valid config must pass, or the corpus means nothing.
// ---------------------------------------------------------------------------

/// The exact shape that died on 2026-10-25: `[[stream]] listen = "*:443"`.
///
/// No `[[server]]` here, so nothing terminates TLS and the shorthand is the only
/// thing under test. `--check` binds nothing, so the privileged port is not a
/// failure — only the serving path warns about `CAP_NET_BIND_SERVICE`.
#[test]
fn a_wildcard_stream_listen_is_accepted() {
    let ok = assert_accepted(
        "good-wildcard-stream.toml",
        "[[stream]]\nname = \"https-pipe\"\nlisten = \"*:443\"\nupstream = \"127.0.0.1:10443\"\n",
    );
    assert!(
        ok.starts_with("ok: 0 [[server]], 1 [[stream]], 0 route(s)"),
        "got: {ok:?}"
    );
}

/// A config a real operator would write, path first and `--check` last.
#[test]
fn a_realistic_three_server_config_is_accepted() {
    let body = format!(
        "[listen]\nhttp  = \"*:80\"\nhttps = \"*:443\"\n{}{}{}\
         \n[[server.route]]\npath = \"/mcp\"\nupstream = \"127.0.0.1:8081\"\n\
         \n[[route]]\npath = \"/api\"\nupstream = \"127.0.0.1:9001\"\nhosts = [\"b.example\"]\n\
         \n[[stream]]\nname = \"smtp\"\nlisten = \"0.0.0.0:2525\"\nupstream = \"127.0.0.1:10025\"\n",
        server("a.example", "127.0.0.1:8080"),
        server("b.example", "127.0.0.1:8090"),
        server("c.example", "127.0.0.1:8095"),
    );
    let path = write("good-three-servers.toml", &body);

    // `uping <path> --check` must behave exactly like `uping --check <path>`.
    let out = Command::new(env!("CARGO_BIN_EXE_uping"))
        .arg(&path)
        .arg("--check")
        .output()
        .expect("spawning the uping binary");

    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {:?}, stderr: {}",
        stdout(&out),
        stderr(&out)
    );
    let ok = stdout(&out);
    assert!(
        ok.starts_with("ok: 3 [[server]], 1 [[stream]], 2 route(s)"),
        "got: {ok:?}"
    );
    assert_eq!(ok.lines().count(), 1, "one line, got: {ok:?}");
}
