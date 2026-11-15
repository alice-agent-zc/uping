//! `uping --dns-zone` prints `hosts(5)` records for the resolver.
//!
//! uping does not serve DNS; it renders the names its config already knows so a
//! WireGuard-side dnsmasq/CoreDNS can load them without a second source of truth.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixtures() -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-dns");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(name: &str, body: &str) -> PathBuf {
    let path = fixtures().join(name);
    std::fs::write(&path, body).unwrap();
    path
}

fn run(path: &Path, extra: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_uping"));
    cmd.args(extra).arg(path);
    cmd.output().expect("spawning the uping binary")
}

const TWO: &str = r#"
[listen]
ipv4  = "203.0.113.10"
ipv6  = "2001:db8::1"
http  = 80
https = 443

[server."public.example"]
upstream = "127.0.0.1:8080"

[server."private.example"]
keys     = "manual"
pub_key  = "p.crt"
priv_key = "p.key"
upstream = "127.0.0.1:9000"
listen   = "10.8.0.1"
http     = false
"#;

#[test]
fn dns_zone_emits_one_record_per_domain_and_family() {
    let path = write("two.toml", TWO);
    let out = run(&path, &["--dns-zone"]);
    assert_eq!(out.status.code(), Some(0), "{:?}", out);
    let text = String::from_utf8_lossy(&out.stdout);
    let records: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    assert_eq!(
        records,
        vec![
            "10.8.0.1 private.example",
            "203.0.113.10 public.example",
            "2001:db8::1 public.example",
        ],
        "unexpected records:\n{text}"
    );
}

#[test]
fn dns_zone_refuses_a_wildcard_listener() {
    let path = write(
        "wild.toml",
        "[listen]\nipv4 = \"0.0.0.0\"\nhttp = 80\nhttps = 443\n\
         [[server]]\ndomain = \"public.example\"\nupstream = \"127.0.0.1:8080\"\n",
    );
    let out = run(&path, &["--dns-zone"]);
    assert_eq!(out.status.code(), Some(1), "{:?}", out);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("wildcard"), "{err}");
    assert!(
        out.stdout.is_empty(),
        "a refusal must not print records: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn check_and_dns_zone_cannot_be_combined() {
    let path = write("both.toml", TWO);
    let out = run(&path, &["--check", "--dns-zone"]);
    assert_eq!(out.status.code(), Some(1), "{:?}", out);
    assert!(String::from_utf8_lossy(&out.stderr).contains("pick one"));
}
