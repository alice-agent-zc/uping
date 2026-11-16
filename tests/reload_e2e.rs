//! `SIGHUP` reloads the config without restarting the process.
//!
//! What is proven is the operator contract: change a static root, `kill -HUP`,
//! the new root is served; write invalid TOML, `kill -HUP`, the old config
//! keeps serving and the process is still there; change a listener, the reload
//! says it needs a restart but applies the rest.

mod support;

use std::net::TcpStream;
use std::process::Command;

use support::*;

fn site(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let root = dir.join(name);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("index.html"), body).unwrap();
    root
}

fn config(
    http: u16,
    https: u16,
    cert: &std::path::Path,
    key: &std::path::Path,
    root: &std::path::Path,
) -> String {
    format!(
        "[listen]\nipv4 = \"127.0.0.1\"\nhttp = {http}\nhttps = {https}\n\
         [tls]\nfallback_cert = true\n\
         [[server]]\ndomain = \"reload.local\"\nkeys = \"manual\"\n\
         pub_key = \"{}\"\npriv_key = \"{}\"\nroot = \"{}\"\n",
        cert.display(),
        key.display(),
        root.display()
    )
}

fn hup(pid: u32) {
    let status = Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .status()
        .expect("kill -HUP");
    assert!(status.success(), "kill -HUP {pid} failed");
}

#[test]
fn a_sighup_applies_a_new_root_and_a_bad_config_changes_nothing() {
    let dir = workspace("reload-e2e");
    let (cert, key) = cert_pair(&dir, "reload.local");
    let one = site(&dir, "site-one", "one");
    let two = site(&dir, "site-two", "two");
    let three = site(&dir, "site-three", "three");

    let http = free_port();
    let https = free_port();
    let cfg = dir.join("config.toml");
    write(&cfg, &config(http, https, &cert, &key, &one));
    let log = dir.join("reload.log");
    let mut server = start(&cfg, &log, https);
    let pid = server.pid();

    let (status, text) = curl(https, "reload.local", "/", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("one"), "{text}");

    // A normal reload: new static root, same listener.
    write(&cfg, &config(http, https, &cert, &key, &two));
    hup(server.pid());
    wait_for_log(&log, "configuration reloaded");
    let (status, text) = curl(https, "reload.local", "/", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("two"), "reload served the old root: {text}");

    // Invalid TOML: the running config must survive.
    write(&cfg, "this is not = = toml");
    hup(server.pid());
    wait_for_log(&log, "reload failed");
    let (status, text) = curl(https, "reload.local", "/", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(
        text.ends_with("two"),
        "a bad reload changed the root: {text}"
    );
    assert!(server.is_alive(), "a bad reload killed the process");

    // A listener change cannot be applied live: it warns, applies the rest,
    // and keeps the old listener.
    let other_https = free_port();
    write(&cfg, &config(http, other_https, &cert, &key, &three));
    hup(server.pid());
    wait_for_log(&log, "require a restart");
    let (status, text) = curl(https, "reload.local", "/", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(
        text.ends_with("three"),
        "the rest of the reload was not applied: {text}"
    );
    assert!(
        TcpStream::connect(("127.0.0.1", other_https)).is_err(),
        "a listener change must not bind the new port without a restart"
    );

    assert_eq!(pid, server.pid(), "the process must not be replaced");
    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}
