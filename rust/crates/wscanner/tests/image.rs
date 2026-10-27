//! F12 against a real engine: pull small Alpine and Debian images, export
//! them through `images::packages`, and check what was read and that no
//! container is left behind. Needs docker (or podman) and the network, so it
//! is ignored by default; CI's Linux job runs it with `-- --ignored`.

use std::process::Command;
use wscanner::db::Cache;
use wscanner::images;

fn check(image: &str, eco: &str, package: &str, source: &str) {
    let engine = images::engine().expect("docker or podman");
    let pulled = Command::new(&engine).args(["pull", "-q", image]).status().expect("pull");
    assert!(pulled.success(), "pull {image}");
    let id = images::image_id(&engine, image);
    assert!(!id.is_empty(), "{image} has an id");
    let d = wscanner::system::TempDir::new("image-it").unwrap();
    let cache = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let (pkgs, gaps) = images::packages(&cache, &engine, image, &id, false, false).unwrap();
    assert!(gaps.is_empty(), "{gaps:?}");
    assert!(
        pkgs.iter().any(|p| p.ecosystem == eco && p.name == package && p.source == source),
        "{image}: no {package} in {eco} from {source}: {pkgs:?}"
    );
    let left =
        Command::new(&engine).args(["ps", "-a", "-q", "--filter", &format!("ancestor={image}")]).output().unwrap();
    assert!(String::from_utf8_lossy(&left.stdout).trim().is_empty(), "the exported container is removed");
    // Cached by id: the second read exports nothing.
    let again = images::packages(&cache, &engine, image, &id, false, true).unwrap();
    assert_eq!(again.0.len(), pkgs.len());
}

#[test]
#[ignore]
fn alpine_image() {
    check("alpine:3.20", "Alpine:v3.20", "busybox", "/lib/apk/db/installed");
}

#[test]
#[ignore]
fn debian_image() {
    check("debian:12-slim", "Debian:12", "dpkg", "/var/lib/dpkg/status");
}
