use super::*;
use crate::checks::Options;
use crate::checks::supply_chain::testing;
use crate::utils::temp::TempDir;

/// The images the repos build from or run, when the engine has them:
/// exported, read, and their packages asked of OSV; one the engine
/// doesn't have is skipped, one it can't export is unchecked.
#[cfg(unix)]
#[test]
fn images_named_by_the_repos_are_read_through_the_engine() {
    let d = TempDir::new("images").unwrap();
    let engine = crate::checks::machine::images::testing::engine(d.path());
    let archive = crate::checks::machine::images::testing::tar(&[
        ("usr/lib/os-release", b'0', "", b"ID=debian\nVERSION_ID=\"12\"\n"),
        ("var/lib/dpkg/status", b'0', "", b"Package: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.11-1~deb12u2\n\nPackage: linux-libc-dev\nStatus: install ok installed\nSource: linux\nVersion: 6.1.0-1\n"),
    ]);
    std::fs::write(d.path().join("rootfs.tar"), archive).unwrap();
    let net = testing::osv_net(&[("Debian:12", "openssl")]);
    let mut s = testing::scan(&net, &d, Options::default());
    let (name, root) = testing::repo(&d, "app");
    testing::write(&root, "Dockerfile", "FROM debian:12 AS base\nFROM scratch\n");
    testing::write(&root, "docker-compose.yml", "services:\n  cache:\n    image: debian:12\n");
    images_with(&mut s, &[(name.clone(), root.clone())], None).unwrap();
    images(&mut s, &[]).unwrap();
    assert!(s.findings.is_empty() && net.requests().is_empty(), "no engine, or no repos: nothing to read");
    images_with(&mut s, &[(name.clone(), root.clone())], Some(engine.clone())).unwrap();
    assert!(s.counts.contains(&("image packages".to_string(), 1)), "the kernel is the host's: {:?}", s.counts);
    let hit = testing::by_id(&s, "GHSA-openssl");
    assert_eq!(hit.len(), 1, "{:?}", s.findings);
    assert_eq!(
        (
            hit[0].kind.as_str(),
            hit[0].component.as_str(),
            hit[0].version.as_str(),
            hit[0].status.as_str(),
            hit[0].fixed.as_str()
        ),
        ("image", "debian:12 › openssl", "3.0.11-1~deb12u2", "fail", "9.9.9")
    );
    assert_eq!(
        hit[0].fix_cmd,
        format!(
            "docker pull debian:12 (the tag may already carry the fixes); if not, bump it in {}; then rebuild",
            short(&root.join("Dockerfile").to_string_lossy())
        )
    );
    assert!(testing::unchecked(&s).is_empty(), "{:?}", s.findings);
    // An image with no package database is a gap; one the engine can't export is unchecked.
    let d2 = TempDir::new("images-gaps").unwrap();
    let engine = crate::checks::machine::images::testing::engine(d2.path());
    let archive = crate::checks::machine::images::testing::tar(&[("etc/os-release", b'0', "", b"ID=arch\n")]);
    std::fs::write(d2.path().join("rootfs.tar"), archive).unwrap();
    let mut s = testing::scan(&net, &d2, Options::default());
    images_with(&mut s, &[(name.clone(), root.clone())], Some(engine.clone())).unwrap();
    assert_eq!(testing::unchecked(&s), ["image debian:12"]);
    assert!(s.findings[0].note.contains("no dpkg or apk database"), "{}", s.findings[0].note);
    std::fs::write(d2.path().join("create.fail"), "").unwrap();
    let mut s = testing::scan(&net, &d2, Options { refresh: true, ..Default::default() });
    images_with(&mut s, &[(name.clone(), root.clone())], Some(engine.clone())).unwrap();
    assert_eq!(testing::unchecked(&s), ["image debian:12"]);
    assert!(s.findings[0].note.contains("create debian:12 failed"), "{}", s.findings[0].note);
    // The engine doesn't have it: skipped, not unchecked.
    std::fs::write(d2.path().join("inspect.code"), "1").unwrap();
    let mut s = testing::scan(&net, &d2, Options { refresh: true, ..Default::default() });
    images_with(&mut s, &[(name, root)], Some(engine)).unwrap();
    assert!(s.findings.is_empty(), "{:?}", s.findings);
}
