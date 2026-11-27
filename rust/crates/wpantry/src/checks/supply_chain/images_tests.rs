use super::*;
use crate::checks::Options;
use crate::checks::supply_chain::testing;
use crate::utils::temp::TempDir;
use std::path::Path;
use std::time::{Duration, Instant};

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

// ---- an engine that is installed but does not answer ----

/// Short limits so the suite stays fast: the same code paths as the real
/// 5 s probe and 20 s inspect, with the real constants asserted below.
const FAST: Timeouts = Timeouts { probe: Duration::from_millis(400), inspect: Duration::from_millis(400) };

/// A stand-in engine named `name`, recording every call (its arguments, one
/// line each) in `calls.txt` beside it. `version` is the shell it runs for
/// the probe; `inspect` is `case` arms over the image ref for `image
/// inspect`. `create`, `export` and `rm` behave as in
/// [`crate::checks::machine::images::testing::engine`]. A hang is
/// `exec sleep 30`.
fn stand_in(dir: &Path, name: &str, version: &str, inspect: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh\nd=\"$(dirname \"$0\")\"\necho \"$*\" >> \"$d/calls.txt\"\ncase \"$1\" in\n\
             version) {version} ;;\n\
             image) ref=\"$5\"; case \"$ref\" in {inspect} esac ;;\n\
             create) echo cid123 ;;\n\
             export) cp \"$d/rootfs.tar\" \"$3\" ;;\n\
             rm) ;;\n\
             esac\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

const HANG: &str = "exec sleep 30";
const PULLED: &str = "echo sha256:0123456789abcdef0123456789abcdef";

fn calls(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("calls.txt")).unwrap_or_default().lines().map(str::to_string).collect()
}

/// Six refs from a Dockerfile and a compose file, none duplicated.
fn six(d: &TempDir) -> Vec<Repo> {
    let (name, root) = testing::repo(d, "app");
    testing::write(&root, "Dockerfile", "FROM alpine:3.20\nFROM debian:12 AS build\n");
    testing::write(
        &root,
        "docker-compose.yml",
        "services:\n  a:\n    image: nginx:1.27\n  b:\n    image: postgres:16\n  c:\n    image: redis:7\n  d:\n    image: ubuntu:24.04\n",
    );
    vec![(name, root)]
}

fn only_gap(s: &Scan) -> (String, String) {
    assert_eq!(testing::unchecked(s).len(), 1, "one gap: {:?}", s.findings);
    let f = s.findings.iter().find(|f| f.kind == "unchecked").unwrap();
    (f.component.clone(), f.note.clone())
}

/// Hung on everything: one probe, no per-ref calls, one gap that names the
/// engine and the count, within the bound, and no finding.
#[cfg(unix)]
#[test]
fn a_hung_engine_costs_one_probe_and_one_gap() {
    let d = TempDir::new("images-hung").unwrap();
    let engine = stand_in(d.path(), "docker", HANG, &format!("*) {HANG} ;;"));
    let net = testing::osv_net(&[]);
    let mut s = testing::scan(&net, &d, Options::default());
    let repos = six(&d);
    let start = Instant::now();
    images_with_limits(&mut s, &repos, Some(engine), FAST).unwrap();
    assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
    assert_eq!(calls(d.path()), ["version --format {{.Server.Version}}"]);
    let (what, note) = only_gap(&s);
    assert_eq!(what, "container images");
    assert!(
        note.starts_with("docker is installed but is not answering (no answer within 1 s)")
            && note.contains("6 image refs the repos name were not checked"),
        "{note}"
    );
    assert_eq!(s.findings.len(), 1, "the gap and nothing else: {:?}", s.findings);
}

/// The probe answers, the second ask hangs: the loop stops there (no third
/// ask), and the gap counts the refs left, the hung one included. The first
/// ref's "No such image" is an absence, the hang is not.
#[cfg(unix)]
#[test]
fn an_engine_that_stops_answering_part_way_stops_the_loop() {
    let d = TempDir::new("images-stops").unwrap();
    let inspect = format!("alpine:3.20) echo 'Error: No such image: alpine:3.20' >&2; exit 1 ;; *) {HANG} ;;");
    let engine = stand_in(d.path(), "docker", "echo 27.0.1", &inspect);
    let net = testing::osv_net(&[]);
    let mut s = testing::scan(&net, &d, Options::default());
    let repos = six(&d);
    let start = Instant::now();
    images_with_limits(&mut s, &repos, Some(engine), FAST).unwrap();
    assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
    assert_eq!(
        calls(d.path()),
        [
            "version --format {{.Server.Version}}",
            "image inspect --format {{.Id}} alpine:3.20",
            "image inspect --format {{.Id}} debian:12"
        ]
    );
    let (what, note) = only_gap(&s);
    assert_eq!(what, "container images");
    assert_eq!(
        note,
        "docker stopped answering after 1 of 6 image refs (asking about debian:12 timed out after 1 s); 5 not checked"
    );
}

/// The daemon is down and says so at once: no inspect calls, the engine's
/// own words in the gap.
#[cfg(unix)]
#[test]
fn an_engine_that_cannot_reach_its_daemon_is_one_gap() {
    let d = TempDir::new("images-down").unwrap();
    let down = "echo 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?' >&2; exit 1";
    let engine = stand_in(d.path(), "docker", down, &format!("*) {PULLED} ;;"));
    let net = testing::osv_net(&[]);
    let mut s = testing::scan(&net, &d, Options::default());
    let repos = six(&d);
    let start = Instant::now();
    images_with_limits(&mut s, &repos, Some(engine), Timeouts::default()).unwrap();
    assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
    assert_eq!(calls(d.path()), ["version --format {{.Server.Version}}"]);
    let (_, note) = only_gap(&s);
    assert!(note.contains("Cannot connect to the Docker daemon") && note.contains("6 image refs"), "{note}");
}

/// No engine: nothing asked, nothing recorded; and an engine with no refs to
/// check is not asked either (a repo scan without images costs nothing).
#[cfg(unix)]
#[test]
fn no_engine_or_no_refs_asks_nothing() {
    let d = TempDir::new("images-none").unwrap();
    let net = testing::osv_net(&[]);
    let mut s = testing::scan(&net, &d, Options::default());
    let repos = six(&d);
    images_with_limits(&mut s, &repos, None, FAST).unwrap();
    assert!(s.findings.is_empty());
    let engine = stand_in(d.path(), "docker", HANG, &format!("*) {HANG} ;;"));
    images_with_limits(&mut s, &[], Some(engine), FAST).unwrap();
    assert!(s.findings.is_empty() && calls(d.path()).is_empty(), "{:?}", calls(d.path()));
}

/// Healthy: one image pulled (read through create, export, rm), one the
/// engine says it has not (skipped, no gap), in order, after one probe.
#[cfg(unix)]
#[test]
fn a_healthy_engine_reads_what_is_pulled_and_skips_what_is_not() {
    for (name, absent) in [
        ("docker", "echo 'Error response from daemon: No such image: nginx:1.27' >&2; exit 1"),
        ("podman", "echo 'Error: nginx:1.27: image not known' >&2; exit 125"),
    ] {
        let d = TempDir::new("images-healthy").unwrap();
        let archive = crate::checks::machine::images::testing::tar(&[
            ("usr/lib/os-release", b'0', "", b"ID=debian\nVERSION_ID=\"12\"\n"),
            (
                "var/lib/dpkg/status",
                b'0',
                "",
                b"Package: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.11-1~deb12u2\n",
            ),
        ]);
        std::fs::write(d.path().join("rootfs.tar"), archive).unwrap();
        let engine = stand_in(d.path(), name, "echo 27.0.1", &format!("debian:12) {PULLED} ;; *) {absent} ;;"));
        let net = testing::osv_net(&[("Debian:12", "openssl")]);
        let mut s = testing::scan(&net, &d, Options::default());
        let (rname, root) = testing::repo(&d, "app");
        testing::write(&root, "Dockerfile", "FROM debian:12\nFROM nginx:1.27\n");
        images_with_limits(&mut s, &[(rname, root)], Some(engine), FAST).unwrap();
        // Each ref is asked, then read before the next is asked.
        let got = calls(d.path());
        assert_eq!(got.len(), 6, "{name}: {got:?}");
        assert_eq!(
            [&got[0], &got[1], &got[2], &got[4], &got[5]],
            [
                "version --format {{.Server.Version}}",
                "image inspect --format {{.Id}} debian:12",
                "create --pull=never debian:12 wpantry-export",
                "rm -f cid123",
                "image inspect --format {{.Id}} nginx:1.27"
            ],
            "{name}"
        );
        assert!(got[3].starts_with("export -o ") && got[3].ends_with(" cid123"), "{name}: {got:?}");
        assert!(s.counts.contains(&("image packages".to_string(), 1)), "{name}: {:?}", s.counts);
        assert_eq!(testing::by_id(&s, "GHSA-openssl").len(), 1, "{name}");
        assert!(testing::unchecked(&s).is_empty(), "{name}: not pulled is not a gap: {:?}", s.findings);
    }
}

/// podman that does not answer is named as podman.
#[cfg(unix)]
#[test]
fn a_hung_podman_is_named_in_the_gap() {
    let d = TempDir::new("images-podman").unwrap();
    let engine = stand_in(d.path(), "podman", HANG, &format!("*) {HANG} ;;"));
    let net = testing::osv_net(&[]);
    let mut s = testing::scan(&net, &d, Options::default());
    let repos = six(&d);
    images_with_limits(&mut s, &repos, Some(engine), FAST).unwrap();
    let (_, note) = only_gap(&s);
    assert!(note.starts_with("podman is installed but is not answering"), "{note}");
    assert_eq!(calls(d.path()).len(), 1);
}

/// An error that is not "no such image" is never read as "not pulled": the
/// ref is a gap of its own (and the other refs are still asked, since the
/// engine answered).
#[cfg(unix)]
#[test]
fn an_inspect_error_is_a_gap_for_that_ref_not_an_absence() {
    let d = TempDir::new("images-error").unwrap();
    let inspect = "alpine:3.20) echo 'permission denied while trying to connect' >&2; exit 1 ;; *) echo 'Error: No such image' >&2; exit 1 ;;";
    let engine = stand_in(d.path(), "docker", "echo 27.0.1", inspect);
    let net = testing::osv_net(&[]);
    let mut s = testing::scan(&net, &d, Options::default());
    let repos = six(&d);
    images_with_limits(&mut s, &repos, Some(engine), FAST).unwrap();
    assert_eq!(testing::unchecked(&s), ["image alpine:3.20"]);
    assert!(s.findings[0].note.contains("permission denied"), "{}", s.findings[0].note);
    assert_eq!(calls(d.path()).len(), 7, "the probe and all six refs");
}

/// The real limits: a probe of a few seconds, an inspect of 20 s, which the
/// timed tests above shorten.
#[test]
fn the_default_limits_are_the_documented_ones() {
    let t = Timeouts::default();
    assert_eq!((t.probe, t.inspect), (Duration::from_secs(5), Duration::from_secs(20)));
}

/// Risk: a machine scan with no repo that names an image probes the engine,
/// and when Docker Desktop is closed records a gap that "0 image refs were
/// not checked" on every scan of the laptop: noise about nothing. Oracle:
/// with no repo refs the engine is asked only for its running containers
/// (no `version` probe), and a daemon that is down (so nothing runs) leaves
/// no gap. A running container is still read.
/// Known bad: the probe and its gap ahead of the listing.
#[cfg(unix)]
#[test]
fn a_machine_scan_with_no_refs_does_not_probe_or_record_a_gap() {
    use std::os::unix::fs::PermissionsExt;
    let d = TempDir::new("images-norefs").unwrap();
    let down = "echo 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock.' >&2; exit 1";
    let engine = d.path().join("docker");
    std::fs::write(
        &engine,
        format!(
            "#!/bin/sh\necho \"$*\" >> \"$(dirname \"$0\")/calls.txt\"\ncase \"$1\" in version|ps) {down} ;; esac\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
    let net = testing::osv_net(&[]);
    let mut s = testing::scan(&net, &d, Options { machine: true, ..Default::default() });
    images_with_limits(&mut s, &[], Some(engine), FAST).unwrap();
    assert!(s.findings.is_empty(), "{:?}", s.findings);
    assert_eq!(calls(d.path()), ["ps --format {{.Image}}"]);
}

/// Risk: the engine's stderr goes into the gap note as it is, and docker and
/// podman name their socket and config under the home directory, so the
/// report carries the user's home path. Oracle: the note has the engine's
/// words with the home directory as `~`, and no home path.
#[cfg(unix)]
#[test]
fn the_engine_s_words_in_a_gap_name_the_home_directory_as_tilde() {
    let home = crate::utils::files::test_home();
    let h = crate::utils::files::home().display().to_string();
    let d = TempDir::new("images-home").unwrap();
    let down = format!("echo 'Cannot connect to the Docker daemon at unix://{h}/.docker/run/docker.sock.' >&2; exit 1");
    let engine = stand_in(d.path(), "docker", &down, &format!("*) {PULLED} ;;"));
    let net = testing::osv_net(&[]);
    let mut s = testing::scan(&net, &d, Options::default());
    images_with_limits(&mut s, &six(&d), Some(engine), FAST).unwrap();
    let (_, note) = only_gap(&s);
    assert!(note.contains("unix://~/.docker/run/docker.sock"), "{note}");
    assert!(!note.contains(&h), "{note}");
    drop(home);
}
