use super::testing::{header, tar};
use super::*;

#[test]
fn reads_an_exported_debian_image() {
    let d = TempDir::new("untar").unwrap();
    let pax_name = "app/node_modules/x/package-lock.json";
    let pax_rec = format!("{} path={pax_name}\n", pax_name.len() + 9);
    let archive = tar(&[
        ("usr/lib/os-release", b'0', "", b"ID=debian\nVERSION_ID=\"12\"\n"),
        ("etc/os-release", b'2', "../usr/lib/os-release", b""),
        ("var/lib/dpkg/status", b'0', "", b"Package: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.11-1~deb12u2\n"),
        ("srv/app/Cargo.lock", b'0', "", b"version = 4\n[[package]]\nname = \"itoa\"\nversion = \"1.0.9\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"),
        ("../escape/Cargo.lock", b'0', "", b"x"),
        ("etc/evil", b'2', "/../../outside", b""),
        ("pax", b'x', "", pax_rec.as_bytes()),
        ("ignored", b'0', "", b"{}"),
        ("usr/bin/tool", b'0', "", &[1, 2, 3]),
    ]);
    let t = d.path().join("rootfs.tar");
    std::fs::write(&t, archive).unwrap();
    let root = d.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    untar(&t, &root).unwrap();
    assert!(!d.path().join("escape").exists(), "paths outside the root are ignored");
    assert!(!root.join("app/node_modules").exists(), "dependency directories are pruned, as in a repo walk");
    assert!(!root.join("usr/bin/tool").exists(), "only the files the extractors read are kept");
    let (pkgs, gaps) = read_root(&root);
    let got: Vec<(String, String, String, String)> =
        pkgs.into_iter().map(|p| (p.ecosystem, p.name, p.version, p.source)).collect();
    assert_eq!(
        got,
        [
            ("Debian:12".into(), "openssl".into(), "3.0.11-1~deb12u2".into(), "/var/lib/dpkg/status".into()),
            ("crates.io".into(), "itoa".into(), "1.0.9".into(), "/srv/app/Cargo.lock".into()),
        ]
    );
    assert!(gaps.is_empty(), "{gaps:?}");
}

#[test]
fn the_kernel_in_an_image_is_the_hosts() {
    let pkg = |name: &str, source: &str| ImagePackage {
        ecosystem: "Debian:12".into(),
        name: name.into(),
        version: "6.1.176-1".into(),
        source: source.into(),
    };
    assert!(host_kernel(&pkg("linux", "/var/lib/dpkg/status")));
    assert!(!host_kernel(&pkg("libssh2", "/var/lib/dpkg/status")));
    assert!(!host_kernel(&pkg("linux", "/srv/app/package-lock.json")), "an npm package named linux is not the kernel");
}

#[test]
fn a_cut_short_export_is_an_error_not_an_empty_image() {
    let d = TempDir::new("untar").unwrap();
    let whole = tar(&[("var/lib/dpkg/status", b'0', "", b"Package: x\nStatus: install ok installed\nVersion: 1\n")]);
    for cut in [vec![65u8; 23], whole[..512].to_vec(), whole[..whole.len() - 1024].to_vec(), Vec::new()] {
        let t = d.path().join("cut.tar");
        std::fs::write(&t, &cut).unwrap();
        let root = d.path().join(format!("root{}", cut.len()));
        std::fs::create_dir_all(&root).unwrap();
        assert!(matches!(untar(&t, &root), Err(Error::Invalid(_))), "{} bytes", cut.len());
    }
}

/// Python keeps osv-scanner's result at `image:<id>` (`packages` is a
/// count there); Rust neither reads it nor trusts an entry of the wrong
/// shape under its own key.
#[test]
fn python_and_malformed_cache_entries_are_not_read_as_an_empty_image() {
    let d = TempDir::new("imgcache").unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    c.put_run("image:sha256:1", "sha256:1", &json!({"packages": 1, "vulnerable": []})).unwrap();
    let no_engine = Path::new("/nonexistent/docker");
    assert!(packages(&c, no_engine, "x", "sha256:1", false, true).is_err(), "offline, nothing of ours cached");
    c.put_run("image-packages:sha256:1", "sha256:1", &json!({"packages": 1})).unwrap();
    assert!(packages(&c, no_engine, "x", "sha256:1", false, true).is_err());
    assert!(packages(&c, no_engine, "x", "sha256:1", false, false).is_err(), "rereads, and can't");
}

/// The rarer header shapes: a ustar prefix, GNU long names and links,
/// a pax linkpath, a base-256 size, a hard link and an absolute symlink
/// (both resolved inside the root), directories and other kinds skipped.
#[test]
fn long_names_links_and_other_kinds() {
    let d = TempDir::new("untar-shapes").unwrap();
    let status = b"Package: zlib1g\nStatus: install ok installed\nSource: zlib\nVersion: 1:1.2.13.dfsg-1\n";
    let rel = b"ID=debian\nVERSION_ID=\"12\"\n";
    let mut a = Vec::new();
    // ustar prefix + name; a directory entry first.
    a.extend(header("var/lib/dpkg", b'5', "", 0, ""));
    a.extend(header("status", b'0', "", status.len(), "var/lib/dpkg"));
    a.extend(status);
    a.extend(vec![0u8; 512 - status.len()]);
    // A GNU long name ('L') followed by the entry it names.
    let long = "usr/lib/os-release";
    a.extend(header("././@LongLink", b'L', "", long.len() + 1, ""));
    a.extend(long.as_bytes());
    a.extend(vec![0u8; 512 - long.len()]);
    a.extend(header("short", b'0', "", rel.len(), ""));
    a.extend(rel);
    a.extend(vec![0u8; 512 - rel.len()]);
    // A hard link to it, named with a `./` component in the middle.
    a.extend(header("etc/./os-release", b'1', "usr/lib/os-release", 0, ""));
    // A GNU long link ('K') naming an absolute symlink target.
    let target = "/usr/lib/os-release";
    a.extend(header("././@LongLink", b'K', "", target.len() + 1, ""));
    a.extend(target.as_bytes());
    a.extend(vec![0u8; 512 - target.len()]);
    a.extend(header("lib/apk/db/installed", b'2', "", 0, ""));
    // A pax linkpath for a symlink that escapes the root: dropped.
    let pax = "26 linkpath=../../outside\n";
    a.extend(header("pax", b'x', "", pax.len(), ""));
    a.extend(pax.as_bytes());
    a.extend(vec![0u8; 512 - pax.len()]);
    a.extend(header("srv/Cargo.lock", b'2', "", 0, ""));
    // A hard link to a file the archive doesn't hold: nothing to copy.
    a.extend(header("srv/package-lock.json", b'1', "missing/package-lock.json", 0, ""));
    // A base-256 size (the high bit set) on a file that isn't wanted.
    let mut big = header("usr/bin/tool", b'0', "", 0, "");
    big[124..136].copy_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
    a.extend(big);
    a.extend([1, 2, 3]);
    a.extend(vec![0u8; 509]);
    a.extend([0u8; 1024]);
    let t = d.path().join("rootfs.tar");
    std::fs::write(&t, &a).unwrap();
    let root = d.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    untar(&t, &root).unwrap();
    assert_eq!(std::fs::read(root.join("var/lib/dpkg/status")).unwrap(), status, "the ustar prefix joins the name");
    assert_eq!(std::fs::read(root.join("usr/lib/os-release")).unwrap(), rel, "the long name wins over 'short'");
    assert_eq!(std::fs::read(root.join("etc/os-release")).unwrap(), rel, "a hard link is a copy");
    assert_eq!(std::fs::read(root.join("lib/apk/db/installed")).unwrap(), rel, "an absolute symlink, from the root");
    assert!(!root.join("srv/Cargo.lock").exists(), "a link out of the root is dropped");
    assert!(!root.join("srv/package-lock.json").exists(), "a link to nothing is nothing");
    assert!(!root.join("usr/bin/tool").exists() && !root.join("short").exists());
    assert!(!d.path().join("outside").exists());
    let (pkgs, gaps) = read_root(&root);
    assert_eq!(pkgs.len(), 1, "{pkgs:?}");
    assert_eq!((pkgs[0].name.as_str(), pkgs[0].version.as_str()), ("zlib", "1:1.2.13.dfsg-1"));
    assert!(gaps.is_empty(), "{gaps:?}");
}

#[test]
fn an_oversized_extension_header_is_refused() {
    let d = TempDir::new("untar-ext").unwrap();
    let mut a = Vec::new();
    a.extend(header("pax", b'x', "", (1 << 20) + 1, ""));
    a.extend([0u8; 1024]);
    let t = d.path().join("rootfs.tar");
    std::fs::write(&t, &a).unwrap();
    let err = untar(&t, d.path()).unwrap_err();
    assert!(matches!(&err, Error::Invalid(m) if m.contains("oversized")), "{err}");
}

/// What read_root can't read is a gap, named: an OS database without a
/// release OSV knows, a release without a database, a lockfile that
/// won't parse.
#[test]
fn what_cannot_be_read_is_a_named_gap() {
    let d = TempDir::new("root-empty").unwrap();
    assert_eq!(read_root(d.path()), (Vec::new(), Vec::new()), "an empty root: nothing, and no gap");
    let d = TempDir::new("root-gaps").unwrap();
    let root = d.path();
    std::fs::create_dir_all(root.join("var/lib/dpkg")).unwrap();
    std::fs::write(root.join("var/lib/dpkg/status"), "Package: x\nStatus: install ok installed\nVersion: 1\n").unwrap();
    let (pkgs, gaps) = read_root(root);
    assert!(pkgs.is_empty());
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    assert!(gaps[0].starts_with("OS packages: "), "{gaps:?}");

    let d = TempDir::new("root-gaps").unwrap();
    let root = d.path();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::create_dir_all(root.join("app")).unwrap();
    std::fs::write(root.join("etc/os-release"), "ID=arch\n").unwrap();
    std::fs::write(root.join("app/Cargo.lock"), "[[package]\nname = \n").unwrap();
    let (pkgs, gaps) = read_root(root);
    assert!(pkgs.is_empty());
    assert_eq!(gaps.len(), 2, "{gaps:?}");
    assert!(gaps[0].contains("no dpkg or apk database (arch images"), "{gaps:?}");
    assert!(gaps[1].starts_with("/app/Cargo.lock: "), "{gaps:?}");
}

/// The engine's answers: an id (with or without its `sha256:` prefix),
/// nothing that isn't hex, nothing when inspect fails, nothing when the
/// engine can't run.
#[cfg(unix)]
#[test]
fn the_image_id_is_the_engines_hex_answer() {
    let d = TempDir::new("image-id").unwrap();
    let engine = testing::engine(d.path());
    assert_eq!(image_id(&engine, "debian:12"), "sha256:0123456789abcdef0123456789abcdef");
    std::fs::write(d.path().join("inspect.txt"), "WARNING: x\n0123456789abcdef\n").unwrap();
    assert_eq!(image_id(&engine, "debian:12"), "0123456789abcdef", "the last line");
    std::fs::write(d.path().join("inspect.txt"), "Error: no such image\n").unwrap();
    assert_eq!(image_id(&engine, "debian:12"), "");
    std::fs::write(d.path().join("inspect.txt"), "sha256:0123456789abcdef0123456789abcdef\n").unwrap();
    std::fs::write(d.path().join("inspect.code"), "1").unwrap();
    assert_eq!(image_id(&engine, "debian:12"), "", "an id printed by a failing inspect doesn't count");
    assert_eq!(image_id(Path::new("/nonexistent/docker"), "debian:12"), "");
}

/// create, export, read, cache: the packages come from the export, the
/// container is removed afterwards (also when the export fails), and
/// the result is reused offline by image id.
#[cfg(unix)]
#[test]
fn packages_are_exported_through_the_engine_and_cached() {
    let d = TempDir::new("image-pkgs").unwrap();
    let engine = testing::engine(d.path());
    let archive = tar(&[
        ("etc/os-release", b'0', "", b"ID=alpine\nVERSION_ID=3.20.1\n"),
        ("lib/apk/db/installed", b'0', "", b"P:musl\nV:1.2.5-r0\n\nP:busybox\nV:1.36.1-r29\n\n"),
    ]);
    std::fs::write(d.path().join("rootfs.tar"), archive).unwrap();
    let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let (pkgs, gaps) = packages(&c, &engine, "alpine:3.20", "sha256:abc", false, false).unwrap();
    let got: Vec<(String, String, String, String)> =
        pkgs.into_iter().map(|p| (p.ecosystem, p.name, p.version, p.source)).collect();
    assert_eq!(
        got,
        [
            ("Alpine:v3.20".into(), "busybox".into(), "1.36.1-r29".into(), "/lib/apk/db/installed".into()),
            ("Alpine:v3.20".into(), "musl".into(), "1.2.5-r0".into(), "/lib/apk/db/installed".into()),
        ]
    );
    assert!(gaps.is_empty(), "{gaps:?}");
    assert_eq!(std::fs::read_to_string(d.path().join("removed.txt")).unwrap().trim(), "cid123");
    // Cached by id: offline, with the engine gone, the same answer.
    let (again, _) = packages(&c, Path::new("/nonexistent/docker"), "alpine:3.20", "sha256:abc", false, true).unwrap();
    assert_eq!(again.len(), 2);
    // Failures name the engine and its last stderr line; the container
    // created before a failed export is still removed.
    std::fs::remove_file(d.path().join("removed.txt")).unwrap();
    std::fs::write(d.path().join("export.fail"), "").unwrap();
    let err = packages(&c, &engine, "alpine:3.20", "sha256:def", false, false).unwrap_err();
    assert_eq!(err.to_string(), format!("{} export failed: Error: export broke", engine.display()));
    assert_eq!(std::fs::read_to_string(d.path().join("removed.txt")).unwrap().trim(), "cid123");
    std::fs::write(d.path().join("create.fail"), "").unwrap();
    let err = packages(&c, &engine, "alpine:3.20", "sha256:def", false, false).unwrap_err();
    assert_eq!(err.to_string(), format!("{} create alpine:3.20 failed: Error: No such image", engine.display()));
    assert!(matches!(err, Error::Failed(_)));
    assert!(packages(&c, Path::new("/nonexistent/docker"), "x", "sha256:def", false, false).is_err());
}

#[test]
fn paths_and_headers() {
    assert_eq!(inside("./etc/os-release"), Some(PathBuf::from("etc/os-release")));
    assert_eq!(inside("/a/../../b"), None);
    assert_eq!(inside("etc/./x"), Some(PathBuf::from("etc/x")));
    assert_eq!(inside("/./etc/x"), Some(PathBuf::from("etc/x")));
    assert_eq!(octal(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]), 256, "base-256");
    assert_eq!(normalize("etc/../usr/lib/os-release"), Some(PathBuf::from("usr/lib/os-release")));
    assert_eq!(normalize("../../x"), None);
    assert_eq!(octal(b"00000000017\0"), 15);
    assert_eq!(pax(b"29 path=a/very/long/name.txt\n")["path"], "a/very/long/name.txt");
    // Short, oversized and non-UTF-8 records end the parse, never panic.
    assert!(pax(b"1 x").is_empty());
    assert!(pax(b"3 \xff\xfe=1\n9 k=v\n").len() <= 1);
    assert!(pax(b"99 path=short\n").is_empty());
}
