use super::*;

#[test]
fn install_kinds_from_paths() {
    let k = |p: &str| kind(Path::new(p));
    assert_eq!(
        k("/Users/x/.local/share/mise/installs/packslip-github-com-waffuruai-pantry/0.2.0/.mise-bins/wpantry"),
        Kind::Mise
    );
    assert_eq!(k("/home/x/.cargo/bin/wpantry"), Kind::Cargo);
    assert_eq!(k("/opt/homebrew/Cellar/wpantry/0.2.0/bin/wpantry"), Kind::Brew);
    assert_eq!(k("/Users/x/.local/share/waffuru/pantry/rust/target/release/wpantry"), Kind::Source);
    assert_eq!(k("/Users/x/.local/bin/wpantry"), Kind::File);
    assert_eq!(k("/usr/local/bin/wpantry"), Kind::File);
}

#[test]
fn release_versions_only() {
    for ok in ["0.2.0", "1.0.0-rc.1", "1.2.3+build.7"] {
        assert!(is_version(ok), "{ok}");
    }
    for bad in ["", "v0.2.0", "0.2", "0.2.0 evil", "0.2.0;rm", "../x", "0.2.0/../../x"] {
        assert!(!is_version(bad), "{bad:?}");
    }
}

#[test]
fn newer_releases_only() {
    assert!(newer("0.2.0", "0.3.0"));
    assert!(newer("0.2.0", "0.2.1"));
    assert!(!newer("0.2.0", "0.2.0"));
    assert!(!newer("0.3.0", "0.2.9"));
    assert!(!newer("0.2.0", ""));
    assert!(!newer("0.2.0", "0.3.0 evil"));
}

#[test]
fn sha256sums_entries() {
    let sums = "abc  other\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  wpantry-universal-apple-darwin\nAAAA *wpantry-x\n";
    assert_eq!(
        sum_for(sums, "wpantry-universal-apple-darwin").as_deref(),
        Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );
    assert_eq!(sum_for(sums, "wpantry-x"), None, "a 4-char hash is not one");
    assert_eq!(sum_for(sums, "missing"), None);
}

#[test]
fn replace_keeps_the_old_binary_and_rolls_back() {
    let d = TempDir::new("replace").unwrap();
    let dest = d.path().join("wpantry");
    std::fs::write(&dest, "#!/bin/sh\necho old\n").unwrap();
    let good = d.path().join("good");
    std::fs::write(&good, "#!/bin/sh\necho wpantry 9.9.9\n").unwrap();
    let bad = d.path().join("bad");
    std::fs::write(&bad, "#!/bin/sh\nexit 3\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in [&dest, &good, &bad] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        replace(&good, &dest).unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "#!/bin/sh\necho wpantry 9.9.9\n");
        assert_eq!(std::fs::read_to_string(d.path().join("wpantry.old")).unwrap(), "#!/bin/sh\necho old\n");
        assert!(replace(&bad, &dest).is_err());
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "#!/bin/sh\necho wpantry 9.9.9\n", "rolled back");
    }
}

#[test]
fn release_assets_per_platform() {
    assert_eq!(asset_for("macos", "aarch64").unwrap(), "wpantry-universal-apple-darwin");
    assert_eq!(asset_for("linux", "x86_64").unwrap(), "wpantry-x86_64-unknown-linux-musl");
    assert_eq!(asset_for("linux", "aarch64").unwrap(), "wpantry-aarch64-unknown-linux-musl");
    assert!(asset_for("windows", "x86_64").is_err());
    assert!(asset_for("linux", "riscv64").is_err());
    // This machine is one of them (the release workflow builds for it).
    assert!(asset().is_ok());
    assert!(workdir().unwrap().path().is_dir());
}

#[test]
fn latest_release_from_github() {
    let d = TempDir::new("latest").unwrap();
    let cache = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let net = net::Fake::new(|r| {
        assert!(r.url.ends_with("/repos/waffuruai/pantry/releases/latest"), "{}", r.url);
        Ok(net::Response::ok(r#"{"tag_name": "v0.3.1"}"#))
    });
    assert_eq!(latest(&cache, &net, false).unwrap(), "0.3.1");
    assert_eq!(latest(&cache, &net::Fake::offline(), false).unwrap(), "0.3.1", "cached for a day");
}

/// A release on a fake GitHub: SHA256SUMS, the asset and the signature bundles.
fn release(version: &'static str, sums: &'static str, body: &'static [u8]) -> net::Fake {
    net::Fake::new(move |r| {
        let want = format!("https://github.com/waffuruai/pantry/releases/download/v{version}/");
        assert!(r.url.starts_with(&want), "{}", r.url);
        assert_eq!(r.header("Accept"), Some("application/octet-stream"));
        let name = &r.url[want.len()..];
        Ok(match name {
            "SHA256SUMS" => net::Response::ok(sums),
            n if n.ends_with(".sigstore.json") => net::Response::ok("{}"),
            n if n.starts_with("wpantry-") => net::Response::ok(body),
            _ => net::Response { status: 404, body: Vec::new(), etag: None },
        })
    })
}

#[test]
fn downloads_refuse_missing_and_oversized_assets() {
    let net = release("0.3.0", "", b"bin");
    assert!(matches!(download(&net, "0.3.0", "nothing"), Err(Error::Offline(_))));
    assert_eq!(download(&net, "0.3.0", "wpantry-x").unwrap(), b"bin");
    let big = net::Fake::new(|_| Ok(net::Response::ok(vec![0u8; MAX_ASSET + 1])));
    assert!(matches!(download(&big, "0.3.0", "wpantry-x"), Err(Error::Invalid(_))));
}

/// A fake verifier: a script that prints `stdout`, writes `stderr` and exits with `code`.
#[cfg(unix)]
fn tool(dir: &Path, name: &str, stdout: &str, stderr: &str, code: i32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh
printf '%s' '{stdout}'
printf '%s' '{stderr}' >&2
exit {code}
"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

#[cfg(unix)]
fn only(name: &'static str, path: PathBuf) -> impl Fn(&str) -> Option<PathBuf> {
    move |n: &str| (n == name).then(|| path.clone())
}

#[cfg(unix)]
#[test]
fn fetch_verified_checks_the_sum_then_a_signature() {
    let d = TempDir::new("fetch").unwrap();
    let asset = asset().unwrap();
    let body: &[u8] = b"a release binary\n";
    let sum = crate::utils::sha256::hex(body);
    let sums: &'static str = Box::leak(format!("{sum}  {asset}\n").into_boxed_str());
    let none = |_: &str| -> Option<PathBuf> { None };
    let err = |r: Result<(PathBuf, Verified)>| match r {
        Err(e) => e.to_string(),
        Ok((p, v)) => panic!("verified {} by {}", p.display(), v.by),
    };
    // No verifier: refused on the checksum alone.
    let net = release("0.3.0", sums, body);
    let e = err(fetch_verified_with(&none, &net, "0.3.0", d.path()));
    assert!(e.contains("no signature verifier"), "{e}");
    assert_eq!(std::fs::read(d.path().join(asset)).unwrap(), body, "the file was written before verifying");
    // SHA256SUMS without this asset, and a body that doesn't match it.
    let e = err(fetch_verified_with(&none, &release("0.3.0", "abc  other\n", body), "0.3.0", d.path()));
    assert!(e.contains("no entry"), "{e}");
    let e = err(fetch_verified_with(&none, &release("0.3.0", sums, b"tampered"), "0.3.0", d.path()));
    assert!(e.contains("checksum mismatch"), "{e}");
    // packslip, pinned to the release signer.
    let bin = TempDir::new("verifiers").unwrap();
    let ok = tool(bin.path(), "packslip", "ok: github.com/waffuruai/pantry 0.3.0 signer ps1_x\n", "", 0);
    let (file, v) = fetch_verified_with(&only("packslip", ok), &net, "0.3.0", d.path()).unwrap();
    assert_eq!(file, d.path().join(asset));
    assert!(v.by.starts_with("packslip (github.com/waffuruai/pantry 0.3.0"), "{}", v.by);
    assert!(d.path().join("packslip.sigstore.json").is_file());
    let other = tool(bin.path(), "packslip", "ok: github.com/waffuruai/pantry 0.2.9\n", "", 0);
    let e = err(fetch_verified_with(&only("packslip", other), &net, "0.3.0", d.path()));
    assert!(e.contains("packslip did not verify") && e.contains("0.2.9"), "{e}");
    let silent = tool(bin.path(), "packslip", "", "bad signature\n", 1);
    let e = err(fetch_verified_with(&only("packslip", silent), &net, "0.3.0", d.path()));
    assert!(e.ends_with("bad signature"), "{e}");
    // gh, against the release workflow at the tag.
    let gh = tool(bin.path(), "gh", "", "", 0);
    let (_, v) = fetch_verified_with(&only("gh", gh), &net, "0.3.0", d.path()).unwrap();
    assert_eq!(v.by, "GitHub attestation (waffuruai/pantry, release.yml@v0.3.0)");
    let gh = tool(bin.path(), "gh", "", "Error: no attestations\n", 1);
    let e = err(fetch_verified_with(&only("gh", gh), &net, "0.3.0", d.path()));
    assert!(e.contains("gh attestation verify failed") && e.ends_with("no attestations"), "{e}");
    // cosign, with the keyless bundle.
    let cosign = tool(bin.path(), "cosign", "Verified OK\n", "", 0);
    let (_, v) = fetch_verified_with(&only("cosign", cosign), &net, "0.3.0", d.path()).unwrap();
    assert_eq!(v.by, "cosign (release.yml@v0.3.0)");
    assert!(d.path().join(format!("{asset}.sigstore.json")).is_file());
    let cosign = tool(bin.path(), "cosign", "", "Error: bad bundle\n", 2);
    let e = err(fetch_verified_with(&only("cosign", cosign), &net, "0.3.0", d.path()));
    assert!(e.contains("cosign did not verify") && e.contains("refs/tags/v0.3.0"), "{e}");
    // A verifier that is listed but can't run is an error, never a pass.
    for name in ["packslip", "gh", "cosign"] {
        let gone = only(name, bin.path().join("gone"));
        let e = err(fetch_verified_with(&gone, &net, "0.3.0", d.path()));
        assert!(e.contains("gone"), "{name}: {e}");
    }
    // The real verifiers are never reached when the release can't be fetched.
    let e = err(fetch_verified(&net::Fake::offline(), "0.3.0", d.path()));
    assert!(e.contains("offline"), "{e}");
}

#[cfg(unix)]
#[test]
fn replace_into_an_empty_slot_and_a_slot_that_cant_take_it() {
    use std::os::unix::fs::PermissionsExt;
    let d = TempDir::new("replace2").unwrap();
    let good = d.path().join("good");
    std::fs::write(&good, "#!/bin/sh\necho wpantry 9.9.9\n").unwrap();
    std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dest = d.path().join("wpantry");
    replace(&good, &dest).unwrap();
    assert!(!d.path().join("wpantry.old").exists(), "nothing to keep");
    // A destination openat can't be renamed over: a path with a trailing slash that is no directory.
    let odd = d.path().join("odd/");
    let e = replace(&good, &odd).unwrap_err().to_string();
    assert!(!e.is_empty());
    assert!(!odd.exists());
    assert!(
        std::fs::read_dir(d.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".wpantry-update")),
        "no staging file left"
    );
    assert!(replace(&good, Path::new("/")).is_err(), "no directory");
}
