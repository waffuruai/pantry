use super::*;
use crate::checks::machine::testing;
use crate::utils::net::Fake;

impl Checker {
    pub(crate) fn trusts(&self, anchors: &Path) -> bool {
        self.verify(anchors) == Verdict::Trusts
    }

    /// One store, found and verified.
    fn check_one(&mut self, label: &str, shown: &str, bundle: &Path, hint: &str) -> Option<Store> {
        let p = self.store(label, shown, bundle, hint)?;
        self.finish(vec![p]).pop()
    }
}

/// PIP_CERT is pip's store: judged like any bundle, unchecked when it
/// can't be, and never skipped as clean.
#[test]
fn pip_cert_is_pips_store_and_one_that_cant_be_judged_is_unchecked() {
    let Some(openssl) = which("openssl") else { return };
    let mut c = Checker::new(openssl).unwrap();
    let bad = c.dir.path().join("pipcert-bad.pem");
    std::fs::write(&bad, include_str!("../../../assets/distrusted-ca/roots.pem")).unwrap();
    let junk = c.dir.path().join("pipcert-junk.pem");
    std::fs::write(&junk, "not a certificate\n").unwrap();
    let empty = c.dir.path().join("pipcert-empty.pem");
    std::fs::write(&empty, "").unwrap();
    let missing = c.dir.path().join("pipcert-missing.pem");
    let judged = |c: &mut Checker, p: &Path| {
        let pending = pip_cert_store(c, &p.display().to_string())?;
        c.finish(vec![pending]).pop()
    };
    let s = judged(&mut c, &bad).unwrap();
    assert!(s.trusts && s.unchecked.is_none() && s.label == "pip" && s.shown.starts_with("PIP_CERT="), "{s:?}");
    let s = judged(&mut c, &junk).unwrap();
    assert!(!s.trusts && s.unchecked.as_deref() == Some("no PEM certificate in the file"), "{s:?}");
    let s = judged(&mut c, &missing).unwrap();
    assert!(!s.trusts && s.unchecked.as_deref() == Some("PIP_CERT names no file"), "{s:?}");
    assert!(judged(&mut c, &empty).is_none(), "an empty bundle trusts nothing");
}

#[test]
fn splits_bundles_and_judges_stores() {
    let ints = certificates(INTERMEDIATES);
    assert_eq!(ints.len(), 12);
    assert!(
        ints.iter().all(
            |c| c.starts_with("-----BEGIN CERTIFICATE-----") && c.trim_end().ends_with("-----END CERTIFICATE-----")
        )
    );
    let Some(openssl) = which("openssl") else { return };
    let mut c = Checker::new(openssl).unwrap();
    // The roots that anchor the intermediates: a store that still trusts them.
    let bad = c.dir.path().join("bad.pem");
    std::fs::write(&bad, include_str!("../../../assets/distrusted-ca/roots.pem")).unwrap();
    assert!(c.trusts(&bad), "a bundle with the compromised roots trusts the chain");
    let none = c.dir.path().join("none.pem");
    std::fs::write(&none, ISSUERS).unwrap();
    assert!(!c.trusts(&none), "a bundle without those roots rejects it");
    assert_eq!(c.verify(&none), Verdict::Clean);
    let s = c.check_one("x", "x", &bad, "").unwrap();
    assert!(s.trusts && s.unchecked.is_none());
    assert!(c.check_one("x", "x", &bad, "").is_none(), "each store once");
}

/// A hashed directory is checked through its certificates, with nothing
/// from the system store (LibreSSL reads it for a missing -CAfile).
#[test]
fn a_hashed_directory_is_judged_by_its_own_certificates() {
    let Some(openssl) = which("openssl") else { return };
    let c = Checker::new(openssl).unwrap();
    let (bad, none) = (c.dir.path().join("bad"), c.dir.path().join("none"));
    for (d, pem) in [(&bad, include_str!("../../../assets/distrusted-ca/roots.pem")), (&none, ISSUERS)] {
        std::fs::create_dir_all(d).unwrap();
        for (i, cert) in certificates(pem).iter().enumerate() {
            std::fs::write(d.join(format!("{i:08x}.0")), cert).unwrap();
        }
    }
    assert_eq!(c.verify(&bad), Verdict::Trusts);
    assert_eq!(c.verify(&none), Verdict::Clean);
}

/// A store openssl can't use is unchecked, never "doesn't trust".
#[test]
fn an_unusable_store_is_unchecked_not_clean() {
    let Some(openssl) = which("openssl") else { return };
    let mut c = Checker::new(openssl).unwrap();
    let junk = c.dir.path().join("junk.pem");
    std::fs::write(&junk, "not a certificate\n").unwrap();
    let s = c.check_one("x", "junk", &junk, "").unwrap();
    assert!(!s.trusts);
    assert_eq!(s.unchecked.as_deref(), Some("no PEM certificate in the file"));
    // openssl itself refusing the file (a PEM block that isn't a certificate).
    let broken = c.dir.path().join("broken.pem");
    std::fs::write(&broken, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").unwrap();
    assert!(matches!(c.verify(&broken), Verdict::Unknown(_)), "{:?}", c.verify(&broken));
    let s = c.check_one("x", "broken", &broken, "").unwrap();
    assert!(!s.trusts && s.unchecked.is_some());
    let empty = c.dir.path().join("empty-store.pem");
    std::fs::write(&empty, "").unwrap();
    assert!(c.check_one("x", "empty", &empty, "").is_none(), "an empty file trusts nothing");
}

/// A store openssl can't run against, or a directory that can't be
/// read, is unknown; nothing is ever "clean" by default.
#[test]
fn an_openssl_that_cant_run_and_a_directory_that_cant_be_read_are_unknown() {
    let c = Checker::new(PathBuf::from("/nonexistent/openssl")).unwrap();
    let pem = c.dir.path().join("a.pem");
    std::fs::write(&pem, ISSUERS).unwrap();
    let v = c.verify(&pem);
    assert!(matches!(&v, Verdict::Unknown(why) if why.contains("/nonexistent/openssl")), "{v:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let locked = c.dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("00000000.0"), ISSUERS).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&locked).is_err() {
            let v = c.verify(&locked);
            assert!(matches!(&v, Verdict::Unknown(why) if why.starts_with("can't read ")), "{v:?}");
        }
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// A directory is a store when it holds hashed certificates; a file
/// that can't be read is unchecked; each real path is taken once.
#[test]
fn directories_and_unreadable_files_as_stores() {
    let mut c = Checker::new(PathBuf::from("openssl")).unwrap();
    let (hashed, plain) = (c.dir.path().join("hashed"), c.dir.path().join("plain"));
    std::fs::create_dir(&hashed).unwrap();
    std::fs::write(hashed.join("deadbeef.0"), ISSUERS).unwrap();
    std::fs::create_dir(&plain).unwrap();
    std::fs::write(plain.join("README"), "no certificates here").unwrap();
    assert!(c.store("x", "plain", &plain, "").is_none(), "a directory without hashed certificates trusts nothing");
    assert!(c.store("x", "missing", &c.dir.path().join("missing"), "").is_none());
    let p = c.store("x", "hashed", &hashed, "h").unwrap();
    assert_eq!(
        p.store,
        Store { label: "x".into(), shown: "hashed".into(), trusts: false, unchecked: None, hint: "h".into() }
    );
    assert_eq!(p.bundle, hashed);
    assert!(c.store("x", "hashed", &hashed, "").is_none(), "once");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let secret = c.dir.path().join("secret.pem");
        std::fs::write(&secret, ISSUERS).unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&secret).is_err() {
            let p = c.store("x", "secret", &secret, "").unwrap();
            assert!(p.store.unchecked.as_deref().is_some_and(|w| w.starts_with("can't read it: ")), "{:?}", p.store);
            let s = c.finish(vec![p]).pop().unwrap();
            assert!(!s.trusts && s.unchecked.is_some());
        }
    }
}

/// The stores the tools point at: OPENSSLDIR's bundle and hashed
/// directory, each Python's certifi and pip bundles, each Node's
/// compiled-in roots; and on macOS the keychain's trust settings last.
#[test]
fn check_finds_the_stores_the_tools_name() {
    let Some(_) = which("openssl") else { return };
    let d = TempDir::new("stores").unwrap();
    let roots = include_str!("../../../assets/distrusted-ca/roots.pem");
    let ossl = d.path().join("ossl");
    std::fs::create_dir_all(ossl.join("certs")).unwrap();
    std::fs::write(ossl.join("cert.pem"), roots).unwrap();
    for (i, cert) in certificates(ISSUERS).iter().enumerate() {
        std::fs::write(ossl.join("certs").join(format!("{i:08x}.0")), cert).unwrap();
    }
    let (certifi, pipca) = (d.path().join("certifi.pem"), d.path().join("pipca.pem"));
    std::fs::write(&certifi, ISSUERS).unwrap();
    std::fs::write(&pipca, roots).unwrap();
    let (certifi_s, pipca_s) = (certifi.display().to_string(), pipca.display().to_string());
    let ossl_s = ossl.display().to_string();
    let (certifi_r, pipca_r) = (certifi_s.clone(), pipca_s.clone());
    let recorded = move |argv: &[&OsStr]| -> String {
        let words: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        let joined = words.join(" ");
        if joined.ends_with("version -d") {
            format!("OPENSSLDIR: \"{ossl_s}\"\n")
        } else if joined.ends_with("xcode-select -p") {
            "/Library/Developer/CommandLineTools\n".to_string()
        } else if joined.contains("import certifi;") {
            format!("{certifi_r}\n")
        } else if joined.contains("pip._vendor.certifi") {
            format!("{pipca_r}\n")
        } else if joined.contains("rootCertificates") {
            ISSUERS.to_string()
        } else if joined.ends_with("--version") {
            "v22.0.0\n".to_string()
        } else {
            String::new()
        }
    };
    let stores = check_with(&recorded).unwrap();
    let find = |label: &str, shown: &str| stores.iter().find(|s| s.label == label && s.shown == shown);
    let bundle = find("openssl", &format!("{}/cert.pem", ossl.display())).expect("OPENSSLDIR's bundle");
    assert!(bundle.trusts && bundle.unchecked.is_none(), "{bundle:?}");
    assert!(bundle.hint.starts_with("Update the store "), "{}", bundle.hint);
    let hashed = find("openssl", &format!("{}/certs", ossl.display())).expect("OPENSSLDIR's hashed directory");
    assert!(!hashed.trusts && hashed.unchecked.is_none(), "{hashed:?}");
    let pythons = process::on_path::<&str>("python3", &[]);
    if !pythons.is_empty() {
        let s = find("certifi", &certifi_s).expect("certifi's bundle");
        assert!(!s.trusts && s.unchecked.is_none() && s.hint.contains("pip install -U certifi"), "{s:?}");
        if std::env::var("PIP_CERT").ok().filter(|p| !p.is_empty()).is_none() {
            let s = find("pip", &pipca_s).expect("pip's vendored bundle");
            assert!(s.trusts && s.hint.contains("PIP_CERT"), "{s:?}");
        }
    }
    for (i, (node, _)) in process::on_path::<&str>("node", &[]).iter().enumerate() {
        let s = find("node", &format!("{node} (v22.0.0)")).expect("the node's roots");
        assert!(!s.trusts && s.unchecked.is_none() && s.hint.starts_with("Upgrade Node"), "node {i}: {s:?}");
    }
    for s in &stores {
        assert!(!s.trusts || s.unchecked.is_none(), "unchecked is never trusted: {s:?}");
    }
    if MACOS {
        let last = stores.last().unwrap();
        assert_eq!((last.label.as_str(), last.unchecked.as_deref()), ("keychain", None));
    } else {
        assert!(stores.iter().all(|s| s.label != "keychain"));
    }
}

/// The stores on this machine, as the scan sees them.
#[test]
fn check_on_this_machine() {
    let Some(_) = which("openssl") else { return };
    let stores = check().unwrap();
    assert!(stores.iter().all(|s| !s.label.is_empty() && !s.shown.is_empty() && !s.hint.is_empty()));
    assert!(stores.iter().all(|s| !s.trusts || s.unchecked.is_none()));
}

#[test]
fn trust_stores_that_trust_a_distrusted_ca_fail() {
    let d = crate::utils::temp::TempDir::new("ca").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    let store = |label: &str, trusts: bool, unchecked: Option<&str>| Store {
        label: label.into(),
        shown: format!("/etc/{label}"),
        trusts,
        unchecked: unchecked.map(str::to_string),
        hint: format!("fix {label}"),
    };
    ca_trust(
        &mut s,
        Ok(vec![store("system", true, None), store("java", false, Some("no keytool")), store("python", false, None)]),
    );
    assert_eq!(s.counts, [("CA trust stores".to_string(), 3)]);
    assert_eq!(testing::unchecked_note(&s, "CA trust: java /etc/java"), "no keytool");
    let f = s.findings.iter().find(|f| f.vuln_id == "DISTRUSTED-CA").unwrap();
    assert_eq!(
        (f.kind.as_str(), f.component.as_str(), f.fix_cmd.as_str()),
        ("config", "CA trust: system /etc/system", "fix system")
    );
    assert!(f.note.contains(ADVISORY));
    assert_eq!(s.findings.len(), 2);
    let mut s2 = testing::scan(&net, &d);
    ca_trust(&mut s2, Err(Error::Missing("openssl".into())));
    assert_eq!(
        (s2.findings[0].component.as_str(), s2.findings[0].vuln_id.as_str(), s2.findings[0].fix_cmd.as_str()),
        ("openssl", "MISSING", "Install openssl")
    );
    let mut s3 = testing::scan(&net, &d);
    ca_trust(&mut s3, Err(Error::Failed("openssl crashed".into())));
    assert_eq!(testing::unchecked_note(&s3, "CA trust stores"), "openssl crashed");
}
