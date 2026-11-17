use super::*;
use crate::checks::machine::ca_trust::{Checker, ISSUERS, certificates};

/// The fix removes the distrusted roots from a bundle and nothing else,
/// keeps the original once, says so, and is idempotent.
#[test]
fn harden_removes_the_distrusted_roots_and_keeps_the_rest() {
    let Some(openssl) = which("openssl") else { return };
    let dir = TempDir::new("catrust-fix-test").unwrap();
    let bundle = dir.path().join("bundle.pem");
    let original = format!("# a bundle\n{ISSUERS}{ROOTS}# trailing note\n");
    std::fs::write(&bundle, &original).unwrap();
    let said = std::cell::RefCell::new(Vec::new());
    fix(Some(&bundle), &|l| said.borrow_mut().push(l.to_string())).unwrap();
    let after = std::fs::read_to_string(&bundle).unwrap();
    assert_eq!(certificates(&after).len(), certificates(ISSUERS).len(), "{after}");
    assert!(after.starts_with("# a bundle\n") && after.ends_with("# trailing note\n"), "comments stay: {after}");
    assert_eq!(std::fs::read_to_string(dir.path().join("bundle.pem.orig")).unwrap(), original);
    let n = certificates(ROOTS).len();
    assert!(said.borrow().iter().any(|l| l.contains(&format!("removed {n} distrusted root(s)"))), "{said:?}");
    assert!(!Checker::new(openssl).unwrap().trusts(&bundle), "the rewritten bundle rejects the chains");
    said.borrow_mut().clear();
    fix(Some(&bundle), &|l| said.borrow_mut().push(l.to_string())).unwrap();
    assert!(said.borrow().iter().any(|l| l.contains("holds none of the distrusted roots")), "{said:?}");
    assert!(fix(Some(&dir.path().join("nope.pem")), &|_| {}).is_err(), "a missing bundle is an error");
}

/// Our fingerprint is openssl's.
#[test]
fn fingerprints_match_openssl() {
    let roots = certificates(ROOTS);
    assert_eq!(roots.len(), 2);
    let Some(openssl) = which("openssl") else { return };
    let dir = TempDir::new("catrust-fp").unwrap();
    for (i, c) in roots.iter().enumerate() {
        let f = dir.path().join(format!("{i}.pem"));
        std::fs::write(&f, c).unwrap();
        let said = run(
            &[
                openssl.as_os_str(),
                OsStr::new("x509"),
                OsStr::new("-in"),
                f.as_os_str(),
                OsStr::new("-noout"),
                OsStr::new("-fingerprint"),
                OsStr::new("-sha256"),
            ],
            Duration::from_secs(10),
        );
        let theirs: String = said.split('=').nth(1).unwrap_or("").trim().replace(':', "");
        assert_eq!(fingerprint(c).unwrap(), theirs.to_ascii_uppercase(), "{said}");
    }
    assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
    assert_eq!(base64_decode("aGVs\nbG8gd29ybGQ=").unwrap(), b"hello world");
    assert!(base64_decode("a*b").is_none());
    assert!(fingerprint("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").is_none());
    let e = entries(
        "# one\nx\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n# two\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\ntail\n",
    );
    assert_eq!(e.len(), 3);
    assert!(e[0].starts_with("# one\nx\n") && e[1].starts_with("# two\n") && e[2] == "tail\n");
    assert_eq!(entry_name(&e[0], "ABCDEF0123456789XX"), "one");
    assert_eq!(entry_name("-----BEGIN", "ABCDEF0123456789XX"), "sha256 ABCDEF0123456789\u{2026}");
}
