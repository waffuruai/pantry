//! Is a certificate authority this machine trusts known to be compromised?
//! (On its own: `ca-trust/check-ca-trust.sh` in the repo.) A trust store fails when openssl can build a path from one of the
//! distrusted intermediates in `assets/distrusted-ca/` (today: the eMudhra
//! intermediates whose private keys leaked) to a root the store holds: the
//! trust decision every OpenSSL-, LibreSSL-, pip- or Node-based client
//! makes. On macOS the keychain's trust settings are asked too.

use crate::error::{Error, Result};
use crate::system::{self, MACOS, TempDir, exec, realpath, run, which};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub const INTERMEDIATES: &str = include_str!("../assets/distrusted-ca/intermediates.pem");
pub const ISSUERS: &str = include_str!("../assets/distrusted-ca/issuers.pem");
pub const ADVISORY: &str = "https://emudhra.we-have-a-problem.com/";

/// One trust store and whether it still trusts a distrusted CA, or why
/// that couldn't be told (then `trusts` is false and the scan reports the
/// store unchecked, never clean).
#[derive(Clone, Debug, PartialEq)]
pub struct Store {
    pub label: String,
    pub shown: String,
    pub trusts: bool,
    pub unchecked: Option<String>,
    pub hint: String,
}

/// What `openssl verify` established for a store.
#[derive(Clone, Debug, PartialEq)]
enum Verdict {
    /// A distrusted intermediate chains to one of the store's roots.
    Trusts,
    /// Every intermediate was verified against the store, and none chained.
    Clean,
    /// openssl couldn't load the store or didn't run: nothing established.
    Unknown(String),
}

/// The certificates in a PEM bundle, one PEM each.
pub fn certificates(pem: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in pem.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            cur = Some(String::new());
        }
        if let Some(c) = cur.as_mut() {
            c.push_str(line);
            c.push('\n');
        }
        if line.starts_with("-----END CERTIFICATE-----")
            && let Some(c) = cur.take()
        {
            out.push(c);
        }
    }
    out
}

struct Checker {
    openssl: PathBuf,
    dir: TempDir,
    ints: Vec<PathBuf>,
    issuers: PathBuf,
    seen: Vec<String>,
    /// Numbers the bundles gathered from hashed directories, which are
    /// verified at once.
    gathered: AtomicUsize,
}

impl Checker {
    fn new(openssl: PathBuf) -> Result<Checker> {
        let dir = TempDir::new("catrust")?;
        // One file per intermediate: openssl verify reads only the first certificate in a file.
        let mut ints = Vec::new();
        for (i, c) in certificates(INTERMEDIATES).iter().enumerate() {
            let f = dir.path().join(format!("int{i:02}.pem"));
            std::fs::write(&f, c)?;
            ints.push(f);
        }
        let issuers = dir.path().join("issuers.pem");
        std::fs::write(&issuers, ISSUERS)?;
        // Empty default locations: openssl verify still reads the system
        // store next to an explicit -CAfile or -CApath on some systems.
        // OpenSSL honours these variables; LibreSSL (macOS) doesn't, so
        // `verify` is also always given both -CAfile and -CApath.
        std::fs::create_dir_all(dir.path().join("empty"))?;
        std::fs::write(dir.path().join("empty.pem"), "")?;
        Ok(Checker { openssl, dir, ints, issuers, seen: Vec::new(), gathered: AtomicUsize::new(0) })
    }

    /// Whether the anchors (a PEM bundle, or a hashed directory) chain any
    /// distrusted intermediate to one of their roots. Only a verification
    /// that ran counts either way: `name: OK` is a chain, an `error N at`
    /// verdict is none; anything else (a file openssl can't load, a timeout)
    /// is unknown, whatever the exit code.
    fn verify(&self, anchors: &Path) -> Verdict {
        // LibreSSL's verify reads its default store for whichever of -CAfile
        // and -CApath is missing, whatever SSL_CERT_FILE and SSL_CERT_DIR say,
        // and that store would be blamed on this one. So both are always
        // given: a hashed directory's certificates are gathered into one
        // file (an empty -CAfile doesn't load), and -CApath is empty.
        let file = if anchors.is_dir() {
            match self.gather(anchors) {
                Ok(f) => f,
                Err(e) => return Verdict::Unknown(format!("can't read {}: {e}", anchors.display())),
            }
        } else {
            anchors.to_path_buf()
        };
        let empty_pem = self.dir.path().join("empty.pem").display().to_string();
        let empty_dir = self.dir.path().join("empty").display().to_string();
        let uri = format!("file:{empty_dir}");
        // Apple's openssl may retry a failed verification against the macOS
        // keychain (its Trust Evaluation Agent), blaming the keychain's trust
        // on this store; the keychain is checked on its own in `check`.
        let env = [
            ("SSL_CERT_FILE", empty_pem.as_str()),
            ("SSL_CERT_DIR", empty_dir.as_str()),
            ("SSL_CERT_URI", uri.as_str()),
            ("OPENSSL_X509_TEA_DISABLE", "1"),
        ];
        // One intermediate per call (see `new`), all at once; read in order.
        let outputs = system::par_map(&self.ints, system::PROBES, |int| {
            let argv = [
                self.openssl.as_os_str(),
                OsStr::new("verify"),
                OsStr::new("-CAfile"),
                file.as_os_str(),
                OsStr::new("-CApath"),
                OsStr::new(&empty_dir),
                OsStr::new("-untrusted"),
                self.issuers.as_os_str(),
                int.as_os_str(),
            ];
            exec(&argv, &env, Duration::from_secs(30))
        });
        for (int, o) in self.ints.iter().zip(outputs) {
            let o = match o {
                Ok(o) => o,
                Err(e) => return Verdict::Unknown(e.to_string()),
            };
            let said = format!("{}\n{}", o.stdout, o.stderr);
            let ok = format!("{}: OK", int.display());
            if o.code == Some(0) && said.lines().any(|l| l.trim() == ok) {
                return Verdict::Trusts;
            }
            let failed = said.lines().any(|l| {
                l.strip_prefix("error ")
                    .and_then(|r| r.split_once(" at "))
                    .is_some_and(|(n, _)| n.parse::<u32>().is_ok())
            });
            if !failed {
                let why = said.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("no output");
                return Verdict::Unknown(format!("openssl verify: {why}"));
            }
        }
        Verdict::Clean
    }

    /// The certificates of a hashed directory (`<hash>.<n>`) as one bundle.
    fn gather(&self, dir: &Path) -> std::io::Result<PathBuf> {
        let mut names: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x.to_string_lossy().bytes().all(|b| b.is_ascii_digit())))
            .collect();
        names.sort();
        let mut pem = String::new();
        for n in names {
            if let Ok(b) = crate::system::read_capped_bytes(&n, MAX_STORE) {
                pem.push_str(&certificates(&String::from_utf8_lossy(&b)).concat());
            }
        }
        let out = self.dir.path().join(format!("dir{}.pem", self.gathered.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&out, pem)?;
        Ok(out)
    }

    fn trusts(&self, anchors: &Path) -> bool {
        self.verify(anchors) == Verdict::Trusts
    }

    /// One store to check, once per real path; None when it doesn't exist
    /// (or is an empty file or a directory without hashed certificates,
    /// which trust nothing). A store that can't be read or holds no
    /// certificate is unchecked. [`Checker::finish`] verifies it.
    fn store(&mut self, label: &str, shown: &str, bundle: &Path, hint: &str) -> Option<Pending> {
        let mut unchecked = None;
        if bundle.is_dir() {
            let hashed = std::fs::read_dir(bundle)
                .ok()?
                .filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy().ends_with(".0"));
            if !hashed {
                return None;
            }
        } else {
            if std::fs::metadata(bundle).map_or(true, |m| m.len() == 0) {
                return None;
            }
            match crate::system::read_capped_bytes(bundle, MAX_STORE) {
                Ok(b) if certificates(&String::from_utf8_lossy(&b)).is_empty() => {
                    unchecked = Some("no PEM certificate in the file".to_string())
                }
                Ok(_) => {}
                Err(e) => unchecked = Some(format!("can't read it: {e}")),
            }
        }
        let real = realpath(&bundle.display().to_string());
        if self.seen.contains(&real) {
            return None;
        }
        self.seen.push(real);
        Some(Pending {
            store: Store { label: label.into(), shown: shown.into(), trusts: false, unchecked, hint: hint.into() },
            bundle: bundle.to_path_buf(),
        })
    }

    /// Verify the stores, a few at once (each runs its intermediates at
    /// once too), in their order.
    fn finish(&self, pending: Vec<Pending>) -> Vec<Store> {
        let verdicts = system::par_map(&pending, STORES_AT_ONCE, |p| match &p.store.unchecked {
            Some(why) => Verdict::Unknown(why.clone()),
            None => self.verify(&p.bundle),
        });
        pending
            .into_iter()
            .zip(verdicts)
            .map(|(p, verdict)| Store {
                trusts: verdict == Verdict::Trusts,
                unchecked: match verdict {
                    Verdict::Unknown(why) => Some(why),
                    _ => None,
                },
                ..p.store
            })
            .collect()
    }
}

/// A store found and not yet verified.
struct Pending {
    store: Store,
    bundle: PathBuf,
}

/// Stores verified at once; each runs its intermediates at once as well.
const STORES_AT_ONCE: usize = 4;
/// The largest trust store read (a system bundle is a few hundred KiB).
const MAX_STORE: u64 = 16 << 20;

fn sh(argv: &[&OsStr]) -> String {
    run(argv, Duration::from_secs(30))
}

/// Every trust store found and whether it trusts a distrusted CA.
/// `Missing` without openssl.
pub fn check() -> Result<Vec<Store>> {
    let openssl = which("openssl").ok_or_else(|| Error::Missing("openssl".into()))?;
    let mut c = Checker::new(openssl.clone())?;
    let mut pending = Vec::new();
    let mut add = |s: Option<Pending>| pending.extend(s);
    let fix = "ca-trust/fix-ca-trust.sh from the pantry repo, or the OS's ca-certificates update";
    if MACOS {
        add(c.store("system", "/etc/ssl/cert.pem", Path::new("/etc/ssl/cert.pem"), &format!("Run {fix}")));
    } else {
        for f in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/ssl/cert.pem",
            "/etc/ssl/certs",
        ] {
            add(c.store("system", f, Path::new(f), &format!("Update the ca-certificates package, or run {fix}")));
        }
    }
    let dir_line = sh(&[openssl.as_os_str(), OsStr::new("version"), OsStr::new("-d")]);
    if let Some(d) = dir_line.trim().strip_prefix("OPENSSLDIR: \"").and_then(|r| r.strip_suffix('"')) {
        for f in [format!("{d}/cert.pem"), format!("{d}/certs")] {
            add(c.store("openssl", &f, Path::new(&f), &format!("Update the store {} reads", openssl.display())));
        }
    }
    let brew = system::brew_prefix();
    if !brew.is_empty() {
        let f = format!("{brew}/etc/ca-certificates/cert.pem");
        add(c.store("brew", &f, Path::new(&f), "Run: brew upgrade ca-certificates"));
    }
    let mut pythons: Vec<String> =
        system::on_path::<&str>("python3", &[]).into_iter().map(|(shown, _)| shown).collect();
    if MACOS && sh(&[OsStr::new("xcode-select"), OsStr::new("-p")]).starts_with('/') {
        pythons.push("/usr/bin/python3".into());
    }
    // pip reads PIP_CERT instead of its own bundle when it is set.
    let pip_cert = std::env::var("PIP_CERT").ok().filter(|p| Path::new(p).is_file());
    let pip_cert_clean = pip_cert.is_some_and(|pc| !c.trusts(Path::new(&pc)));
    let path_of = |py: &str, code: &str| {
        sh(&[OsStr::new(py), OsStr::new("-I"), OsStr::new("-c"), OsStr::new(code)])
            .trim()
            .lines()
            .last()
            .unwrap_or("")
            .to_string()
    };
    let bundles = system::par_map(&pythons, system::PROBES, |py| {
        (
            path_of(py, "import certifi; print(certifi.where())"),
            path_of(py, "import pip._vendor.certifi as c; print(c.where())"),
        )
    });
    for (py, (certifi, pip_ca)) in pythons.iter().zip(bundles) {
        if certifi.starts_with('/') {
            add(c.store("certifi", &certifi, Path::new(&certifi), &format!("Run: {py} -m pip install -U certifi")));
        }
        if !pip_ca.starts_with('/') || pip_cert_clean {
            continue;
        }
        add(c.store(
            "pip",
            &pip_ca,
            Path::new(&pip_ca),
            &format!("Run: {py} -m pip install -U pip, or export PIP_CERT to a fixed bundle"),
        ));
    }
    // Node compiles its roots in; dump them to check like any other bundle.
    let nodes: Vec<String> = system::on_path::<&str>("node", &[]).into_iter().map(|(node, _)| node).collect();
    let dumps = system::par_map(&nodes, system::PROBES, |node| {
        let roots =
            sh(&[OsStr::new(node), OsStr::new("-p"), OsStr::new("require('tls').rootCertificates.join('\\n')")]);
        (roots, sh(&[OsStr::new(node), OsStr::new("--version")]))
    });
    for (i, (node, (roots, v))) in nodes.iter().zip(dumps).enumerate() {
        if !roots.contains("BEGIN CERTIFICATE") {
            continue;
        }
        let f = c.dir.path().join(format!("node{i}.pem"));
        if std::fs::write(&f, roots).is_err() {
            continue;
        }
        add(c.store(
            "node",
            &format!("{node} ({})", v.trim()),
            &f,
            "Upgrade Node (26.12.1, 24.22.1, 22.23.4 or later)",
        ));
    }
    let mut out = c.finish(pending);
    // The macOS trust settings that Safari, URLSession and Go use; -L: local only.
    if MACOS {
        let trusts = system::par_map(&c.ints, system::PROBES, |int| {
            let argv = [
                OsStr::new("security"),
                OsStr::new("verify-cert"),
                OsStr::new("-L"),
                OsStr::new("-q"),
                OsStr::new("-p"),
                OsStr::new("basic"),
                OsStr::new("-c"),
                int.as_os_str(),
                OsStr::new("-c"),
                c.issuers.as_os_str(),
            ];
            exec(&argv, &[], Duration::from_secs(30)).is_ok_and(|o| o.code == Some(0))
        })
        .contains(&true);
        out.push(Store {
            label: "keychain".into(),
            shown: "macOS trust settings".into(),
            trusts,
            unchecked: None,
            hint: "Install the latest macOS update".into(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Checker {
        /// One store, found and verified.
        fn check_one(&mut self, label: &str, shown: &str, bundle: &Path, hint: &str) -> Option<Store> {
            let p = self.store(label, shown, bundle, hint)?;
            self.finish(vec![p]).pop()
        }
    }

    #[test]
    fn splits_bundles_and_judges_stores() {
        let ints = certificates(INTERMEDIATES);
        assert_eq!(ints.len(), 12);
        assert!(ints.iter().all(
            |c| c.starts_with("-----BEGIN CERTIFICATE-----") && c.trim_end().ends_with("-----END CERTIFICATE-----")
        ));
        let Some(openssl) = which("openssl") else { return };
        let mut c = Checker::new(openssl).unwrap();
        // The roots that anchor the intermediates: a store that still trusts them.
        let bad = c.dir.path().join("bad.pem");
        std::fs::write(&bad, include_str!("../assets/distrusted-ca/roots.pem")).unwrap();
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
        for (d, pem) in [(&bad, include_str!("../assets/distrusted-ca/roots.pem")), (&none, ISSUERS)] {
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
}
