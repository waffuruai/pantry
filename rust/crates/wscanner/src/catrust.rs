//! Is a certificate authority this machine trusts known to be compromised?
//! (Python: `check-ca-trust.sh`, which `bin/wscanner` runs before a machine
//! scan.) A trust store fails when openssl can build a path from one of the
//! distrusted intermediates in `assets/distrusted-ca/` (today: the eMudhra
//! intermediates whose private keys leaked) to a root the store holds: the
//! trust decision every OpenSSL-, LibreSSL-, pip- or Node-based client
//! makes. On macOS the keychain's trust settings are asked too.

use crate::error::{Error, Result};
use crate::system::{self, MACOS, TempDir, exec, realpath, run, which};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const INTERMEDIATES: &str = include_str!("../assets/distrusted-ca/intermediates.pem");
pub const ISSUERS: &str = include_str!("../assets/distrusted-ca/issuers.pem");
pub const ADVISORY: &str = "https://emudhra.we-have-a-problem.com/";

/// One trust store and whether it still trusts a distrusted CA.
#[derive(Clone, Debug, PartialEq)]
pub struct Store {
    pub label: String,
    pub shown: String,
    pub trusts: bool,
    pub hint: String,
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
        std::fs::create_dir_all(dir.path().join("empty"))?;
        std::fs::write(dir.path().join("empty.pem"), "")?;
        Ok(Checker { openssl, dir, ints, issuers, seen: Vec::new() })
    }

    /// Whether the anchors (a PEM bundle, or a hashed directory) chain any
    /// distrusted intermediate to one of their roots.
    fn trusts(&self, anchors: &Path) -> bool {
        let opt = if anchors.is_dir() { "-CApath" } else { "-CAfile" };
        let empty_pem = self.dir.path().join("empty.pem").display().to_string();
        let empty_dir = self.dir.path().join("empty").display().to_string();
        let uri = format!("file:{empty_dir}");
        let env = [
            ("SSL_CERT_FILE", empty_pem.as_str()),
            ("SSL_CERT_DIR", empty_dir.as_str()),
            ("SSL_CERT_URI", uri.as_str()),
        ];
        self.ints.iter().any(|int| {
            let argv = [
                self.openssl.as_os_str(),
                OsStr::new("verify"),
                OsStr::new(opt),
                anchors.as_os_str(),
                OsStr::new("-untrusted"),
                self.issuers.as_os_str(),
                int.as_os_str(),
            ];
            exec(&argv, &env, Duration::from_secs(30)).is_ok_and(|o| o.code == Some(0))
        })
    }

    /// Check one store, once per real path; None when it doesn't exist.
    fn store(&mut self, label: &str, shown: &str, bundle: &Path, hint: &str) -> Option<Store> {
        if bundle.is_dir() {
            let hashed = std::fs::read_dir(bundle)
                .ok()?
                .filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy().ends_with(".0"));
            if !hashed {
                return None;
            }
        } else if std::fs::metadata(bundle).map_or(true, |m| m.len() == 0) {
            return None;
        }
        let real = realpath(&bundle.display().to_string());
        if self.seen.contains(&real) {
            return None;
        }
        self.seen.push(real);
        Some(Store { label: label.into(), shown: shown.into(), trusts: self.trusts(bundle), hint: hint.into() })
    }
}

fn sh(argv: &[&OsStr]) -> String {
    run(argv, Duration::from_secs(30))
}

/// Every trust store found and whether it trusts a distrusted CA.
/// `Missing` without openssl.
pub fn check() -> Result<Vec<Store>> {
    let openssl = which("openssl").ok_or_else(|| Error::Missing("openssl".into()))?;
    let mut c = Checker::new(openssl.clone())?;
    let mut out = Vec::new();
    let mut add = |s: Option<Store>| out.extend(s);
    let fix = "the bundled fix-ca-trust.sh (python/), or the OS's ca-certificates update";
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
    let pip_cert = std::env::var("PIP_CERT").ok().filter(|p| Path::new(p).is_file());
    for py in pythons {
        let path_of = |code: &str| {
            sh(&[OsStr::new(&py), OsStr::new("-I"), OsStr::new("-c"), OsStr::new(code)])
                .trim()
                .lines()
                .last()
                .unwrap_or("")
                .to_string()
        };
        let certifi = path_of("import certifi; print(certifi.where())");
        if certifi.starts_with('/') {
            add(c.store("certifi", &certifi, Path::new(&certifi), &format!("Run: {py} -m pip install -U certifi")));
        }
        let pip_ca = path_of("import pip._vendor.certifi as c; print(c.where())");
        if !pip_ca.starts_with('/') {
            continue;
        }
        // pip reads PIP_CERT instead of its own bundle when it is set.
        if let Some(pc) = &pip_cert
            && !c.trusts(Path::new(pc))
        {
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
    for (i, (node, _)) in system::on_path::<&str>("node", &[]).into_iter().enumerate() {
        let roots =
            sh(&[OsStr::new(&node), OsStr::new("-p"), OsStr::new("require('tls').rootCertificates.join('\\n')")]);
        if !roots.contains("BEGIN CERTIFICATE") {
            continue;
        }
        let f = c.dir.path().join(format!("node{i}.pem"));
        if std::fs::write(&f, roots).is_err() {
            continue;
        }
        let v = sh(&[OsStr::new(&node), OsStr::new("--version")]);
        add(c.store(
            "node",
            &format!("{node} ({})", v.trim()),
            &f,
            "Upgrade Node (26.12.1, 24.22.1, 22.23.4 or later)",
        ));
    }
    // The macOS trust settings that Safari, URLSession and Go use; -L: local only.
    if MACOS {
        let trusts = c.ints.iter().any(|int| {
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
        });
        out.push(Store {
            label: "keychain".into(),
            shown: "macOS trust settings".into(),
            trusts,
            hint: "Install the latest macOS update".into(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(c.store("x", "x", &bad, "").unwrap().trusts);
        assert!(c.store("x", "x", &bad, "").is_none(), "each store once");
    }
}
