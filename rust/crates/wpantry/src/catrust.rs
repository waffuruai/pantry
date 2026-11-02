//! Is a certificate authority this machine trusts known to be compromised?
//! (On its own: `ca-trust/check-ca-trust.sh` in the repo; `wpantry harden
//! ca-trust` repairs what it finds.) A trust store fails when openssl can build a path from one of the
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

/// pip's trust store when `PIP_CERT` is `pc`: the file, verified like any
/// store (unreadable or malformed, it is unchecked, never clean), or, when
/// it names no file, a store already judged unchecked. None for an empty
/// file, which trusts nothing.
fn pip_cert_store(c: &mut Checker, pc: &str) -> Option<Pending> {
    let shown = format!("PIP_CERT={pc}");
    let hint = "Point PIP_CERT at a bundle without the leaked CAs, or unset it";
    if Path::new(pc).is_file() {
        return c.store("pip", &shown, Path::new(pc), hint);
    }
    Some(Pending {
        store: Store {
            label: "pip".into(),
            shown,
            trusts: false,
            unchecked: Some("PIP_CERT names no file".into()),
            hint: hint.into(),
        },
        bundle: PathBuf::from(pc),
    })
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
    let fix = "wpantry harden ca-trust (asks for sudo to install the result), or the OS's ca-certificates update";
    if MACOS {
        add(c.store("system", "/etc/ssl/cert.pem", Path::new("/etc/ssl/cert.pem"), &format!("Run: {fix}")));
    } else {
        for f in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/ssl/cert.pem",
            "/etc/ssl/certs",
        ] {
            add(c.store("system", f, Path::new(f), &format!("Update the ca-certificates package, or run: {fix}")));
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
    // pip reads PIP_CERT instead of its vendored bundle when it is set: then
    // that file is pip's store, and the vendored bundles aren't what pip trusts.
    let pip_cert = std::env::var("PIP_CERT").ok().filter(|p| !p.is_empty());
    if let Some(pc) = &pip_cert {
        add(pip_cert_store(&mut c, pc));
    }
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
        if !pip_ca.starts_with('/') || pip_cert.is_some() {
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

/* ---------- the fix: `wpantry harden ca-trust` ---------- */

/// The roots that anchor the distrusted intermediates: what the fix removes
/// from a bundle the OS has not fixed yet.
pub const ROOTS: &str = include_str!("../assets/distrusted-ca/roots.pem");

/// Standard base64 (what PEM carries); None for a character outside it.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// A certificate's SHA-256 fingerprint (of its DER bytes), upper-case hex
/// without colons: what `openssl x509 -fingerprint -sha256` prints, joined.
pub fn fingerprint(pem: &str) -> Option<String> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect();
    base64_decode(&body).filter(|d| !d.is_empty()).map(|d| crate::sha256::hex(&d).to_ascii_uppercase())
}

/// A bundle's entries: each certificate with the comment lines above it,
/// then whatever follows the last one, kept as it is.
fn entries(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.split_inclusive('\n') {
        cur.push_str(line);
        if line.starts_with("-----END CERTIFICATE-----") {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The fingerprint of an entry's certificate, if it has one.
fn entry_fingerprint(entry: &str) -> Option<String> {
    certificates(entry).first().and_then(|c| fingerprint(c))
}

/// How an entry is named in the log: its comment line (bundles name each
/// CA above its certificate), else its fingerprint.
fn entry_name(entry: &str, fp: &str) -> String {
    entry
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with('#') && l.trim_start_matches('#').trim().len() > 1)
        .map(|l| l.trim_start_matches('#').trim().to_string())
        .unwrap_or_else(|| format!("sha256 {}\u{2026}", &fp[..fp.len().min(16)]))
}

fn is_root() -> bool {
    run(&["id", "-u"], Duration::from_secs(5)).trim() == "0"
}

/// Runs `argv` as root: directly when we are, else through sudo on the
/// terminal (it prompts there). Nothing is captured, so the prompt shows.
fn as_root(argv: &[&OsStr]) -> Result<()> {
    let shown = argv.iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ");
    let mut cmd = if is_root() {
        let mut c = std::process::Command::new(argv[0]);
        c.args(&argv[1..]);
        c
    } else {
        let mut c = std::process::Command::new("sudo");
        c.args(argv);
        c
    };
    let status =
        cmd.stdout(std::process::Stdio::null()).status().map_err(|e| Error::Failed(format!("{shown}: {e}")))?;
    if status.success() { Ok(()) } else { Err(Error::Failed(format!("{shown} failed ({status})"))) }
}

fn root_group() -> String {
    let g = run(&["id", "-gn", "root"], Duration::from_secs(5)).trim().to_string();
    if g.is_empty() { "root".into() } else { g }
}

/// Whether a store (a bundle, or a hashed directory) still trusts a
/// distrusted CA; an error when that can't be told (then nothing is
/// installed on the strength of it).
fn still_trusts(store: &Path) -> Result<bool> {
    let openssl = which("openssl").ok_or_else(|| Error::Missing("openssl".into()))?;
    match Checker::new(openssl)?.verify(store) {
        Verdict::Trusts => Ok(true),
        Verdict::Clean => Ok(false),
        Verdict::Unknown(why) => Err(Error::Failed(format!("can't verify {}: {why}", store.display()))),
    }
}

/// Every existing store among `paths` must now reject the distrusted CAs.
fn verify_system(paths: &[&str]) -> Result<()> {
    for p in paths {
        let path = Path::new(p);
        let hashed = path.is_dir()
            && std::fs::read_dir(path)
                .ok()
                .is_some_and(|d| d.filter_map(|e| e.ok()).any(|e| e.file_name().to_string_lossy().ends_with(".0")));
        if !(path.is_file() || hashed) {
            continue;
        }
        if still_trusts(path)? {
            return Err(Error::Failed(format!("{p} still trusts a distrusted CA")));
        }
    }
    Ok(())
}

/// Installs `new` over `target`, keeping the original once as
/// `target.orig`: directly when the file and its directory can be written,
/// else as root.
fn install(target: &Path, new: &Path) -> Result<()> {
    let orig = PathBuf::from(format!("{}.orig", target.display()));
    let direct = (|| -> std::io::Result<()> {
        if !orig.exists() {
            std::fs::copy(target, &orig)?;
        }
        std::fs::write(target, std::fs::read(new)?)
    })();
    match direct {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            if !orig.exists() {
                as_root(&[OsStr::new("cp"), OsStr::new("-p"), target.as_os_str(), orig.as_os_str()])?;
            }
            let group = root_group();
            as_root(&[
                OsStr::new("install"),
                OsStr::new("-m"),
                OsStr::new("0644"),
                OsStr::new("-o"),
                OsStr::new("root"),
                OsStr::new("-g"),
                OsStr::new(&group),
                new.as_os_str(),
                target.as_os_str(),
            ])
        }
        Err(e) => Err(e.into()),
    }
}

/// Rewrites a PEM bundle without the distrusted roots (macOS's
/// /etc/ssl/cert.pem, or `--bundle FILE`). Never installs a bundle that
/// lost more than the roots, or that still trusts them.
fn fix_bundle(target: &Path, drop: &[String], say: &dyn Fn(&str)) -> Result<()> {
    let bytes = system::read_capped_bytes(target, MAX_STORE)
        .map_err(|e| Error::Failed(format!("no such bundle: {}: {e}", target.display())))?;
    let text = String::from_utf8_lossy(&bytes);
    let mut kept = String::new();
    let mut removed = 0usize;
    for e in entries(&text) {
        if let Some(fp) = entry_fingerprint(&e)
            && drop.contains(&fp)
        {
            removed += 1;
            say(&format!("  removing {}", entry_name(&e, &fp)));
            continue;
        }
        kept.push_str(&e);
    }
    if removed == 0 {
        say(&format!("\u{2713} {} holds none of the distrusted roots", target.display()));
        return Ok(());
    }
    let before = text.matches("BEGIN CERTIFICATE").count();
    let after = kept.matches("BEGIN CERTIFICATE").count();
    if after + removed != before {
        return Err(Error::Failed(format!(
            "rewrite kept {after} of {before} certificates; leaving {} alone",
            target.display()
        )));
    }
    let tmp = TempDir::new("catrust-fix")?;
    let new = tmp.path().join("bundle.pem");
    std::fs::write(&new, &kept)?;
    if still_trusts(&new)? {
        return Err(Error::Failed(format!(
            "the rewritten bundle still trusts a distrusted CA; leaving {} alone",
            target.display()
        )));
    }
    install(target, &new)?;
    say(&format!(
        "\u{2713} removed {removed} distrusted root(s) from {} (original: {}.orig)",
        target.display(),
        target.display()
    ));
    Ok(())
}

/// The `.crt` files under a directory, a few levels deep.
fn crt_files(dir: &Path, depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for e in rd.filter_map(|e| e.ok()) {
        let p = e.path();
        if p.is_dir() {
            if depth > 0 {
                out.extend(crt_files(&p, depth - 1));
            }
        } else if p.extension().is_some_and(|x| x == "crt") {
            out.push(p);
        }
    }
    out.sort();
    out
}

fn file_fingerprint(p: &Path) -> Option<String> {
    let b = system::read_capped_bytes(p, MAX_STORE).ok()?;
    entry_fingerprint(&String::from_utf8_lossy(&b))
}

/// Debian, Ubuntu, Alpine: deselect each matching certificate with a `!`
/// line in /etc/ca-certificates.conf, which update-ca-certificates honours
/// on every rebuild.
fn fix_ca_certificates_conf(drop: &[String], say: &dyn Fn(&str)) -> Result<()> {
    let conf = Path::new("/etc/ca-certificates.conf");
    let share = Path::new("/usr/share/ca-certificates");
    let mut text = std::fs::read_to_string(conf)?;
    let mut n = 0usize;
    for f in crt_files(share, 4) {
        if !file_fingerprint(&f).is_some_and(|fp| drop.contains(&fp)) {
            continue;
        }
        let rel = f.strip_prefix(share).unwrap_or(&f).to_string_lossy().into_owned();
        say(&format!("  distrusting {rel}"));
        let off = format!("!{rel}");
        let mut lines: Vec<String> = text.lines().map(|l| if l == rel { off.clone() } else { l.to_string() }).collect();
        if !lines.contains(&off) {
            lines.push(off);
        }
        text = lines.join("\n") + "\n";
        n += 1;
    }
    for f in crt_files(Path::new("/usr/local/share/ca-certificates"), 0) {
        if file_fingerprint(&f).is_some_and(|fp| drop.contains(&fp)) {
            return Err(Error::Failed(format!(
                "{} adds a distrusted root by hand; remove it, then re-run",
                f.display()
            )));
        }
    }
    if n == 0 {
        say("\u{2713} the system store holds none of the distrusted roots");
        return Ok(());
    }
    let tmp = TempDir::new("catrust-fix")?;
    let new = tmp.path().join("ca-certificates.conf");
    std::fs::write(&new, &text)?;
    let orig = PathBuf::from("/etc/ca-certificates.conf.orig");
    if !orig.exists() {
        as_root(&[OsStr::new("cp"), OsStr::new("-p"), conf.as_os_str(), orig.as_os_str()])?;
    }
    as_root(&[OsStr::new("install"), OsStr::new("-m"), OsStr::new("0644"), new.as_os_str(), conf.as_os_str()])?;
    as_root(&[OsStr::new("update-ca-certificates")])?;
    verify_system(&["/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem", "/etc/ssl/certs"])?;
    say(&format!("\u{2713} distrusted {n} root(s) in {} (original: {})", conf.display(), orig.display()));
    Ok(())
}

/// Fedora, RHEL, Arch, openSUSE: the roots go into the p11-kit blocklist,
/// and the store is rebuilt.
fn fix_blocklist(dir: &Path, rebuild: &[&str], say: &dyn Fn(&str)) -> Result<()> {
    as_root(&[OsStr::new("mkdir"), OsStr::new("-p"), dir.as_os_str()])?;
    let tmp = TempDir::new("catrust-fix")?;
    for (i, c) in certificates(ROOTS).iter().enumerate() {
        let Some(fp) = fingerprint(c) else { continue };
        let f = tmp.path().join(format!("root{i}.pem"));
        std::fs::write(&f, c)?;
        let dest = dir.join(format!("waffuru-distrusted-{}.pem", &fp[..16]));
        as_root(&[OsStr::new("install"), OsStr::new("-m"), OsStr::new("0644"), f.as_os_str(), dest.as_os_str()])?;
    }
    let argv: Vec<&OsStr> = rebuild.iter().map(OsStr::new).collect();
    as_root(&argv)?;
    verify_system(&[
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
        "/etc/ssl/certs",
    ])?;
    say(&format!("\u{2713} blocklisted the distrusted roots in {}", dir.display()));
    Ok(())
}

/// `<parent>/blocklist`, or the older `<parent>/blacklist` where only that exists.
fn blocklist_dir(parent: &str) -> PathBuf {
    let (new, old) = (Path::new(parent).join("blocklist"), Path::new(parent).join("blacklist"));
    if old.is_dir() && !new.is_dir() { old } else { new }
}

/// `wpantry harden ca-trust`: distrusts the leaked roots in the system
/// trust store, the advisory's workaround until the OS's ca-certificates
/// update ships, matched by fingerprint; root is needed only to install the
/// result (sudo asks on the terminal). `bundle` rewrites that PEM file
/// instead, as on macOS (the tests use it). Each step is told to `say`.
pub fn fix(bundle: Option<&Path>, say: &dyn Fn(&str)) -> Result<()> {
    let drop: Vec<String> = certificates(ROOTS).iter().filter_map(|c| fingerprint(c)).collect();
    if drop.is_empty() {
        return Err(Error::Failed("no distrusted root is bundled".into()));
    }
    if let Some(b) = bundle {
        return fix_bundle(b, &drop, say);
    }
    if MACOS {
        return fix_bundle(Path::new("/etc/ssl/cert.pem"), &drop, say);
    }
    if Path::new("/etc/pki/trust").is_dir() {
        return fix_blocklist(&blocklist_dir("/etc/pki/trust"), &["update-ca-certificates"], say);
    }
    if Path::new("/etc/pki/ca-trust/source").is_dir() {
        return fix_blocklist(&blocklist_dir("/etc/pki/ca-trust/source"), &["update-ca-trust", "extract"], say);
    }
    if Path::new("/etc/ca-certificates/trust-source").is_dir() {
        return fix_blocklist(
            Path::new("/etc/ca-certificates/trust-source/blocklist"),
            &["update-ca-trust", "extract"],
            say,
        );
    }
    if Path::new("/etc/ca-certificates.conf").is_file() && which("update-ca-certificates").is_some() {
        return fix_ca_certificates_conf(&drop, say);
    }
    Err(Error::Failed(format!(
        "don't know this system's trust store. Update its ca-certificates package (see {ADVISORY})."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Checker {
        fn trusts(&self, anchors: &Path) -> bool {
            self.verify(anchors) == Verdict::Trusts
        }

        /// One store, found and verified.
        fn check_one(&mut self, label: &str, shown: &str, bundle: &Path, hint: &str) -> Option<Store> {
            let p = self.store(label, shown, bundle, hint)?;
            self.finish(vec![p]).pop()
        }
    }

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

    /// PIP_CERT is pip's store: judged like any bundle, unchecked when it
    /// can't be, and never skipped as clean.
    #[test]
    fn pip_cert_is_pips_store_and_one_that_cant_be_judged_is_unchecked() {
        let Some(openssl) = which("openssl") else { return };
        let mut c = Checker::new(openssl).unwrap();
        let bad = c.dir.path().join("pipcert-bad.pem");
        std::fs::write(&bad, include_str!("../assets/distrusted-ca/roots.pem")).unwrap();
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
