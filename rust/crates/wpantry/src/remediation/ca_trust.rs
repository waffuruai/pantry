//! `wpantry harden ca-trust`: distrust the leaked roots in the system trust
//! store, by the OS's own mechanism (a blocklist directory, `ca-certificates.conf`,
//! or a rewritten bundle), as root, and check the store no longer trusts them.
//! What it fixes is found by [`crate::checks::machine::ca_trust`].

use crate::checks::machine::ca_trust::{ADVISORY, Checker, MAX_STORE, Verdict, certificates};
use crate::error::{Error, Result};
use crate::utils::files;
use crate::utils::os::MACOS;
use crate::utils::process::run;
use crate::utils::process::which;
use crate::utils::temp::TempDir;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The roots that anchor the distrusted intermediates: what the fix removes
/// from a bundle the OS has not fixed yet.
pub const ROOTS: &str = include_str!("../../assets/distrusted-ca/roots.pem");

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
    base64_decode(&body).filter(|d| !d.is_empty()).map(|d| crate::utils::sha256::hex(&d).to_ascii_uppercase())
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
    let bytes = files::read_capped_bytes(target, MAX_STORE)
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
    let b = files::read_capped_bytes(p, MAX_STORE).ok()?;
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
}
