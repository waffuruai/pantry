//! How this wpantry got onto the machine, and how to replace it with a
//! newer release without trusting the download: the release's `SHA256SUMS`
//! must name the binary, and a verifier that is installed (packslip, with
//! the release signer pinned; `gh attestation verify` against the release
//! workflow at the tag; cosign against the same identity) must pass. With
//! no verifier the update is refused, never installed on a checksum alone.
//!
//! An install mise, cargo or Homebrew made is updated through that tool,
//! which keeps its own record and verification; a source build is left to
//! whoever built it.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::net::{self, Net};
use crate::system::{TempDir, exec, which};
use crate::{feeds, versions};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const REPO: &str = "waffuruai/pantry";
/// The packslip signer fingerprint of pantry's releases (`packslip pin` on
/// the v0.2.0 bundle, signed by release.yml): a release signed by anyone
/// else is refused.
pub const SIGNER_PIN: &str = "ps1_nhdt6s6bechkheqxxkkcy3womq";
pub const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";
const DOWNLOAD: &str = "https://github.com/waffuruai/pantry/releases/download/v{version}/{asset}";
/// A release binary is a few MB; anything bigger is not one.
const MAX_ASSET: usize = 64 << 20;

/// Where this binary came from.
#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    /// mise's packslip backend (`mise use -g packslip:github.com/waffuruai/pantry`).
    Mise,
    /// `cargo install wpantry-cli`.
    Cargo,
    /// Homebrew.
    Brew,
    /// A build in a pantry checkout (ops' `mise run wpantry` with a commit pin, or `cargo build`).
    Source,
    /// install.sh, or a binary someone put on PATH: a file we replace in place.
    File,
}

/// The install kind of the binary at `exe` (its real path), from where it sits.
pub fn kind(exe: &Path) -> Kind {
    let p = exe.to_string_lossy().replace('\\', "/");
    if p.contains("/mise/installs/packslip-github-com-waffuruai-pantry/") || p.contains("/.mise-bins/") {
        Kind::Mise
    } else if p.contains("/.cargo/bin/") {
        Kind::Cargo
    } else if p.contains("/Cellar/") || p.contains("/homebrew/") || p.contains("/linuxbrew/") {
        Kind::Brew
    } else if p.contains("/target/release/") || p.contains("/target/debug/") {
        Kind::Source
    } else {
        Kind::File
    }
}

/// The release asset for this machine, as the release workflow names it.
pub fn asset() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", _) => Ok("wpantry-universal-apple-darwin"),
        ("linux", "x86_64") => Ok("wpantry-x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Ok("wpantry-aarch64-unknown-linux-musl"),
        (os, arch) => Err(Error::Invalid(format!("no wpantry release for {os} {arch} yet"))),
    }
}

/// The newest release version (without a leading v), refreshed daily.
pub fn latest(cache: &Cache, net: &dyn Net, offline: bool) -> Result<String> {
    feeds::github_latest(cache, net, REPO, offline)
}

/// A release version as the tags name them: `X.Y.Z`, with an optional
/// `-pre` or `+build` tail of version characters. Anything else never
/// reaches a download URL or a command.
pub fn is_version(v: &str) -> bool {
    let (core, tail) = v.split_once(['-', '+']).unwrap_or((v, ""));
    let mut parts = core.split('.');
    let three = (0..3).all(|_| parts.next().is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())));
    three
        && parts.next().is_none()
        && v.len() <= 64
        && tail.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'+')
}

/// Whether `latest` is a newer release than `current`.
pub fn newer(current: &str, latest: &str) -> bool {
    is_version(latest) && versions::lt(current, latest)
}

/// The sha256 `SHA256SUMS` lists for `asset`.
pub fn sum_for(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let (hash, name) = l.trim().split_once(char::is_whitespace)?;
        let name = name.trim().trim_start_matches('*');
        (name == asset && hash.len() == 64).then(|| hash.to_ascii_lowercase())
    })
}

fn download(net: &dyn Net, version: &str, asset: &str) -> Result<Vec<u8>> {
    let url = DOWNLOAD.replace("{version}", version).replace("{asset}", asset);
    let resp = net::request(net, &url, None, &[("Accept", "application/octet-stream")], None)?;
    if resp.status == 404 {
        return Err(Error::Offline(format!("{url}: not found")));
    }
    if resp.body.len() > MAX_ASSET {
        return Err(Error::Invalid(format!("{asset} is over {MAX_ASSET} bytes")));
    }
    Ok(resp.body)
}

/// Which verifier checked the download, in words.
pub struct Verified {
    pub by: String,
}

/// Download release `version`'s binary for this machine into `dir`, check
/// it against `SHA256SUMS`, then against a signature; the path of the
/// verified file.
pub fn fetch_verified(net: &dyn Net, version: &str, dir: &Path) -> Result<(PathBuf, Verified)> {
    let asset = asset()?;
    let sums = String::from_utf8_lossy(&download(net, version, "SHA256SUMS")?).into_owned();
    let expected = sum_for(&sums, asset)
        .ok_or_else(|| Error::Invalid(format!("the release's SHA256SUMS has no entry for {asset}")))?;
    let bytes = download(net, version, asset)?;
    let actual = crate::sha256::hex(&bytes);
    if actual != expected {
        return Err(Error::Invalid(format!("{asset}: checksum mismatch (expected {expected}, got {actual})")));
    }
    let file = dir.join(asset);
    std::fs::write(&file, &bytes)?;
    let by = verify(net, version, &file, dir, asset)?;
    Ok((file, Verified { by }))
}

/// The first verifier that is installed must pass: packslip (signer pinned),
/// gh (the attestation from release.yml at the tag), cosign (the keyless
/// bundle from the same identity). None installed: an error, never a pass.
fn verify(net: &dyn Net, version: &str, file: &Path, dir: &Path, asset: &str) -> Result<String> {
    let tag = format!("v{version}");
    if let Some(packslip) = which("packslip") {
        let bundle = dir.join("packslip.sigstore.json");
        std::fs::write(&bundle, download(net, version, "packslip.sigstore.json")?)?;
        let out = exec(
            &[
                packslip.as_os_str(),
                OsStr::new("verify"),
                bundle.as_os_str(),
                OsStr::new("--artifact"),
                file.as_os_str(),
                OsStr::new("--pin"),
                OsStr::new(SIGNER_PIN),
            ],
            &[],
            Duration::from_secs(120),
        )?;
        let first = out.stdout.lines().next().unwrap_or("").trim().to_string();
        let expect = format!("ok: github.com/{REPO} {version}");
        if out.code != Some(0) || !(first == expect || first.starts_with(&format!("{expect} "))) {
            let why = if first.is_empty() { out.stderr.trim().to_string() } else { first };
            return Err(Error::Invalid(format!(
                "packslip did not verify {asset} as github.com/{REPO} {version}: {why}"
            )));
        }
        return Ok(format!("packslip (github.com/{REPO} {version}, signer {SIGNER_PIN})"));
    }
    if let Some(gh) = which("gh") {
        let out = exec(
            &[
                gh.as_os_str(),
                OsStr::new("attestation"),
                OsStr::new("verify"),
                file.as_os_str(),
                OsStr::new("--repo"),
                OsStr::new(REPO),
                OsStr::new("--signer-workflow"),
                OsStr::new(&format!("{REPO}/{RELEASE_WORKFLOW}")),
                OsStr::new("--source-ref"),
                OsStr::new(&format!("refs/tags/{tag}")),
            ],
            &[],
            Duration::from_secs(120),
        )?;
        if out.code != Some(0) {
            return Err(Error::Invalid(format!(
                "gh attestation verify failed for {asset} ({RELEASE_WORKFLOW} at {tag}): {}",
                out.stderr.trim().lines().last().unwrap_or("")
            )));
        }
        return Ok(format!("GitHub attestation ({REPO}, release.yml@{tag})"));
    }
    if let Some(cosign) = which("cosign") {
        let bundle = dir.join(format!("{asset}.sigstore.json"));
        std::fs::write(&bundle, download(net, version, &format!("{asset}.sigstore.json"))?)?;
        let identity = format!("https://github.com/{REPO}/{RELEASE_WORKFLOW}@refs/tags/{tag}");
        let out = exec(
            &[
                cosign.as_os_str(),
                OsStr::new("verify-blob"),
                file.as_os_str(),
                OsStr::new("--bundle"),
                bundle.as_os_str(),
                OsStr::new("--certificate-identity"),
                OsStr::new(&identity),
                OsStr::new("--certificate-oidc-issuer"),
                OsStr::new("https://token.actions.githubusercontent.com"),
            ],
            &[],
            Duration::from_secs(120),
        )?;
        if out.code != Some(0) {
            return Err(Error::Invalid(format!(
                "cosign did not verify {asset} as {identity}: {}",
                out.stderr.trim().lines().last().unwrap_or("")
            )));
        }
        return Ok(format!("cosign (release.yml@{tag})"));
    }
    Err(Error::Invalid(
        "no signature verifier is installed (packslip, gh or cosign): the download is not installed on its checksum alone. \
         See https://github.com/waffuruai/pantry/blob/main/docs/public/install.md#verify"
            .into(),
    ))
}

/// Put `verified` where `dest` is, atomically: written beside it, made
/// executable, renamed over; the old binary is kept as `dest.old` until the
/// next update, and put back if the new one doesn't run.
pub fn replace(verified: &Path, dest: &Path) -> Result<()> {
    let dir = dest.parent().ok_or_else(|| Error::Invalid(format!("{} has no directory", dest.display())))?;
    let staging = dir.join(format!(".wpantry-update-{}", std::process::id()));
    std::fs::copy(verified, &staging)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))?;
    }
    let old = dir.join("wpantry.old");
    let _ = std::fs::remove_file(&old);
    let had_old = dest.exists();
    if had_old {
        std::fs::rename(dest, &old)?;
    }
    if let Err(e) = std::fs::rename(&staging, dest) {
        let _ = std::fs::remove_file(&staging);
        if had_old {
            let _ = std::fs::rename(&old, dest);
        }
        return Err(e.into());
    }
    let smoke = exec(&[dest.as_os_str(), OsStr::new("version")], &[], Duration::from_secs(30));
    if !smoke.as_ref().is_ok_and(|o| o.code == Some(0)) {
        let _ = std::fs::remove_file(dest);
        if had_old {
            let _ = std::fs::rename(&old, dest);
        }
        return Err(Error::Failed(format!(
            "the new {} doesn't run on this computer; the old one is back",
            dest.display()
        )));
    }
    Ok(())
}

/// A temp dir for the download, private to us.
pub fn workdir() -> Result<TempDir> {
    TempDir::new("update")
}

#[cfg(test)]
mod tests {
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
}
