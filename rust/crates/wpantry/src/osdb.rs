//! Linux package databases (F6) and the `os-release` → OSV ecosystem table
//! (F7). dpkg reports source packages (`Source:`, with its own version when
//! it names one), apk reports origins (`o:`), rpm reports names; that is how
//! the distros' advisories name what they fix.
//!
//! The ecosystem table follows osv-scalibr's `MakeEcosystem` and its tests
//! (the extractor library osv-scanner runs), which are the authority: a
//! distro is mapped by its own `ID` only, never by `ID_LIKE` (a derivative's
//! `VERSION_ID` is its own, so borrowing its parent's ecosystem would ask
//! about the wrong release and come back silently clean). Anything unmapped
//! is reported unchecked, never clean.

use crate::error::{Error, Result};
use crate::lockfiles::Package;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

pub const DPKG_STATUS: &str = "/var/lib/dpkg/status";
pub const APK_INSTALLED: &str = "/lib/apk/db/installed";
pub const MAX_DB: u64 = 256 << 20;

/// The OSV ecosystem for this distro's packages, or why there is none.
pub fn ecosystem(rel: &BTreeMap<String, String>) -> std::result::Result<String, String> {
    let id = rel.get("ID").map(String::as_str).unwrap_or("");
    let ver = rel.get("VERSION_ID").map(String::as_str).unwrap_or("");
    let need_version =
        |what: &str| Err(format!("{what} without a VERSION_ID (testing or unstable) has no OSV release to match"));
    match id {
        "debian" if ver.is_empty() => need_version("Debian"),
        "debian" => Ok(format!("Debian:{ver}")),
        "ubuntu" if ver.is_empty() => need_version("Ubuntu"),
        "ubuntu" => Ok(format!("Ubuntu:{ver}")),
        "alpine" if ver.is_empty() => need_version("Alpine"),
        "alpine" => {
            let parts: Vec<&str> = ver.split('.').collect();
            Ok(format!("Alpine:v{}", parts[..parts.len().min(2)].join(".")))
        }
        "wolfi" => Ok("Wolfi".into()),
        "chainguard" => Ok("Chainguard".into()),
        "opensuse-leap" if ver.is_empty() => need_version("openSUSE Leap"),
        "opensuse-leap" => Ok(format!("openSUSE:Leap {ver}")),
        "opensuse-tumbleweed" => Ok("openSUSE:Tumbleweed".into()),
        "sles" if ver.is_empty() => need_version("SUSE"),
        "sles" => Ok(format!("SUSE:{ver}")),
        "" => Err("no os-release ID".into()),
        other => Err(format!("no OSV ecosystem for os-release ID {other:?}")),
    }
}

/// Source packages installed according to a dpkg status file.
pub fn dpkg(text: &str) -> Vec<Package> {
    let mut out = BTreeSet::new();
    for stanza in text.split("\n\n") {
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for line in stanza.lines() {
            if line.starts_with([' ', '\t']) {
                continue; // a continuation line of a multi-line field
            }
            if let Some((k, v)) = line.split_once(':') {
                fields.insert(k, v.trim());
            }
        }
        if fields.get("Status").map(|s| s.split_whitespace().collect::<Vec<_>>())
            != Some(vec!["install", "ok", "installed"])
        {
            continue;
        }
        let (Some(pkg), Some(ver)) = (fields.get("Package"), fields.get("Version")) else { continue };
        let (name, version) = match fields.get("Source") {
            Some(src) => match src.split_once('(') {
                Some((n, v)) => (n.trim(), v.trim_end_matches(')').trim()),
                None => (*src, *ver),
            },
            None => (*pkg, *ver),
        };
        out.insert((name.to_string(), version.to_string()));
    }
    out.into_iter().map(|(n, v)| Package::new("", &n, &v)).collect()
}

/// Origin packages installed according to an apk database.
pub fn apk(text: &str) -> Vec<Package> {
    let mut out = BTreeSet::new();
    for record in text.split("\n\n") {
        let (mut p, mut v, mut o) = ("", "", "");
        for line in record.lines() {
            match line.split_once(':') {
                Some(("P", x)) => p = x,
                Some(("V", x)) => v = x,
                Some(("o", x)) => o = x,
                _ => {}
            }
        }
        let name = if o.is_empty() { p } else { o };
        if !name.is_empty() && !v.is_empty() {
            out.insert((name.to_string(), v.to_string()));
        }
    }
    out.into_iter().map(|(n, v)| Package::new("", &n, &v)).collect()
}

/// Installed rpm packages (openSUSE and SUSE), from
/// `rpm -qa --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\n'`; a zero
/// epoch is dropped, as the advisories write versions.
pub fn rpm_listing(out: &str) -> Vec<Package> {
    let mut pkgs = BTreeSet::new();
    for line in out.lines() {
        let Some((name, ver)) = line.trim().split_once(' ') else { continue };
        if name == "gpg-pubkey" || ver.is_empty() {
            continue;
        }
        let ver = ver.strip_prefix("0:").unwrap_or(ver);
        pkgs.insert((name.to_string(), ver.to_string()));
    }
    pkgs.into_iter().map(|(n, v)| Package::new("", &n, &v)).collect()
}

/// The installed packages of this Linux machine with where they came from,
/// or None when it has no package database we read.
pub fn installed(rel: &BTreeMap<String, String>) -> Result<Option<(String, Vec<Package>)>> {
    let id = rel.get("ID").map(String::as_str).unwrap_or("");
    if Path::new(DPKG_STATUS).is_file() {
        let text = crate::system::read_capped(Path::new(DPKG_STATUS), MAX_DB)?;
        return Ok(Some((DPKG_STATUS.into(), dpkg(&text))));
    }
    if Path::new(APK_INSTALLED).is_file() {
        let text = crate::system::read_capped(Path::new(APK_INSTALLED), MAX_DB)?;
        return Ok(Some((APK_INSTALLED.into(), apk(&text))));
    }
    if id.contains("suse") || id == "sles" {
        let rpm = crate::system::which("rpm").ok_or_else(|| Error::Missing("rpm".into()))?;
        let out = crate::system::exec(
            &[
                rpm.as_os_str(),
                "-qa".as_ref(),
                "--qf".as_ref(),
                "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n".as_ref(),
            ],
            &[],
            Duration::from_secs(300),
        )?;
        if out.code != Some(0) {
            return Err(Error::Failed(format!("rpm -qa exited {:?}: {}", out.code, out.stderr.trim())));
        }
        return Ok(Some(("rpm".into(), rpm_listing(&out.stdout))));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::parse_os_release;

    fn eco(text: &str) -> std::result::Result<String, String> {
        ecosystem(&parse_os_release(text))
    }

    /// osv-scalibr's extractor/filesystem/os/ecosystem tests (MakeEcosystem),
    /// for the distros this reads.
    #[test]
    fn scalibr_conformance() {
        assert_eq!(eco("ID=debian\nVERSION_ID=\"12\"\n"), Ok("Debian:12".into()));
        assert_eq!(eco("ID=alpine\nVERSION_ID=4.5.6\n"), Ok("Alpine:v4.5".into()));
        assert_eq!(eco("ID=alpine\nVERSION_ID=4\n"), Ok("Alpine:v4".into()));
        assert_eq!(eco("ID=wolfi\n"), Ok("Wolfi".into()));
        assert_eq!(eco("ID=chainguard\n"), Ok("Chainguard".into()));
        assert_eq!(eco("ID=opensuse-leap\nVERSION_ID=\"15.5\"\n"), Ok("openSUSE:Leap 15.5".into()));
        assert_eq!(eco("ID=sles\nVERSION_ID=\"15.5\"\n"), Ok("SUSE:15.5".into()));
        assert_eq!(
            eco("ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.5 LTS (Noble Numbat)\"\n"),
            Ok("Ubuntu:24.04".into())
        );
        // OpenWrt and other IDs have no OSV ecosystem.
        assert!(eco("ID=openwrt\nVERSION_ID=22.03.5\n").is_err());
    }

    #[test]
    fn unmapped_is_unchecked_never_clean() {
        assert!(eco("ID=debian\n").is_err(), "sid has no release to match");
        assert!(eco("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=22\n").is_err(), "derivatives aren't guessed");
        assert!(eco("").is_err());
    }

    #[test]
    fn dpkg_source_packages() {
        let status = "Package: libssl3t64\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.13-0ubuntu3.5\nDescription: x\n continued line: not a field\n\nPackage: openssl\nStatus: install ok installed\nVersion: 3.0.13-0ubuntu3.5\n\nPackage: libgcc-s1\nStatus: install ok installed\nSource: gcc-14 (14.2.0-4ubuntu2~24.04)\nVersion: 14.2.0-4ubuntu2~24.04\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 1.0\n";
        let got: Vec<(String, String)> = dpkg(status).into_iter().map(|p| (p.name, p.version)).collect();
        assert_eq!(
            got,
            [("gcc-14".into(), "14.2.0-4ubuntu2~24.04".into()), ("openssl".into(), "3.0.13-0ubuntu3.5".into())]
        );
    }

    #[test]
    fn apk_origins() {
        let db = "C:Q1x=\nP:libcrypto3\nV:3.3.2-r0\no:openssl\n\nP:busybox\nV:1.36.1-r29\n\nP:libssl3\nV:3.3.2-r0\no:openssl\n";
        let got: Vec<(String, String)> = apk(db).into_iter().map(|p| (p.name, p.version)).collect();
        assert_eq!(got, [("busybox".into(), "1.36.1-r29".into()), ("openssl".into(), "3.3.2-r0".into())]);
    }

    #[test]
    fn rpm_names() {
        let got = rpm_listing("curl 0:8.6.0-150600.4.6.1\ngpg-pubkey 0:39db7c82-5f68629b\nfoo 1:2.0-1\n");
        let got: Vec<(String, String)> = got.into_iter().map(|p| (p.name, p.version)).collect();
        assert_eq!(got, [("curl".into(), "8.6.0-150600.4.6.1".into()), ("foo".into(), "1:2.0-1".into())]);
    }
}
