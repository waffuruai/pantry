//! OS updates: macOS Software Update, a Linux distro's advisories by the
//! source its os-release names, and the OS packages (dpkg, apk, rpm) against
//! OSV in the distro's own ecosystem.

use crate::checks::Scan;
use crate::checks::machine::os_packages;
use crate::component::Component;
use crate::error::{Error, Result};
use crate::finding::Finding;
use crate::sources::distros::Advisories;
use crate::sources::osv::Item;
use crate::sources::{distros, osv};
use crate::utils::os::{MACOS, now};
use crate::utils::{dates, os};
use std::collections::BTreeMap;

// OS ----------------------------------------------------------------------------

pub fn os_updates(scan: &mut Scan, macos_updates: (Vec<(String, String)>, String)) -> Result<()> {
    if MACOS {
        macos(scan, macos_updates);
        return Ok(());
    }
    linux_updates(scan, &os::os_release())
}

/// A Linux distro's packages, by the source its os-release names.
fn linux_updates(scan: &mut Scan, rel: &BTreeMap<String, String>) -> Result<()> {
    match os::os_family(rel) {
        "osv" => os_packages(scan, rel),
        "dnf" => {
            scan.status("Asking dnf for security advisories");
            let r = distros::dnf_advisories(&scan.cache, scan.opts.refresh, scan.opts.offline);
            if let Some(res) = scan.guard("OS packages", r.map(Some), None)? {
                distro(scan, rel, res);
            }
            Ok(())
        }
        "arch" => {
            scan.status("Fetching the Arch security tracker");
            let groups = distros::arch(&scan.cache, scan.net, scan.opts.offline);
            let r = groups.and_then(|g| distros::arch_advisories(&scan.cache, &g));
            if let Some(res) = scan.guard("OS packages", r.map(Some), None)? {
                distro(scan, rel, res);
            }
            Ok(())
        }
        _ => {
            let name =
                rel.get("PRETTY_NAME").or_else(|| rel.get("ID")).cloned().unwrap_or_else(|| "this distro".into());
            scan.unchecked(
                &format!("OS packages ({name})"),
                "no advisory source for this distro yet; binaries in system paths are checked against upstream versions instead",
            );
            Ok(())
        }
    }
}

fn macos(scan: &mut Scan, (updates, last): (Vec<(String, String)>, String)) {
    scan.status("Reading macOS Software Update's last scan");
    for (title, ver) in updates {
        scan.add(Finding {
            kind: "os".into(),
            component: title.trim().into(),
            location: "softwareupdate".into(),
            vuln_id: "OS-UPDATE".into(),
            status: "fail".into(),
            fixed: ver.trim().into(),
            note: "macOS updates (and Safari) carry security fixes".into(),
            fix_cmd: "System Settings → General → Software Update (or: sudo softwareupdate -i -a)".into(),
            ..Default::default()
        });
    }
    // "2026-10-20 08:15:32 +0000": stale after two weeks.
    let age = dates::parse_date(last.get(..10).unwrap_or("")).map(|d| now() - d as f64 * 86400.0).unwrap_or(0.0);
    if age > 14.0 * 86400.0 {
        scan.add(Finding {
            kind: "os".into(),
            component: "macOS".into(),
            location: "softwareupdate".into(),
            vuln_id: "OS-UPDATE".into(),
            status: "warn".into(),
            note: format!("Software Update last checked {}; results may be stale", last.get(..10).unwrap_or("")),
            fix_cmd: "softwareupdate --list".into(),
            ..Default::default()
        });
    }
}

/// dpkg, apk or rpm packages against OSV, in the distro's own ecosystem.
fn os_packages(scan: &mut Scan, rel: &BTreeMap<String, String>) -> Result<()> {
    let pretty = rel.get("PRETTY_NAME").or_else(|| rel.get("ID")).cloned().unwrap_or_else(|| "this distro".into());
    let eco = match os_packages::ecosystem(rel) {
        Ok(e) => e,
        Err(why) => {
            scan.unchecked(&format!("OS packages ({pretty})"), &why);
            return Ok(());
        }
    };
    scan.status("Reading the OS package database");
    os_packages_from(scan, rel, &pretty, &eco, os_packages::installed(rel))
}

/// The packages read from the OS database (or why they couldn't be)
/// against OSV.
fn os_packages_from(
    scan: &mut Scan,
    rel: &BTreeMap<String, String>,
    pretty: &str,
    eco: &str,
    installed: Result<Option<(String, Vec<crate::checks::lockfiles::Package>)>>,
) -> Result<()> {
    let (location, pkgs) = match installed {
        Ok(Some(found)) => found,
        Ok(None) => {
            scan.unchecked(&format!("OS packages ({pretty})"), "no package database found");
            return Ok(());
        }
        Err(e @ (Error::Missing(_) | Error::Io(_))) => {
            scan.unchecked(&format!("OS packages ({pretty})"), &e.to_string());
            return Ok(());
        }
        Err(e) if e.is_source() => {
            scan.unchecked(&format!("OS packages ({pretty})"), &e.to_string());
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    scan.count("OS packages", pkgs.len() as i64);
    let items: Vec<Item> = pkgs.iter().map(|p| (eco.to_string(), p.name.clone(), p.version.clone())).collect();
    let answers = scan.lookup(&items, "OS packages against OSV")?;
    for (p, item) in pkgs.iter().zip(items) {
        let Some(recs) = answers.get(&item).filter(|r| !r.is_empty()) else { continue };
        let mut c = Component::new("os", &p.name, &p.version, &location);
        c.fix = os::os_fix(rel, &p.name);
        let groups = osv::group_by_alias(recs);
        c.osv = Some(item);
        scan.advisories(&c, &[], None, "fail", Some(groups));
    }
    Ok(())
}

fn distro(scan: &mut Scan, rel: &BTreeMap<String, String>, res: Advisories) {
    scan.count("OS packages", res.packages);
    scan.unfixed += res.unfixed;
    for p in res.vulnerable {
        let kev = p.issues.iter().any(|i| scan.kev.contains(i));
        scan.add(Finding {
            kind: "os".into(),
            component: p.name.clone(),
            version: p.installed,
            location: "system packages".into(),
            vuln_id: p.advisory,
            status: "fail".into(),
            fixed: p.fixed,
            kev,
            severity: p.severity,
            note: p.issues.iter().take(4).cloned().collect::<Vec<_>>().join(", "),
            fix_cmd: os::os_fix(rel, &p.name),
            fix_auto: false,
            ..Default::default()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::machine::testing;
    use crate::utils::net::Fake;

    #[test]
    fn macos_updates_fail_and_a_stale_scan_warns() {
        let d = crate::utils::temp::TempDir::new("macos").unwrap();
        let net = Fake::offline();
        let mut s = testing::scan(&net, &d);
        let updates =
            vec![("macOS Sequoia 15.7.1 ".to_string(), " 15.7.1".to_string()), ("Safari".into(), "26.1".into())];
        macos(&mut s, (updates, "2024-01-01 08:15:32 +0000".into()));
        assert_eq!(
            testing::kinds(&s),
            [
                ("macOS Sequoia 15.7.1".to_string(), "OS-UPDATE".to_string(), "fail".to_string()),
                ("Safari".to_string(), "OS-UPDATE".to_string(), "fail".to_string()),
                ("macOS".to_string(), "OS-UPDATE".to_string(), "warn".to_string()),
            ]
        );
        assert_eq!(s.findings[0].fixed, "15.7.1");
        assert_eq!(s.findings[2].note, "Software Update last checked 2024-01-01; results may be stale");
        // No last scan date at all: nothing to call stale.
        let mut s2 = testing::scan(&net, &d);
        macos(&mut s2, (Vec::new(), String::new()));
        assert!(s2.findings.is_empty());
    }

    #[test]
    fn os_updates_on_this_machine_only_ever_report_unchecked_offline() {
        let d = crate::utils::temp::TempDir::new("os").unwrap();
        let net = Fake::offline();
        let mut s = testing::scan(&net, &d);
        // A Mac: Software Update's answer, given above. Linux: its package
        // database against OSV (unreachable here), or no source yet.
        os_updates(&mut s, (Vec::new(), String::new())).unwrap();
        if MACOS || os::os_family(&os::os_release()) != "dnf" {
            assert!(s.findings.iter().all(|f| f.kind == "unchecked"), "{:?}", testing::kinds(&s));
        }
    }

    #[test]
    fn distros_without_a_source_are_unchecked() {
        let d = crate::utils::temp::TempDir::new("distro").unwrap();
        let net = Fake::new(|r| {
            assert_eq!(r.url, distros::ARCH_URL);
            Ok(crate::utils::net::Response::ok(r#"[{"name": "ASA-1", "packages": ["x"]}]"#))
        });
        let mut s = testing::scan(&net, &d);
        linux_updates(&mut s, &testing::rel(&[("ID", "debian")])).unwrap();
        assert!(testing::unchecked_note(&s, "OS packages (debian)").starts_with("Debian without a VERSION_ID"));
        linux_updates(&mut s, &testing::rel(&[("ID", "gentoo"), ("PRETTY_NAME", "Gentoo Linux")])).unwrap();
        assert!(testing::unchecked_note(&s, "OS packages (Gentoo Linux)").starts_with("no advisory source"));
        linux_updates(&mut s, &testing::rel(&[])).unwrap();
        testing::unchecked_note(&s, "OS packages (this distro)");
        // dnf and pacman aren't on this machine (or answer for it): unchecked, never clean.
        let mut s2 = testing::scan(&net, &d);
        linux_updates(&mut s2, &testing::rel(&[("ID", "arch")])).unwrap();
        let mut s3 = testing::scan(&net, &d);
        linux_updates(&mut s3, &testing::rel(&[("ID", "fedora")])).unwrap();
        for s in [&s2, &s3] {
            assert!(s.findings.iter().all(|f| f.kind == "unchecked"), "{:?}", testing::kinds(s));
        }
    }

    #[test]
    fn os_packages_against_osv_in_the_distro_ecosystem() {
        use crate::checks::lockfiles::Package;
        let d = crate::utils::temp::TempDir::new("dpkg").unwrap();
        let net = Fake::new(|r| {
            use crate::utils::net::Response;
            if r.url.ends_with("/querybatch") {
                let body = r.body.clone().unwrap_or_default();
                return Ok(testing::querybatch(&body, &|pkg, _| {
                    if pkg == "acl" { vec!["DEBIAN-CVE-1"] } else { vec![] }
                }));
            }
            Ok(Response::ok(
                serde_json::json!({"id": "DEBIAN-CVE-1", "upstream": ["CVE-2026-4"], "modified": "m", "summary": "acl overflow",
                    "affected": [{"package": {"ecosystem": "Debian:13", "name": "acl"},
                                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.3.2-1"}]}]}]})
                .to_string(),
            ))
        });
        let mut s = testing::scan(&net, &d);
        let debian = testing::rel(&[("ID", "debian"), ("VERSION_ID", "13"), ("PRETTY_NAME", "Debian 13")]);
        let pkgs = vec![Package::new("", "acl", "2.3.1-1"), Package::new("", "bash", "5.2-1")];
        os_packages_from(&mut s, &debian, "Debian 13", "Debian:13", Ok(Some(("/var/lib/dpkg/status".into(), pkgs))))
            .unwrap();
        assert_eq!(s.counts, [("OS packages".to_string(), 2)]);
        assert_eq!(testing::kinds(&s), [("acl".to_string(), "DEBIAN-CVE-1".to_string(), "fail".to_string())]);
        let f = &s.findings[0];
        assert_eq!((f.kind.as_str(), f.location.as_str(), f.fixed.as_str()), ("os", "/var/lib/dpkg/status", "2.3.2-1"));
        assert_eq!(f.fix_cmd, "sudo apt-get update && sudo apt-get install --only-upgrade acl");
        // The database missing, unreadable or failing is unchecked; the cache failing is an error.
        let mut s2 = testing::scan(&net, &d);
        os_packages_from(&mut s2, &debian, "Debian 13", "Debian:13", Ok(None)).unwrap();
        assert_eq!(testing::unchecked_note(&s2, "OS packages (Debian 13)"), "no package database found");
        let mut s3 = testing::scan(&net, &d);
        os_packages_from(&mut s3, &debian, "Debian 13", "Debian:13", Err(Error::Missing("rpm".into()))).unwrap();
        assert!(testing::unchecked_note(&s3, "OS packages (Debian 13)").contains("rpm"));
        let mut s4 = testing::scan(&net, &d);
        os_packages_from(&mut s4, &debian, "Debian 13", "Debian:13", Err(Error::Failed("rpm -qa exited".into())))
            .unwrap();
        assert!(testing::unchecked_note(&s4, "OS packages (Debian 13)").contains("rpm -qa"));
        let mut s5 = testing::scan(&net, &d);
        let broken = Err(Error::Cache(rusqlite::Error::InvalidQuery));
        assert!(os_packages_from(&mut s5, &debian, "Debian 13", "Debian:13", broken).is_err());
    }

    #[test]
    fn a_suse_without_rpm_or_a_mac_has_no_package_database_to_read() {
        let d = crate::utils::temp::TempDir::new("suse").unwrap();
        let net = Fake::offline();
        let mut s = testing::scan(&net, &d);
        linux_updates(&mut s, &testing::rel(&[("ID", "sles"), ("VERSION_ID", "15.6"), ("PRETTY_NAME", "SLES 15")]))
            .unwrap();
        assert!(s.findings.iter().all(|f| f.kind == "unchecked"), "{:?}", testing::kinds(&s));
        assert!(s.findings.iter().any(|f| f.component.starts_with("OS packages")), "{:?}", testing::kinds(&s));
    }

    #[test]
    fn distro_advisories_become_os_findings() {
        let d = crate::utils::temp::TempDir::new("dnf").unwrap();
        let net = Fake::offline();
        let mut s = testing::scan(&net, &d);
        s.kev.insert("CVE-2026-5".into());
        let vuln = |name: &str, issues: &[&str]| distros::Vulnerable {
            name: name.into(),
            installed: "1.0-1".into(),
            fixed: "1.0-2".into(),
            advisory: format!("FEDORA-{name}"),
            severity: "Important".into(),
            issues: issues.iter().map(|i| i.to_string()).collect(),
        };
        let res = Advisories {
            packages: 1200,
            vulnerable: vec![vuln("openssl", &["CVE-2026-5", "CVE-2026-6"]), vuln("curl", &[])],
            unfixed: 3,
        };
        distro(&mut s, &testing::rel(&[("ID", "fedora")]), res);
        assert_eq!((s.counts[0].1, s.unfixed), (1200, 3));
        let f = &s.findings[0];
        assert_eq!(
            (f.kind.as_str(), f.component.as_str(), f.vuln_id.as_str(), f.kev),
            ("os", "openssl", "FEDORA-openssl", true)
        );
        assert_eq!(
            (f.note.as_str(), f.fixed.as_str(), f.severity.as_str()),
            ("CVE-2026-5, CVE-2026-6", "1.0-2", "Important")
        );
        assert!(f.fix_cmd.ends_with(" upgrade openssl"));
        assert!(!s.findings[1].kev);
    }
}
