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
#[path = "os_updates_tests.rs"]
mod tests;
