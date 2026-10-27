//! Checks for this machine. Ported so far: Linux OS packages (F6) — the
//! dpkg, apk and rpm databases asked of OSV directly, dnf's own advisories
//! and the Arch tracker. The rest of the inventory (tools, runtimes and
//! their packages, apps, browsers, macOS updates, Homebrew, editors,
//! harness configs, running containers, CA trust, the breach check) is
//! phase 2 and reported unchecked until then, never clean.

use crate::check::{Finding, Scan};
use crate::check_supply::PHASE_2;
use crate::distros::{self, Advisories};
use crate::error::{Error, Result};
use crate::osdb;
use crate::osv::{self, Item};
use crate::system::{self, Component, MACOS};

pub const INVENTORY: &str = "machine inventory: tools, runtimes, packages, apps, browsers, Homebrew, editors, \
                             harness configs, running containers, CA trust, breach check";

pub fn run(scan: &mut Scan) -> Result<()> {
    os_updates(scan)?;
    scan.unchecked(INVENTORY, PHASE_2);
    Ok(())
}

pub fn os_updates(scan: &mut Scan) -> Result<()> {
    if MACOS {
        scan.unchecked("macOS Software Update", PHASE_2);
        return Ok(());
    }
    let rel = system::os_release();
    match system::os_family(&rel) {
        "osv" => os_packages(scan, &rel),
        "dnf" => {
            scan.status("Asking dnf for security advisories");
            let r = distros::dnf_advisories(&scan.cache, scan.opts.refresh, scan.opts.offline);
            if let Some(res) = scan.guard("OS packages", r.map(Some), None)? {
                distro(scan, &rel, res);
            }
            Ok(())
        }
        "arch" => {
            scan.status("Fetching the Arch security tracker");
            let groups = crate::feeds::arch(&scan.cache, scan.net, scan.opts.offline);
            let r = groups.and_then(|g| distros::arch_advisories(&scan.cache, &g));
            if let Some(res) = scan.guard("OS packages", r.map(Some), None)? {
                distro(scan, &rel, res);
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

/// dpkg, apk or rpm packages against OSV, in the distro's own ecosystem.
fn os_packages(scan: &mut Scan, rel: &std::collections::BTreeMap<String, String>) -> Result<()> {
    let pretty = rel.get("PRETTY_NAME").or_else(|| rel.get("ID")).cloned().unwrap_or_else(|| "this distro".into());
    let eco = match osdb::ecosystem(rel) {
        Ok(e) => e,
        Err(why) => {
            scan.unchecked(&format!("OS packages ({pretty})"), &why);
            return Ok(());
        }
    };
    scan.status("Reading the OS package database");
    let (location, pkgs) = match osdb::installed(rel) {
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
    let items: Vec<Item> = pkgs.iter().map(|p| (eco.clone(), p.name.clone(), p.version.clone())).collect();
    let answers = scan.lookup(&items, "OS packages against OSV")?;
    for (p, item) in pkgs.iter().zip(items) {
        let Some(recs) = answers.get(&item).filter(|r| !r.is_empty()) else { continue };
        let mut c = Component::new("os", &p.name, &p.version, &location);
        c.fix = system::os_fix(rel, &p.name);
        let groups = osv::group_by_alias(recs);
        c.osv = Some(item);
        scan.advisories(&c, &[], None, "fail", Some(groups));
    }
    Ok(())
}

fn distro(scan: &mut Scan, rel: &std::collections::BTreeMap<String, String>, res: Advisories) {
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
            fix_cmd: system::os_fix(rel, &p.name),
            fix_auto: false,
        });
    }
}
