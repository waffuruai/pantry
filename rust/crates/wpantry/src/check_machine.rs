//! Checks for this machine: tools, runtimes and their packages, apps and
//! browsers, OS updates and OS packages, Homebrew formulae, and the
//! certificate authorities it trusts.

use crate::catalog::{MISE_REPO, TOOLS};
use crate::check::{Finding, REMOVE, Scan, display_id, fill, is_kev, is_malicious};
use crate::db::severity_of;
use crate::distros::{self, Advisories};
use crate::error::{Error, Result};
use crate::feeds;
use crate::osdb;
use crate::osv::{self, Item};
use crate::system::{self, Component, MACOS, now};
use crate::{apps as apps_mod, catrust, cellar, packages, scanners, tools, versions};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// A browser release younger than this only warns.
pub const GRACE: f64 = 3.0 * 86400.0;

/// Formulae `--update` must not upgrade either: their catalog fix.
fn manual(formula: &str) -> Option<&'static str> {
    TOOLS.iter().find(|t| t.name == formula && !t.fix.is_empty()).map(|t| t.fix)
}

/// The machine checks; returns what the inventory found, for the
/// supply-chain sweep.
pub fn run(scan: &mut Scan) -> Result<Vec<Component>> {
    // The probes that need nothing from the scan run beside it: the trust
    // stores and Software Update's last scan, seconds of subprocesses each.
    std::thread::scope(|s| {
        let trust = s.spawn(catrust::check);
        let updates = s.spawn(apps_mod::macos_updates);
        let found = inventory(scan);
        components(scan, &found)?;
        apps(scan)?;
        os_updates(scan, joined(updates))?;
        brew(scan)?;
        ca_trust(scan, joined(trust));
        Ok(found)
    })
}

/// A probe's result; its panic, if it had one, carries on here.
fn joined<T>(probe: std::thread::ScopedJoinHandle<'_, T>) -> T {
    probe.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

pub fn inventory(scan: &mut Scan) -> Vec<Component> {
    std::thread::scope(|s| {
        let docker = s.spawn(apps_mod::docker);
        let mut found = inventory_local(scan);
        scan.status("Asking Docker for its engine version");
        found.extend(joined(docker));
        scan.count("tools, runtimes and packages", found.len() as i64);
        found
    })
}

/// What the machine has installed, without Docker's engine.
fn inventory_local(scan: &mut Scan) -> Vec<Component> {
    scan.status("Finding installed tools, runtimes and package managers");
    let mut found = tools::tools();
    // Bottles poured without the `brew` command (mise's brew: engine): read
    // from the Cellar, since `brew vulns` can't run and `tools` leaves
    // Cellar-owned binaries to it. With brew present, brew vulns covers them.
    if system::which("brew").is_none() {
        scan.status("Reading the Homebrew Cellar (no brew)");
        if let Some((cellar, inv)) = cellar::inventory() {
            scan.count("Homebrew formulae (Cellar, no brew)", inv.components.len() as i64);
            if !inv.unmapped.is_empty() {
                let shown: Vec<&str> = inv.unmapped.iter().take(6).map(String::as_str).collect();
                let more = if inv.unmapped.len() > 6 { ", …" } else { "" };
                scan.unchecked(
                    "Homebrew formulae wpantry can't map to OSV",
                    &format!(
                        "{} formulae in {} ({}{more}) have no catalog entry",
                        inv.unmapped.len(),
                        cellar.display(),
                        shown.join(", ")
                    ),
                );
            }
            found.extend(inv.components);
        }
    }
    scan.status("Listing Python installs and their pip packages");
    found.extend(packages::pythons());
    scan.status("Listing global npm packages");
    let npm = packages::node_packages(&found);
    found.extend(npm);
    scan.status("Listing Ruby gems, cargo installs and pipx tools");
    let gems = packages::gems(&found);
    found.extend(gems);
    found.extend(packages::cargo_installs());
    found.extend(packages::pipx_packages());
    found
}

/// OSV, end of life and (PostgreSQL) the project's own table.
pub fn components(scan: &mut Scan, found: &[Component]) -> Result<()> {
    let items: Vec<Item> = found.iter().filter_map(|c| c.osv.clone()).collect();
    let answers = scan.lookup(&items, "tools, runtimes and packages against OSV")?;
    // For upstream repos, ask OSV about the newer release tags too: the first
    // one it stops reporting an advisory for is the fix.
    let mut candidates: Vec<(Item, Vec<String>)> = Vec::new();
    for c in found {
        if let Some(it) = &c.osv
            && it.0 == "GIT"
            && answers.get(it).is_some_and(|r| !r.is_empty())
            && !candidates.iter().any(|(k, _)| k == it)
        {
            scan.status(&format!("Listing {}'s release tags", it.1));
            candidates.push((it.clone(), osv::candidates(&scan.cache, &it.1, &it.2, scan.opts.offline)?));
        }
    }
    let later_items: Vec<Item> =
        candidates.iter().flat_map(|(k, ts)| ts.iter().map(|t| ("GIT".to_string(), k.1.clone(), t.clone()))).collect();
    let later = scan.lookup(&later_items, "which releases fix upstream-repo advisories")?;
    let newer: HashMap<Item, BTreeMap<String, Vec<String>>> = candidates
        .into_iter()
        .map(|(k, ts)| {
            let m = ts
                .into_iter()
                .filter_map(|t| {
                    later
                        .get(&("GIT".to_string(), k.1.clone(), t.clone()))
                        .map(|recs| (t, recs.iter().map(|r| crate::json::str_at(r, "id").to_string()).collect()))
                })
                .collect();
            (k, m)
        })
        .collect();
    let pg = if found.iter().any(|c| c.name == "postgres") {
        scan.status("Fetching PostgreSQL's security table");
        let r = feeds::postgres(&scan.cache, scan.net, scan.opts.offline);
        scan.guard("PostgreSQL (postgresql.org security table)", r, Vec::new())?
    } else {
        Vec::new()
    };
    for c in found {
        let recs = c.osv.as_ref().and_then(|o| answers.get(o)).cloned().unwrap_or_default();
        let mut failing = scan.advisories(c, &recs, c.osv.as_ref().and_then(|o| newer.get(o)), "fail", None);
        if c.name == "postgres" {
            failing = postgres(scan, c, &pg)? || failing;
        }
        if c.name == "mise" {
            mise(scan, c)?;
        }
        if c.eol.is_some() {
            scan.eol(c, failing)?;
        }
    }
    Ok(())
}

/// A newer mise release only warns (OSV decides failures): a human bumps it
/// in ops, so the fix is never unattended.
pub fn mise(scan: &mut Scan, c: &Component) -> Result<()> {
    let r = feeds::github_latest(&scan.cache, scan.net, MISE_REPO, scan.opts.offline);
    let latest = scan.guard("latest mise release (GitHub)", r, String::new())?;
    if !latest.is_empty() && !versions::same_or_newer(&c.version, &latest) {
        scan.add(Finding {
            vuln_id: "OUTDATED".into(),
            status: "warn".into(),
            fixed: latest.clone(),
            fix_cmd: c.fix.clone(),
            fix_auto: false,
            note: format!(
                "mise {} is behind {latest}. mise is foundational infrastructure: bump MISE_VERSION in ops and rerun its scripts/bootstrap.sh; wpantry never updates it.",
                c.version
            ),
            ..Finding::of(c)
        });
    }
    Ok(())
}

/// An advisory applies when the installed major is listed and the install
/// is older than that major's fixed release.
pub fn postgres(scan: &mut Scan, c: &Component, advisories: &[feeds::PgAdvisory]) -> Result<bool> {
    let major = c.version.split('.').next().unwrap_or("").to_string();
    let mut failing = false;
    for a in advisories {
        let fixed = a.fixed.iter().find(|f| f.split('.').next() == Some(major.as_str())).cloned().unwrap_or_default();
        if !a.majors.contains(&major) || fixed.is_empty() || !versions::lt(&c.version, &fixed) {
            continue;
        }
        let sev = feeds::severity_from_score(a.score);
        if scan.cache.vuln(&a.cve)?.is_none() {
            scan.cache.put_vuln(&serde_json::json!({"id": a.cve, "summary": a.summary, "database_specific": {"severity": sev},
                                                    "affected": [{"package": {"ecosystem": "PostgreSQL", "name": "postgresql"}}]}))?;
        }
        let kev = scan.kev.contains(&a.cve);
        scan.add(Finding {
            vuln_id: a.cve.clone(),
            status: "fail".into(),
            fixed: fixed.clone(),
            kev,
            severity: sev.into(),
            note: format!("{} ({})", a.summary, a.component),
            fix_cmd: fill(&c.fix, &fixed),
            fix_auto: c.auto,
            ..Finding::of(c)
        });
        failing = true;
    }
    Ok(failing)
}

// Apps and browsers -----------------------------------------------------------

pub fn apps(scan: &mut Scan) -> Result<()> {
    scan.status("Reading installed apps");
    let mut found = apps_mod::apps();
    if found.is_empty() {
        return Ok(());
    }
    scan.count("apps", found.len() as i64);
    scan.status("Fetching the Homebrew cask catalog");
    let r = feeds::casks(&scan.cache, scan.net, scan.opts.offline);
    let catalog = scan.guard("latest app versions (Homebrew cask catalog)", r, BTreeMap::new())?;
    let casks = system::brew_casks();
    let items: Vec<Item> = found
        .iter()
        .filter_map(|a| a.extra.get("electron").map(|e| ("npm".to_string(), "electron".to_string(), e.clone())))
        .collect();
    let electron = scan.lookup(&items, "apps' bundled Electron against OSV")?;
    for a in &mut found {
        let (token, latest) =
            catalog.get(a.extra.get("bundle").map(String::as_str).unwrap_or("")).cloned().unwrap_or_default();
        (a.fix, a.auto) = if !token.is_empty() && casks.contains_key(&token) {
            (format!("brew upgrade --cask {token}"), true)
        } else {
            (format!("Update {} from its vendor (or its own updater)", a.name), false)
        };
        let behind = !latest.is_empty() && !versions::same_or_newer(&a.version, &latest);
        if a.kind == "browser" {
            browser(scan, a, behind, &latest)?;
            continue;
        }
        if let Some(ev) = a.extra.get("electron").cloned() {
            let recs = electron.get(&("npm".to_string(), "electron".to_string(), ev)).cloned().unwrap_or_default();
            if electron_finding(scan, a, &recs, behind, &latest) {
                continue;
            }
        }
        if behind {
            scan.add(Finding {
                vuln_id: "OUTDATED".into(),
                status: "warn".into(),
                fixed: latest.clone(),
                note: format!("latest release is {latest}"),
                fix_cmd: a.fix.clone(),
                fix_auto: a.auto,
                ..Finding::of(a)
            });
        }
    }
    Ok(())
}

/// Findings for an app's bundled Electron; false when it has none.
fn electron_finding(scan: &mut Scan, a: &Component, recs: &[Value], behind: bool, latest: &str) -> bool {
    let ev = a.extra.get("electron").cloned().unwrap_or_default();
    let bad: Vec<&Value> = recs
        .iter()
        .filter(|r| is_malicious(r) || !osv::fixed_versions(r, "npm", "electron", None).is_empty())
        .collect();
    if bad.is_empty() {
        return false;
    }
    let mut ids: Vec<String> = bad.iter().map(|r| display_id(r)).collect();
    ids.sort();
    ids.dedup();
    let kev = bad.iter().any(|r| is_kev(r, &scan.kev));
    let f = if behind {
        Finding {
            vuln_id: ids[0].clone(),
            status: "fail".into(),
            fixed: latest.into(),
            kev,
            note: format!("bundles Electron {ev} ({} fixed advisories); {latest} is out", ids.len()),
            fix_cmd: a.fix.clone(),
            fix_auto: a.auto,
            ..Finding::of(a)
        }
    } else {
        Finding {
            vuln_id: ids[0].clone(),
            status: "warn".into(),
            kev,
            note: format!("bundles Electron {ev} ({} fixed advisories); no newer app release yet", ids.len()),
            fix_cmd: format!("Ask the {} vendor to ship a newer Electron", a.name),
            ..Finding::of(a)
        }
    };
    scan.add(f);
    true
}

fn browser(scan: &mut Scan, a: &Component, behind: bool, latest: &str) -> Result<()> {
    match a.extra.get("browser").map(String::as_str).unwrap_or("") {
        "chrome" => {
            scan.status("Fetching Chrome's release feed");
            let r = feeds::chrome(&scan.cache, scan.net, "mac", scan.opts.offline);
            let releases = scan.guard("Chrome (Google's release feed)", r, Vec::new())?;
            let newest = releases
                .into_iter()
                .filter(|(v, _)| versions::lt(&a.version, v))
                .max_by(|x, y| versions::cmp(&x.0, &y.0));
            let (target, start) = newest.unwrap_or_default();
            browser_finding(scan, a, &target, start, "Chrome menu → About Google Chrome, then Relaunch");
        }
        "firefox" => {
            scan.status("Fetching Firefox's release feed");
            let r = feeds::firefox(&scan.cache, scan.net, scan.opts.offline).map(Some);
            if let Some(ff) = scan.guard("Firefox (Mozilla's release feed)", r, None)? {
                let major = a.version.split('.').next().unwrap_or("");
                let target =
                    ff.esr.iter().find(|e| e.split('.').next() == Some(major)).cloned().unwrap_or(ff.latest.clone());
                let start = ff.dates.get(&target).copied().unwrap_or(0.0);
                browser_finding(scan, a, &target, start, "Firefox menu → About Firefox, then Restart to Update");
            }
        }
        _ if behind => scan.add(Finding {
            vuln_id: "OUTDATED".into(),
            status: "warn".into(),
            fixed: latest.into(),
            note: format!("latest release is {latest}"),
            fix_cmd: a.fix.clone(),
            fix_auto: a.auto,
            ..Finding::of(a)
        }),
        _ => {}
    }
    Ok(())
}

fn browser_finding(scan: &mut Scan, a: &Component, target: &str, start: f64, how: &str) {
    if !target.is_empty() && versions::lt(&a.version, target) {
        let old = start > 0.0 && start < now() - GRACE;
        scan.add(Finding {
            vuln_id: "BROWSER".into(),
            status: if old { "fail" } else { "warn" }.into(),
            fixed: target.into(),
            note: format!("{} {target} is out; its releases carry security fixes", a.name),
            fix_cmd: if a.auto { a.fix.clone() } else { how.into() },
            fix_auto: a.auto,
            ..Finding::of(a)
        });
    }
}

// OS ----------------------------------------------------------------------------

pub fn os_updates(scan: &mut Scan, macos_updates: (Vec<(String, String)>, String)) -> Result<()> {
    if MACOS {
        macos(scan, macos_updates);
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
            let groups = feeds::arch(&scan.cache, scan.net, scan.opts.offline);
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
    let age = feeds::parse_date(last.get(..10).unwrap_or("")).map(|d| now() - d as f64 * 86400.0).unwrap_or(0.0);
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
            fix_cmd: system::os_fix(rel, &p.name),
            fix_auto: false,
        });
    }
}

// Homebrew ----------------------------------------------------------------------

pub fn brew(scan: &mut Scan) -> Result<()> {
    scan.status("Checking Homebrew formulae (brew vulns)");
    let res = match scanners::brew_vulns(&scan.cache, scan.opts.refresh, scan.opts.offline) {
        Ok(Some(r)) => r,
        Ok(None) => return Ok(()),
        Err(Error::Missing(_)) => {
            scan.add(Finding {
                kind: "tool".into(),
                component: "brew vulns".into(),
                vuln_id: "MISSING".into(),
                status: "fail".into(),
                note: "Homebrew formulae can't be checked".into(),
                fix_cmd: "brew update".into(),
                fix_auto: true,
                ..Default::default()
            });
            return Ok(());
        }
        Err(e) if e.is_source() => {
            scan.unchecked("Homebrew formulae (brew vulns)", &e.to_string());
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    scan.count("Homebrew formulae", res.get("checked").and_then(Value::as_i64).unwrap_or(0));
    for f in crate::json::arr_at(&res, "findings") {
        let formula = crate::json::str_at(f, "formula").to_string();
        let version = crate::json::str_at(f, "version").to_string();
        let (fix, auto) = match manual(&formula) {
            Some(m) => (m.to_string(), false),
            None => (format!("brew upgrade {formula}"), true),
        };
        let mut c = Component::new("brew", &formula, &version, "Homebrew");
        c.fix = fix;
        c.auto = auto;
        for v in crate::json::arr_at(f, "vulnerabilities") {
            let rec = serde_json::json!({"id": crate::json::str_at(v, "id"), "aliases": v.get("aliases").cloned().unwrap_or(serde_json::json!([]))});
            let fixes: Vec<String> =
                crate::json::strs_at(v, "fixed_versions").into_iter().filter(|x| osv::released(x)).collect();
            if is_malicious(&rec) {
                scan.add(Finding {
                    vuln_id: crate::json::str_at(v, "id").into(),
                    status: "fail".into(),
                    kev: true,
                    severity: "MALICIOUS".into(),
                    note: crate::json::str_at(v, "summary").into(),
                    fix_cmd: REMOVE.replace("{}", &formula),
                    ..Finding::of(&c)
                });
            } else if fixes.is_empty() {
                scan.unfixed += 1;
            } else {
                let sev = crate::json::str_at(v, "severity").to_uppercase();
                scan.add(Finding {
                    vuln_id: display_id(&rec),
                    status: "fail".into(),
                    kev: is_kev(&rec, &scan.kev),
                    fixed: versions::pick_safe(&version, &fixes).unwrap_or_else(|| fixes[0].clone()),
                    severity: if sev.is_empty() { severity_of(&rec) } else { sev },
                    note: crate::json::str_at(v, "summary").into(),
                    fix_cmd: c.fix.clone(),
                    fix_auto: c.auto,
                    ..Finding::of(&c)
                });
            }
        }
    }
    Ok(())
}

// Certificate authorities -------------------------------------------------------

/// Trust stores that still trust a distrusted CA fail (Python ran this as
/// `check-ca-trust.sh` beside the scan; here it is part of it).
pub fn ca_trust(scan: &mut Scan, stores: Result<Vec<catrust::Store>>) {
    scan.status("Checking trust stores for distrusted CAs");
    match stores {
        Ok(stores) => {
            scan.count("CA trust stores", stores.len() as i64);
            for s in &stores {
                if let Some(why) = &s.unchecked {
                    scan.unchecked(&format!("CA trust: {} {}", s.label, s.shown), why);
                }
            }
            for s in stores.into_iter().filter(|s| s.trusts) {
                scan.add(Finding {
                    kind: "config".into(),
                    component: format!("CA trust: {} {}", s.label, s.shown),
                    vuln_id: "DISTRUSTED-CA".into(),
                    status: "fail".into(),
                    note: format!("trusts the leaked eMudhra intermediate CAs ({})", catrust::ADVISORY),
                    fix_cmd: s.hint,
                    ..Default::default()
                });
            }
        }
        Err(Error::Missing(_)) => scan.add(Finding {
            kind: "tool".into(),
            component: "openssl".into(),
            vuln_id: "MISSING".into(),
            status: "fail".into(),
            note: "the trust stores can't be checked for distrusted CAs".into(),
            fix_cmd: "Install openssl".into(),
            ..Default::default()
        }),
        Err(e) => scan.unchecked("CA trust stores", &e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::MISE_FIX;
    use crate::db::Cache;
    use crate::net::Fake;

    fn scan<'a>(net: &'a Fake, d: &crate::system::TempDir) -> Scan<'a> {
        Scan::new(Default::default(), Cache::open(Some(&d.path().join("w.db"))).unwrap(), net, &|_| {}, &|_| {})
    }

    // The test vectors the Python implementation had (`Mise`).
    #[test]
    fn mise_behind_latest_release_warns_and_is_never_unattended() {
        let d = crate::system::TempDir::new("mise").unwrap();
        let net = Fake::new(|r| {
            assert_eq!(r.url, "https://api.github.com/repos/jdx/mise/releases/latest");
            Ok(crate::net::Response::ok(r#"{"tag_name": "v2026.10.21"}"#))
        });
        let mut s = scan(&net, &d);
        let mut c = Component::new("manager", "mise", "2026.10.19", "/h/.local/bin/mise");
        c.fix = MISE_FIX.into();
        mise(&mut s, &c).unwrap();
        let f = &s.findings[0];
        assert_eq!(
            (f.vuln_id.as_str(), f.status.as_str(), f.fixed.as_str(), f.fix_cmd.as_str(), f.fix_auto),
            ("OUTDATED", "warn", "2026.10.21", MISE_FIX, false)
        );
        assert_eq!(
            f.note,
            "mise 2026.10.19 is behind 2026.10.21. mise is foundational infrastructure: bump MISE_VERSION in ops and rerun its scripts/bootstrap.sh; wpantry never updates it."
        );
        // Cached for a day: GitHub isn't asked again.
        let quiet = Fake::new(|_| panic!("cached"));
        let mut s2 = Scan::new(Default::default(), s.cache, &quiet, &|_| {}, &|_| {});
        mise(&mut s2, &c).unwrap();
    }

    #[test]
    fn unreachable_github_is_unchecked_not_clean() {
        let d = crate::system::TempDir::new("mise").unwrap();
        let net = Fake::new(|_| Ok(crate::net::Response { status: 403, body: vec![], etag: None }));
        let mut s = scan(&net, &d);
        mise(&mut s, &Component::new("manager", "mise", "2026.10.19", "")).unwrap();
        assert_eq!(
            (s.findings[0].kind.as_str(), s.findings[0].component.as_str()),
            ("unchecked", "latest mise release (GitHub)")
        );
    }

    #[test]
    fn postgres_advisories_by_major() {
        let d = crate::system::TempDir::new("pg").unwrap();
        let net = Fake::offline();
        let mut s = scan(&net, &d);
        let mut c = Component::new("datastore", "postgres", "17.4", "/usr/bin/postgres");
        c.fix = "Upgrade postgres to {safe}".into();
        let adv = feeds::PgAdvisory {
            cve: "CVE-2026-1".into(),
            majors: vec!["17".into(), "16".into()],
            fixed: vec!["17.6".into(), "16.10".into()],
            component: "core server".into(),
            score: 8.8,
            vector: String::new(),
            summary: "Heap overflow".into(),
        };
        assert!(postgres(&mut s, &c, &[adv]).unwrap());
        let f = &s.findings[0];
        assert_eq!(
            (f.fixed.as_str(), f.severity.as_str(), f.fix_cmd.as_str()),
            ("17.6", "HIGH", "Upgrade postgres to 17.6")
        );
    }

    #[test]
    fn brew_vulns_finding_for_mise_stays_manual() {
        assert_eq!(manual("mise"), Some(MISE_FIX));
        assert_eq!(manual("node"), None);
    }
}
