//! Checks for this machine: tools, runtimes and their packages, apps and
//! browsers, OS updates and OS packages, Homebrew formulae, and the
//! certificate authorities it trusts.

pub mod any;
pub mod apps;
pub mod brew_vulns;
pub mod ca_trust;
pub mod catalog;
pub mod cellar;
pub mod clipper;
pub mod editors;
pub mod harnesses;
pub mod images;
pub mod linux;
pub mod macos;
pub mod os_packages;
pub mod packages;
pub mod settings;
#[cfg(test)]
mod testing;
pub mod tools;

use crate::checks::ecosystems::versions;
use crate::checks::{REMOVE, Scan, display_id, fill, is_kev, is_malicious};
use crate::component::Component;
use crate::db::severity_of;
use crate::error::{Error, Result};
use crate::finding::Finding;
use crate::sources::distros::{self, Advisories};
use crate::sources::endoflife;
use crate::sources::osv::{self, Item};
use crate::sources::releases;
use crate::utils::dates;
use crate::utils::os::MACOS;
use crate::utils::os::now;
use crate::utils::{files, homebrew, os, process};
use catalog::{MISE_REPO, TOOLS};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use {apps as apps_mod, clipper as clipper_mod};

/// A browser release younger than this only warns.
pub const GRACE: f64 = 3.0 * 86400.0;

/// Formulae `wpantry fix` must not upgrade either: their catalog fix.
fn manual(formula: &str) -> Option<&'static str> {
    TOOLS.iter().find(|t| t.name == formula && !t.fix.is_empty()).map(|t| t.fix)
}

/// The machine checks; returns what the inventory found, for the
/// supply-chain sweep.
pub fn run(scan: &mut Scan) -> Result<Vec<Component>> {
    // The probes that need nothing from the scan run beside it: the trust
    // stores and Software Update's last scan, seconds of subprocesses each.
    // brew vulns takes minutes on a first run: it starts now, beside the
    // inventory and the OSV round trips, and is read at the end.
    let brew_job = brew_vulns::brew_job(&scan.cache, scan.opts.refresh, scan.opts.offline)?;
    std::thread::scope(|s| {
        let trust = s.spawn(ca_trust::check);
        let updates = s.spawn(apps_mod::macos_updates);
        let clip = (!scan.opts.no_clipboard).then(|| s.spawn(clipper_mod::run_self_test));
        let home = scan.home.clone();
        let persist = s.spawn(move || {
            crate::checks::machine::any::persistence::gather(&crate::checks::machine::any::persistence::Roots::real(
                home,
            ))
        });
        let brew_ran = brew_job.as_ref().filter(|j| j.stale).map(|j| s.spawn(move || brew_vulns::brew_scan(j)));
        let found = inventory(scan);
        components(scan, &found)?;
        apps(scan)?;
        os_updates(scan, joined(updates))?;
        brew(scan, brew_job.as_ref(), brew_ran.map(joined))?;
        downloads(scan);
        ca_trust(scan, joined(trust));
        if !scan.opts.no_posture {
            posture(scan);
        }
        persistence(scan, joined(persist));
        clipper(scan, clip.map(joined));
        Ok(found)
    })
}

/// The top of `~/Downloads`, `~/Desktop` and `~/Documents`: the documents and images
/// people are sent, read for the shapes malware takes, and ClamAV over
/// them when it is installed.
fn downloads(scan: &mut Scan) {
    let home = crate::utils::files::home();
    let dirs: Vec<std::path::PathBuf> =
        ["Downloads", "Desktop", "Documents"].iter().map(|d| home.join(d)).filter(|d| d.is_dir()).collect();
    if dirs.is_empty() {
        return;
    }
    scan.status("Reading the documents and images in Downloads, Desktop and Documents");
    let mut files = Vec::new();
    for dir in &dirs {
        for d in crate::checks::documents::scan_dir(dir, 1) {
            let component = crate::utils::files::short(&dir.join(&d.file).to_string_lossy());
            crate::checks::supply_chain::add_doc(scan, &component, d);
        }
        files.extend(crate::checks::documents::files_under(dir, 1));
    }
    scan.count("documents and images in Downloads, Desktop and Documents", files.len() as i64);
    crate::checks::supply_chain::clamav(scan, &files, "Downloads, Desktop and Documents");
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
    if process::which("brew").is_none() {
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
    let (pythons, unread) = packages::pythons();
    found.extend(pythons);
    for (py, why) in unread {
        scan.unchecked(&format!("pip packages of {py}"), &why.join("; "));
    }
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
                        .map(|recs| (t, recs.iter().map(|r| crate::utils::json::str_at(r, "id").to_string()).collect()))
                })
                .collect();
            (k, m)
        })
        .collect();
    let pg = if found.iter().any(|c| c.name == "postgres") {
        scan.status("Fetching PostgreSQL's security table");
        let r = releases::postgres(&scan.cache, scan.net, scan.opts.offline);
        scan.guard("PostgreSQL (postgresql.org security table)", r, Vec::new())?
    } else {
        Vec::new()
    };
    // endoflife.date is one request per product: fetch the stale ones side
    // by side before the loop asks for each.
    let products: Vec<String> = found.iter().filter_map(|c| c.eol.as_ref().map(|(p, _)| p.clone())).collect();
    scan.status("Fetching end-of-life dates");
    endoflife::eol_prefetch(&scan.cache, scan.net, &products, scan.opts.offline)?;
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

/// The machine's own security settings (`posture`): a failing Critical or
/// High check fails, the rest warn, a check that can't tell says so.
pub fn posture(scan: &mut Scan) {
    posture_with(scan, &crate::checks::machine::settings::real_runner)
}

/// The posture checks over `runner` (the real machine, or a recording).
fn posture_with(scan: &mut Scan, runner: crate::checks::machine::settings::Runner) {
    use crate::checks::machine::settings::{self, Severity, Status};
    scan.status("Checking the machine's security settings");
    let skip = scan.opts.policy.posture_skip();
    let results = settings::run(&skip, runner);
    scan.count("security settings checked", results.len() as i64);
    for (c, o) in results {
        let (status, note) = match o.status {
            Status::Pass => continue,
            Status::Fail if matches!(c.severity, Severity::Critical | Severity::High) => ("fail", o.evidence),
            Status::Fail => ("warn", o.evidence),
            Status::Manual => ("warn", o.evidence),
            Status::Unknown => ("warn", format!("couldn't tell: {}", o.evidence)),
        };
        let (fix_cmd, fix_auto) = match &c.fix {
            Some(f) => (f.cmd.to_string(), !f.admin && o.status == Status::Fail),
            None => (c.explain.to_string(), false),
        };
        scan.add(Finding {
            kind: "posture".into(),
            component: c.title.into(),
            location: if c.cis.is_empty() { String::new() } else { format!("CIS {}", c.cis) },
            vuln_id: c.id.into(),
            status: status.into(),
            severity: c.severity.as_str().into(),
            note,
            fix_cmd,
            fix_auto,
            ..Default::default()
        });
    }
}

/// Persistence: every place a program can arrange to run again (listed
/// and checked beside the other probes), diffed against the last scan's
/// list in the cache's `persistence` table. Runs with the machine inventory
/// whatever `--no-posture` says, as the clipper's persistence check does:
/// it is malware's footing, not a setting.
pub fn persistence(scan: &mut Scan, (inv, vetted): crate::checks::machine::any::persistence::Gathered) {
    use crate::checks::machine::any::persistence as p;
    scan.status("Comparing launch agents, login items and the other persistence places with the last scan");
    scan.count("persistence items listed", inv.items.len() as i64);
    for (source, why) in &inv.unread {
        scan.unchecked(&format!("persistence: {}s", source.what()), why);
    }
    let (new, first) = match p::diff(&scan.cache, &inv, now()) {
        Ok(d) => d,
        Err(e) => {
            scan.unchecked("persistence baseline", &e.to_string());
            (Vec::new(), Vec::new())
        }
    };
    let baselined = inv.items.iter().filter(|i| first.contains(&i.source)).count();
    scan.count("persistence items recorded as the baseline (first scan)", baselined as i64);
    for f in p::findings(&inv, &new, &vetted, &|path| files::short(&path.to_string_lossy())) {
        scan.add(f);
    }
}

/// Clipboard clippers: the persisted programs that touch the clipboard
/// with wallet addresses in hand, and the self-test's canaries that came
/// back changed. Both are Critical: money sent from this machine goes
/// elsewhere.
pub fn clipper(scan: &mut Scan, self_test: Option<clipper_mod::SelfTest>) {
    use clipper_mod::SelfTest;
    scan.status("Looking for clipboard clippers");
    let (found, read) = clipper_mod::persistence();
    scan.count("launch agents and autostart items read", read as i64);
    for p in found {
        scan.add(Finding {
            kind: "clipper".into(),
            component: p.item.clone(),
            location: p.program.clone(),
            vuln_id: "CLIPPER-PERSISTENCE".into(),
            status: if p.hard { "fail" } else { "warn" }.into(),
            severity: if p.hard { "CRITICAL" } else { "" }.into(),
            note: p.note(),
            fix_cmd: if p.hard {
                format!(
                    "Don't send funds from this machine until it is gone. Unload it (launchctl bootout gui/$(id -u) {}; or remove the autostart entry), move the program aside for a look, check login items and browser extensions for the same, then change the passwords and move the wallets that were used here",
                    p.item
                )
            } else {
                format!("Read what {} is and who installed it; a clipboard manager you installed is fine, anything you don't recognise is not", p.program)
            },
            fix_auto: false,
            ..Default::default()
        });
    }
    match self_test {
        None => {}
        Some(SelfTest::Skipped(why)) => scan.unchecked("clipboard self-test", &why),
        Some(SelfTest::Clean(n)) => scan.count("clipboard canaries copied and read back unchanged", n as i64),
        Some(SelfTest::Swapped(swaps)) => {
            for s in swaps {
                scan.add(Finding {
                    kind: "clipper".into(),
                    component: "clipboard".into(),
                    location: s.chain.name().into(),
                    vuln_id: "CLIPPER-ACTIVE".into(),
                    status: "fail".into(),
                    severity: "CRITICAL".into(),
                    note: format!(
                        "a {} address copied to the clipboard came back as {} on read {}: something on this machine rewrites the clipboard (a clipper). If Handoff / Universal Clipboard is on, other Apple devices receive the swapped address too; the clipper is here, not on them",
                        s.chain.name(),
                        s.got,
                        s.read
                    ),
                    fix_cmd: format!(
                        "Don't send funds from this machine. Find what rewrites the clipboard (the CLIPPER-PERSISTENCE findings, login items, browser extensions, recently installed apps), remove it or reinstall the OS, then report {} on chainabuse.com and the chain's explorer so the next person who searches it is warned",
                        s.got
                    ),
                    fix_auto: false,
                    ..Default::default()
                });
            }
        }
    }
}

/// A newer mise release only warns (OSV decides failures): a human bumps it
/// in ops, so the fix is never unattended.
pub fn mise(scan: &mut Scan, c: &Component) -> Result<()> {
    let r = releases::github_latest(&scan.cache, scan.net, MISE_REPO, scan.opts.offline);
    let latest = scan.guard("latest mise release (GitHub)", r, String::new())?;
    if !latest.is_empty() && !versions::same_or_newer(&c.version, &latest) {
        scan.add(Finding {
            vuln_id: "OUTDATED".into(),
            status: "warn".into(),
            fixed: latest.clone(),
            fix_cmd: c.fix.clone(),
            fix_auto: false,
            note: format!(
                "mise {} is behind {latest}. mise is foundational infrastructure: update it the way it was installed (https://mise.jdx.dev/installing-mise.html); wpantry never updates it.",
                c.version
            ),
            ..Finding::of(c)
        });
    }
    Ok(())
}

/// An advisory applies when the installed major is listed and the install
/// is older than that major's fixed release.
pub fn postgres(scan: &mut Scan, c: &Component, advisories: &[releases::PgAdvisory]) -> Result<bool> {
    let major = c.version.split('.').next().unwrap_or("").to_string();
    let mut failing = false;
    for a in advisories {
        let fixed = a.fixed.iter().find(|f| f.split('.').next() == Some(major.as_str())).cloned().unwrap_or_default();
        if !a.majors.contains(&major) || fixed.is_empty() || !versions::lt(&c.version, &fixed) {
            continue;
        }
        let sev = releases::severity_from_score(a.score);
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
    apps_found(scan, apps_mod::apps(), homebrew::brew_casks)
}

/// The app checks over the bundles found; `casks` lists what Homebrew
/// installed, read only when there are apps to check.
fn apps_found(
    scan: &mut Scan,
    mut found: Vec<Component>,
    casks: impl FnOnce() -> BTreeMap<String, String>,
) -> Result<()> {
    if found.is_empty() {
        return Ok(());
    }
    scan.count("apps", found.len() as i64);
    scan.status("Fetching the Homebrew cask catalog");
    let r = releases::casks(&scan.cache, scan.net, scan.opts.offline);
    let catalog = scan.guard("latest app versions (Homebrew cask catalog)", r, BTreeMap::new())?;
    let casks = casks();
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
            let r = releases::chrome(&scan.cache, scan.net, "mac", scan.opts.offline);
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
            let r = releases::firefox(&scan.cache, scan.net, scan.opts.offline).map(Some);
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

// Homebrew ----------------------------------------------------------------------

pub fn brew(scan: &mut Scan, job: Option<&brew_vulns::BrewJob>, ran: Option<Result<Value>>) -> Result<()> {
    scan.status("Checking Homebrew formulae (brew vulns)");
    let res = match brew_vulns::brew_vulns(&scan.cache, job, ran, scan.opts.refresh, scan.opts.offline) {
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
    for f in crate::utils::json::arr_at(&res, "findings") {
        let formula = crate::utils::json::str_at(f, "formula").to_string();
        let version = crate::utils::json::str_at(f, "version").to_string();
        let (fix, auto) = match manual(&formula) {
            Some(m) => (m.to_string(), false),
            None => (format!("brew upgrade {formula}"), true),
        };
        let mut c = Component::new("brew", &formula, &version, "Homebrew");
        c.fix = fix;
        c.auto = auto;
        for v in crate::utils::json::arr_at(f, "vulnerabilities") {
            let rec = serde_json::json!({"id": crate::utils::json::str_at(v, "id"), "aliases": v.get("aliases").cloned().unwrap_or(serde_json::json!([]))});
            let fixes: Vec<String> =
                crate::utils::json::strs_at(v, "fixed_versions").into_iter().filter(|x| osv::released(x)).collect();
            if is_malicious(&rec) {
                scan.add(Finding {
                    vuln_id: crate::utils::json::str_at(v, "id").into(),
                    status: "fail".into(),
                    kev: true,
                    severity: "MALICIOUS".into(),
                    note: crate::utils::json::str_at(v, "summary").into(),
                    fix_cmd: REMOVE.replace("{}", &formula),
                    ..Finding::of(&c)
                });
            } else if fixes.is_empty() {
                scan.unfixed += 1;
            } else {
                let sev = crate::utils::json::str_at(v, "severity").to_uppercase();
                scan.add(Finding {
                    vuln_id: display_id(&rec),
                    status: "fail".into(),
                    kev: is_kev(&rec, &scan.kev),
                    fixed: versions::pick_safe(&version, &fixes).unwrap_or_else(|| fixes[0].clone()),
                    severity: if sev.is_empty() { severity_of(&rec) } else { sev },
                    note: crate::utils::json::str_at(v, "summary").into(),
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
pub fn ca_trust(scan: &mut Scan, stores: Result<Vec<ca_trust::Store>>) {
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
                    note: format!("trusts the leaked eMudhra intermediate CAs ({})", ca_trust::ADVISORY),
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
    use crate::checks::machine::catalog::MISE_FIX;
    use crate::db::Cache;
    use crate::utils::net::Fake;

    fn scan<'a>(net: &'a Fake, d: &crate::utils::temp::TempDir) -> Scan<'a> {
        Scan::new(Default::default(), Cache::open(Some(&d.path().join("w.db"))).unwrap(), net, &|_| {}, &|_| {})
    }

    // The test vectors the Python implementation had (`Mise`).
    #[test]
    fn mise_behind_latest_release_warns_and_is_never_unattended() {
        let d = crate::utils::temp::TempDir::new("mise").unwrap();
        let net = Fake::new(|r| {
            assert_eq!(r.url, "https://api.github.com/repos/jdx/mise/releases/latest");
            Ok(crate::utils::net::Response::ok(r#"{"tag_name": "v2026.10.21"}"#))
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
            "mise 2026.10.19 is behind 2026.10.21. mise is foundational infrastructure: update it the way it was installed (https://mise.jdx.dev/installing-mise.html); wpantry never updates it."
        );
        // Cached for a day: GitHub isn't asked again.
        let quiet = Fake::new(|_| panic!("cached"));
        let mut s2 = Scan::new(Default::default(), s.cache, &quiet, &|_| {}, &|_| {});
        mise(&mut s2, &c).unwrap();
    }

    #[test]
    fn unreachable_github_is_unchecked_not_clean() {
        let d = crate::utils::temp::TempDir::new("mise").unwrap();
        let net = Fake::new(|_| Ok(crate::utils::net::Response { status: 403, body: vec![], etag: None }));
        let mut s = scan(&net, &d);
        mise(&mut s, &Component::new("manager", "mise", "2026.10.19", "")).unwrap();
        assert_eq!(
            (s.findings[0].kind.as_str(), s.findings[0].component.as_str()),
            ("unchecked", "latest mise release (GitHub)")
        );
    }

    #[test]
    fn postgres_advisories_by_major() {
        let d = crate::utils::temp::TempDir::new("pg").unwrap();
        let net = Fake::offline();
        let mut s = scan(&net, &d);
        let mut c = Component::new("datastore", "postgres", "17.4", "/usr/bin/postgres");
        c.fix = "Upgrade postgres to {safe}".into();
        let adv = releases::PgAdvisory {
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

    fn kinds(s: &Scan) -> Vec<(String, String, String)> {
        s.findings.iter().map(|f| (f.component.clone(), f.vuln_id.clone(), f.status.clone())).collect()
    }

    fn unchecked_note(s: &Scan, what: &str) -> String {
        s.findings
            .iter()
            .find(|f| f.kind == "unchecked" && f.component == what)
            .map(|f| f.note.clone())
            .unwrap_or_else(|| panic!("{what} isn't reported unchecked: {:?}", kinds(s)))
    }

    /// An OSV querybatch answer: the ids for each (package, version) asked.
    fn querybatch(body: &[u8], answer: &dyn Fn(&str, &str) -> Vec<&'static str>) -> crate::utils::net::Response {
        let body: Value = serde_json::from_slice(body).unwrap();
        let results: Vec<Value> = crate::utils::json::arr_at(&body, "queries")
            .iter()
            .map(|q| {
                let ids =
                    answer(crate::utils::json::str_at(&q["package"], "name"), crate::utils::json::str_at(q, "version"));
                let vulns: Vec<Value> = ids.iter().map(|id| serde_json::json!({"id": id, "modified": "m"})).collect();
                if vulns.is_empty() { serde_json::json!({}) } else { serde_json::json!({"vulns": vulns}) }
            })
            .collect();
        crate::utils::net::Response::ok(serde_json::json!({"results": results}).to_string())
    }

    fn npm_rec(id: &str, pkg: &str, fixed: Option<&str>, aliases: &[&str]) -> Value {
        let mut events = vec![serde_json::json!({"introduced": "0"})];
        if let Some(f) = fixed {
            events.push(serde_json::json!({"fixed": f}));
        }
        serde_json::json!({"id": id, "aliases": aliases, "modified": "m", "summary": format!("{id} summary"),
            "affected": [{"package": {"ecosystem": "npm", "name": pkg}, "ranges": [{"type": "SEMVER", "events": events}]}]})
    }

    fn app(name: &str, version: &str, extra: &[(&str, &str)]) -> Component {
        let mut c = Component::new("app", name, version, &format!("/Applications/{name}.app"));
        c.extra.insert("bundle".into(), format!("{name}.app"));
        for (k, v) in extra {
            if *k == "browser" {
                c.kind = "browser".into();
            }
            c.extra.insert(k.to_string(), v.to_string());
        }
        c
    }

    fn casks_body() -> String {
        serde_json::json!([
            {"token": "slack", "version": "4.41.100", "artifacts": [{"app": ["Slack.app"]}]},
            {"token": "zoom", "version": "6.2.0,1", "artifacts": [{"app": ["zoom.us.app"]}]},
            {"token": "notion", "version": "4.0.0", "artifacts": [{"app": ["Notion.app"]}]},
            {"token": "google-chrome", "version": "130.0.6723.117", "artifacts": [{"app": ["Google Chrome.app"]}]},
            {"token": "brave-browser", "version": "1.71.0", "artifacts": [{"app": ["Brave Browser.app"]}]},
            {"token": "arc", "version": "1.60.0", "artifacts": [{"app": ["Arc.app"]}]},
            {"token": "firefox", "version": "latest", "artifacts": [{"app": ["Firefox.app"]}]}
        ])
        .to_string()
    }

    /// The feeds the app check reads: casks, Chrome, Firefox and OSV.
    fn app_net(r: &crate::utils::net::Request) -> Result<crate::utils::net::Response> {
        use crate::utils::net::Response;
        let url = r.url.as_str();
        if url == releases::CASKS_URL {
            return Ok(Response::ok(casks_body()));
        }
        if url.ends_with("/querybatch") {
            let body = r.body.clone().unwrap_or_default();
            return Ok(querybatch(&body, &|pkg, v| match (pkg, v) {
                ("electron", "33.4.11") => vec!["GHSA-e1"],
                ("electron", "34.0.0") => vec!["GHSA-e2"],
                ("electron", "35.0.0") => vec!["GHSA-e3"],
                _ => vec![],
            }));
        }
        if url.contains("/vulns/") {
            let id = url.rsplit('/').next().unwrap_or("");
            let rec = match id {
                "GHSA-e1" => npm_rec(id, "electron", Some("33.4.12"), &["CVE-2026-100"]),
                "GHSA-e2" => npm_rec(id, "electron", Some("34.0.1"), &[]),
                _ => npm_rec(id, "electron", None, &[]),
            };
            return Ok(Response::ok(rec.to_string()));
        }
        if url.starts_with("https://versionhistory.googleapis.com/") {
            // One release older than the grace period, one with no start.
            return Ok(Response::ok(
                serde_json::json!({"releases": [
                    {"version": "130.0.6723.117", "serving": {"startTime": "2024-01-01T00:00:00Z"}},
                    {"version": "129.0.0.0", "serving": {"startTime": ""}}
                ]})
                .to_string(),
            ));
        }
        if url.ends_with("firefox_versions.json") {
            return Ok(Response::ok(
                serde_json::json!({"LATEST_FIREFOX_VERSION": "132.0", "FIREFOX_ESR": "128.5.0esr", "FIREFOX_ESR_NEXT": ""})
                    .to_string(),
            ));
        }
        if url.ends_with("firefox_history_major_releases.json") {
            return Ok(Response::ok(serde_json::json!({"132.0": "2024-10-29"}).to_string()));
        }
        if url.ends_with("firefox_history_stability_releases.json") {
            return Ok(Response::ok(serde_json::json!({"128.4.0": "2024-10-29"}).to_string()));
        }
        panic!("unexpected request {url}")
    }

    #[test]
    fn apps_behind_their_cask_and_with_vulnerable_electron() {
        let d = crate::utils::temp::TempDir::new("apps").unwrap();
        let net = Fake::new(app_net);
        let mut s = scan(&net, &d);
        let found = vec![
            // Behind, with a fixed Electron advisory: fails, the cask upgrade is the fix.
            app("Slack", "4.41.97", &[("electron", "33.4.11")]),
            // Up to date but its Electron has a fix: the vendor's turn.
            app("Notion", "4.0.0", &[("electron", "34.0.0")]),
            // Electron advisory without a fix: not a finding; up to date.
            app("Code", "1.95.0", &[("electron", "35.0.0")]),
            // Behind, no cask installed: update from the vendor.
            app("zoom.us", "6.1.0", &[]),
            // A cask without a version ("latest") says nothing.
            app("Unknown", "1.0", &[]),
        ];
        let casks: BTreeMap<String, String> = [("slack".to_string(), "4.41.97".to_string())].into();
        apps_found(&mut s, found, || casks).unwrap();
        assert_eq!(s.counts, [("apps".to_string(), 5)]);
        let slack = &s.findings[0];
        assert_eq!(
            (slack.component.as_str(), slack.vuln_id.as_str(), slack.status.as_str(), slack.fixed.as_str()),
            ("Slack", "CVE-2026-100", "fail", "4.41.100")
        );
        assert_eq!((slack.fix_cmd.as_str(), slack.fix_auto), ("brew upgrade --cask slack", true));
        assert_eq!(slack.note, "bundles Electron 33.4.11 (1 fixed advisories); 4.41.100 is out");
        let notion = &s.findings[1];
        assert_eq!(
            (notion.component.as_str(), notion.vuln_id.as_str(), notion.status.as_str()),
            ("Notion", "GHSA-e2", "warn")
        );
        assert_eq!(notion.fix_cmd, "Ask the Notion vendor to ship a newer Electron");
        let zoom = &s.findings[2];
        assert_eq!(
            (zoom.component.as_str(), zoom.vuln_id.as_str(), zoom.fixed.as_str()),
            ("zoom.us", "OUTDATED", "6.2.0")
        );
        assert_eq!(
            (zoom.fix_cmd.as_str(), zoom.fix_auto),
            ("Update zoom.us from its vendor (or its own updater)", false)
        );
        assert_eq!(s.findings.len(), 3, "{:?}", kinds(&s));
    }

    #[test]
    fn browsers_follow_their_vendor_feeds() {
        let d = crate::utils::temp::TempDir::new("browsers").unwrap();
        let net = Fake::new(app_net);
        let mut s = scan(&net, &d);
        let found = vec![
            app("Google Chrome", "129.0.6668.100", &[("browser", "chrome")]),
            app("Firefox", "128.3.0", &[("browser", "firefox")]),
            app("Brave Browser", "1.70.0", &[("browser", "brave")]),
            app("Arc", "1.60.0", &[("browser", "arc")]),
        ];
        let casks: BTreeMap<String, String> = [("google-chrome".to_string(), "129.0.6668.100".to_string())].into();
        apps_found(&mut s, found, || casks).unwrap();
        // Chrome's fix has been out longer than the grace period: fail, by brew.
        let chrome = &s.findings[0];
        assert_eq!(
            (chrome.vuln_id.as_str(), chrome.status.as_str(), chrome.fixed.as_str()),
            ("BROWSER", "fail", "130.0.6723.117")
        );
        assert_eq!((chrome.fix_cmd.as_str(), chrome.fix_auto), ("brew upgrade --cask google-chrome", true));
        // Firefox ESR 128 moved to 128.5.0; its date is unknown, so a warning.
        let ff = &s.findings[1];
        assert_eq!((ff.vuln_id.as_str(), ff.status.as_str(), ff.fixed.as_str()), ("BROWSER", "warn", "128.5.0"));
        assert_eq!(ff.fix_cmd, "Firefox menu → About Firefox, then Restart to Update");
        assert_eq!(ff.note, "Firefox 128.5.0 is out; its releases carry security fixes");
        // Other browsers only compare with the cask catalog.
        let brave = &s.findings[2];
        assert_eq!(
            (brave.component.as_str(), brave.vuln_id.as_str(), brave.fixed.as_str()),
            ("Brave Browser", "OUTDATED", "1.71.0")
        );
        assert_eq!(s.findings.len(), 3, "{:?}", kinds(&s));
    }

    #[test]
    fn browser_feeds_down_are_unchecked_and_no_apps_is_nothing() {
        let d = crate::utils::temp::TempDir::new("browsers").unwrap();
        let net = Fake::new(|r| {
            if r.url == releases::CASKS_URL {
                return Ok(crate::utils::net::Response::ok(casks_body()));
            }
            Err(Error::Offline("down".into()))
        });
        let mut s = scan(&net, &d);
        let found = vec![
            app("Google Chrome", "129.0.6668.100", &[("browser", "chrome")]),
            app("Firefox", "128.3.0", &[("browser", "firefox")]),
        ];
        apps_found(&mut s, found, BTreeMap::new).unwrap();
        unchecked_note(&s, "Chrome (Google's release feed)");
        unchecked_note(&s, "Firefox (Mozilla's release feed)");
        assert_eq!(s.findings.len(), 2, "{:?}", kinds(&s));
        let mut s2 = scan(&net, &d);
        apps_found(&mut s2, Vec::new(), || panic!("no apps, no casks")).unwrap();
        assert!(s2.findings.is_empty() && s2.counts.is_empty());
    }

    #[test]
    fn cask_catalog_down_still_checks_electron() {
        let d = crate::utils::temp::TempDir::new("casks").unwrap();
        let net = Fake::new(|r| {
            if r.url == releases::CASKS_URL {
                return Err(Error::Offline("down".into()));
            }
            app_net(r)
        });
        let mut s = scan(&net, &d);
        apps_found(&mut s, vec![app("Slack", "4.41.97", &[("electron", "33.4.11")])], BTreeMap::new).unwrap();
        unchecked_note(&s, "latest app versions (Homebrew cask catalog)");
        let slack = s.findings.iter().find(|f| f.component == "Slack").unwrap();
        assert_eq!(
            (slack.status.as_str(), slack.fix_cmd.as_str()),
            ("warn", "Ask the Slack vendor to ship a newer Electron")
        );
    }

    const FOO: &str = "https://github.com/jdx/foo.git";

    #[test]
    fn components_against_osv_eol_postgres_and_mise() {
        let d = crate::utils::temp::TempDir::new("components").unwrap();
        let net = Fake::new(|r| {
            use crate::utils::net::Response;
            let url = r.url.as_str();
            if url.ends_with("/querybatch") {
                let body = r.body.clone().unwrap_or_default();
                return Ok(querybatch(&body, &|pkg, v| match (pkg, v) {
                    ("left-pad", "1.0.0") => vec!["GHSA-lp"],
                    (FOO, "v1.0.0" | "v1.0.1") => vec!["CVE-2026-9"],
                    _ => vec![],
                }));
            }
            if url.contains("/vulns/") {
                let id = url.rsplit('/').next().unwrap_or("");
                let rec = if id == "GHSA-lp" {
                    npm_rec(id, "left-pad", Some("1.0.1"), &[])
                } else {
                    serde_json::json!({"id": id, "modified": "m", "summary": "foo overflow",
                        "affected": [{"ranges": [{"type": "GIT", "repo": FOO, "events": [{"introduced": "abc"}]}]}]})
                };
                return Ok(Response::ok(rec.to_string()));
            }
            if url == "https://endoflife.date/api/nodejs.json" {
                return Ok(Response::ok(
                    serde_json::json!([{"cycle": "18", "eol": "2025-04-30", "latest": "18.20.8"},
                                       {"cycle": "22", "eol": false, "latest": "22.11.0"}])
                    .to_string(),
                ));
            }
            if url == "https://api.github.com/repos/jdx/mise/releases/latest" {
                return Ok(Response::ok(r#"{"tag_name": "v2026.10.21"}"#));
            }
            panic!("unexpected request {url}")
        });
        let mut s = scan(&net, &d);
        // Release tags and PostgreSQL's table come from the cache: no git, no HTML.
        s.cache.put_run(&format!("tags:{FOO}"), "", &serde_json::json!(["v1.0.1", "v1.0.2"])).unwrap();
        s.cache
            .put_run(
                "postgres",
                "",
                &serde_json::json!([{"cve": "CVE-2026-1", "majors": ["17"], "fixed": ["17.6"], "component": "core",
                                     "score": 8.8, "vector": "", "summary": "Heap overflow"}]),
            )
            .unwrap();
        let mut pad = Component::new("package", "left-pad", "1.0.0", "/usr/local/lib/node_modules/left-pad");
        pad.osv = Some(("npm".into(), "left-pad".into(), "1.0.0".into()));
        pad.fix = "npm install -g left-pad@{safe}".into();
        let mut foo = Component::new("tool", "foo", "1.0.0", "/usr/local/bin/foo");
        foo.osv = Some(("GIT".into(), FOO.into(), "v1.0.0".into()));
        let mut node = Component::new("runtime", "node", "18.0.0", "/usr/local/bin/node");
        node.eol = Some(("nodejs".into(), "18".into()));
        let mut pg = Component::new("datastore", "postgres", "17.4", "/usr/local/bin/postgres");
        pg.fix = "Upgrade postgres to {safe}".into();
        let mise = Component::new("manager", "mise", "2026.10.19", "/h/.local/bin/mise");
        components(&mut s, &[pad, foo, node, pg, mise]).unwrap();
        let got = kinds(&s);
        assert_eq!(
            got,
            [
                ("left-pad".to_string(), "GHSA-lp".to_string(), "fail".to_string()),
                ("foo".to_string(), "CVE-2026-9".to_string(), "fail".to_string()),
                ("node".to_string(), "EOL".to_string(), "fail".to_string()),
                ("postgres".to_string(), "CVE-2026-1".to_string(), "fail".to_string()),
                ("mise".to_string(), "OUTDATED".to_string(), "warn".to_string()),
            ],
            "{got:?}"
        );
        // The first later tag OSV stops reporting the advisory for is the fix.
        assert_eq!(s.findings[1].fixed, "v1.0.2");
        // Nothing found: nothing asked.
        let quiet = Fake::new(|_| panic!("nothing to ask about"));
        let mut s2 = Scan::new(Default::default(), s.cache, &quiet, &|_| {}, &|_| {});
        components(&mut s2, &[]).unwrap();
        assert!(s2.findings.is_empty());
        assert_eq!(s.findings[0].fixed, "1.0.1");
        assert_eq!(s.findings[2].note, "nodejs 18 reached end of life on 2025-04-30; supported: 22");
    }

    #[test]
    fn postgres_skips_other_majors_and_known_cves() {
        let d = crate::utils::temp::TempDir::new("pg").unwrap();
        let net = Fake::offline();
        let mut s = scan(&net, &d);
        let c = Component::new("datastore", "postgres", "17.4", "/usr/bin/postgres");
        let adv = |majors: &[&str], fixed: &[&str]| releases::PgAdvisory {
            cve: "CVE-2026-2".into(),
            majors: majors.iter().map(|m| m.to_string()).collect(),
            fixed: fixed.iter().map(|f| f.to_string()).collect(),
            component: "core".into(),
            score: 5.0,
            vector: String::new(),
            summary: "s".into(),
        };
        // Another major, a major without a fix, and an install already fixed.
        assert!(
            !postgres(&mut s, &c, &[adv(&["16"], &["16.10"]), adv(&["17"], &[]), adv(&["17"], &["17.4"])]).unwrap()
        );
        assert!(s.findings.is_empty());
        assert!(postgres(&mut s, &c, &[adv(&["17"], &["17.6"])]).unwrap());
        assert!(s.cache.vuln("CVE-2026-2").unwrap().is_some());
        // Known to the cache already: not stored again.
        assert!(postgres(&mut s, &c, &[adv(&["17"], &["17.6"])]).unwrap());
        assert_eq!(s.findings.len(), 2);
    }

    #[test]
    fn persistence_baselines_first_then_warns_on_what_is_new() {
        use crate::checks::machine::any::persistence::{Inventory, Item, Source};
        let d = crate::utils::temp::TempDir::new("persistence").unwrap();
        let net = Fake::offline();
        let mut s = scan(&net, &d);
        let item = |loc: &str| Item {
            source: Source::Launchd,
            location: loc.into(),
            ident: String::new(),
            program: None,
            injects: Vec::new(),
            line: 0,
        };
        let mut inv = Inventory {
            items: vec![item("a.plist")],
            read: vec![Source::Launchd],
            unread: vec![(Source::SystemExtension, "systemextensionsctl list gave no answer".into())],
        };
        persistence(&mut s, (inv.clone(), Default::default()));
        assert_eq!(
            kinds(&s),
            [("persistence: system extensions".to_string(), "UNCHECKED".to_string(), "warn".to_string())],
            "the first scan records, and says what it couldn't read"
        );
        assert!(s.counts.iter().any(|(k, n)| k.starts_with("persistence items recorded") && *n == 1));
        let mut s2 = Scan::new(Default::default(), s.cache, &net, &|_| {}, &|_| {});
        inv.items.push(item("b.plist"));
        inv.unread.clear();
        persistence(&mut s2, (inv, Default::default()));
        assert_eq!(kinds(&s2), [("b.plist".to_string(), "PERSISTENCE-NEW".to_string(), "warn".to_string())]);
        assert_eq!(s2.findings[0].kind, "persistence");
    }

    #[test]
    fn posture_reports_what_fails_and_what_it_cannot_tell() {
        let d = crate::utils::temp::TempDir::new("posture").unwrap();
        let net = Fake::offline();
        let mut s = scan(&net, &d);
        // A machine that answers nothing: every check fails or can't tell.
        posture_with(&mut s, &|_argv: &[&str]| String::new());
        assert!(!s.findings.is_empty());
        for f in &s.findings {
            assert_eq!(f.kind, "posture");
            assert!(f.vuln_id.starts_with("POSTURE-"), "{}", f.vuln_id);
            assert!(f.status == "fail" || f.status == "warn", "{f:?}");
            assert!(!f.fix_cmd.is_empty(), "{f:?}");
            if f.status == "fail" {
                assert!(f.severity == "CRITICAL" || f.severity == "HIGH", "{f:?}");
            }
        }
        assert!(s.counts.iter().any(|(k, n)| k == "security settings checked" && *n > 0));
        let unknown: Vec<&Finding> = s.findings.iter().filter(|f| f.note.starts_with("couldn't tell: ")).collect();
        assert!(unknown.iter().all(|f| f.status == "warn" && !f.fix_auto));
    }

    #[test]
    fn macos_updates_fail_and_a_stale_scan_warns() {
        let d = crate::utils::temp::TempDir::new("macos").unwrap();
        let net = Fake::offline();
        let mut s = scan(&net, &d);
        let updates =
            vec![("macOS Sequoia 15.7.1 ".to_string(), " 15.7.1".to_string()), ("Safari".into(), "26.1".into())];
        macos(&mut s, (updates, "2024-01-01 08:15:32 +0000".into()));
        assert_eq!(
            kinds(&s),
            [
                ("macOS Sequoia 15.7.1".to_string(), "OS-UPDATE".to_string(), "fail".to_string()),
                ("Safari".to_string(), "OS-UPDATE".to_string(), "fail".to_string()),
                ("macOS".to_string(), "OS-UPDATE".to_string(), "warn".to_string()),
            ]
        );
        assert_eq!(s.findings[0].fixed, "15.7.1");
        assert_eq!(s.findings[2].note, "Software Update last checked 2024-01-01; results may be stale");
        // No last scan date at all: nothing to call stale.
        let mut s2 = scan(&net, &d);
        macos(&mut s2, (Vec::new(), String::new()));
        assert!(s2.findings.is_empty());
    }

    #[test]
    fn os_updates_on_this_machine_only_ever_report_unchecked_offline() {
        let d = crate::utils::temp::TempDir::new("os").unwrap();
        let net = Fake::offline();
        let mut s = scan(&net, &d);
        // A Mac: Software Update's answer, given above. Linux: its package
        // database against OSV (unreachable here), or no source yet.
        os_updates(&mut s, (Vec::new(), String::new())).unwrap();
        if MACOS || os::os_family(&os::os_release()) != "dnf" {
            assert!(s.findings.iter().all(|f| f.kind == "unchecked"), "{:?}", kinds(&s));
        }
    }

    fn rel(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn distros_without_a_source_are_unchecked() {
        let d = crate::utils::temp::TempDir::new("distro").unwrap();
        let net = Fake::new(|r| {
            assert_eq!(r.url, distros::ARCH_URL);
            Ok(crate::utils::net::Response::ok(r#"[{"name": "ASA-1", "packages": ["x"]}]"#))
        });
        let mut s = scan(&net, &d);
        linux_updates(&mut s, &rel(&[("ID", "debian")])).unwrap();
        assert!(unchecked_note(&s, "OS packages (debian)").starts_with("Debian without a VERSION_ID"));
        linux_updates(&mut s, &rel(&[("ID", "gentoo"), ("PRETTY_NAME", "Gentoo Linux")])).unwrap();
        assert!(unchecked_note(&s, "OS packages (Gentoo Linux)").starts_with("no advisory source"));
        linux_updates(&mut s, &rel(&[])).unwrap();
        unchecked_note(&s, "OS packages (this distro)");
        // dnf and pacman aren't on this machine (or answer for it): unchecked, never clean.
        let mut s2 = scan(&net, &d);
        linux_updates(&mut s2, &rel(&[("ID", "arch")])).unwrap();
        let mut s3 = scan(&net, &d);
        linux_updates(&mut s3, &rel(&[("ID", "fedora")])).unwrap();
        for s in [&s2, &s3] {
            assert!(s.findings.iter().all(|f| f.kind == "unchecked"), "{:?}", kinds(s));
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
                return Ok(querybatch(&body, &|pkg, _| if pkg == "acl" { vec!["DEBIAN-CVE-1"] } else { vec![] }));
            }
            Ok(Response::ok(
                serde_json::json!({"id": "DEBIAN-CVE-1", "upstream": ["CVE-2026-4"], "modified": "m", "summary": "acl overflow",
                    "affected": [{"package": {"ecosystem": "Debian:13", "name": "acl"},
                                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.3.2-1"}]}]}]})
                .to_string(),
            ))
        });
        let mut s = scan(&net, &d);
        let debian = rel(&[("ID", "debian"), ("VERSION_ID", "13"), ("PRETTY_NAME", "Debian 13")]);
        let pkgs = vec![Package::new("", "acl", "2.3.1-1"), Package::new("", "bash", "5.2-1")];
        os_packages_from(&mut s, &debian, "Debian 13", "Debian:13", Ok(Some(("/var/lib/dpkg/status".into(), pkgs))))
            .unwrap();
        assert_eq!(s.counts, [("OS packages".to_string(), 2)]);
        assert_eq!(kinds(&s), [("acl".to_string(), "DEBIAN-CVE-1".to_string(), "fail".to_string())]);
        let f = &s.findings[0];
        assert_eq!((f.kind.as_str(), f.location.as_str(), f.fixed.as_str()), ("os", "/var/lib/dpkg/status", "2.3.2-1"));
        assert_eq!(f.fix_cmd, "sudo apt-get update && sudo apt-get install --only-upgrade acl");
        // The database missing, unreadable or failing is unchecked; the cache failing is an error.
        let mut s2 = scan(&net, &d);
        os_packages_from(&mut s2, &debian, "Debian 13", "Debian:13", Ok(None)).unwrap();
        assert_eq!(unchecked_note(&s2, "OS packages (Debian 13)"), "no package database found");
        let mut s3 = scan(&net, &d);
        os_packages_from(&mut s3, &debian, "Debian 13", "Debian:13", Err(Error::Missing("rpm".into()))).unwrap();
        assert!(unchecked_note(&s3, "OS packages (Debian 13)").contains("rpm"));
        let mut s4 = scan(&net, &d);
        os_packages_from(&mut s4, &debian, "Debian 13", "Debian:13", Err(Error::Failed("rpm -qa exited".into())))
            .unwrap();
        assert!(unchecked_note(&s4, "OS packages (Debian 13)").contains("rpm -qa"));
        let mut s5 = scan(&net, &d);
        let broken = Err(Error::Cache(rusqlite::Error::InvalidQuery));
        assert!(os_packages_from(&mut s5, &debian, "Debian 13", "Debian:13", broken).is_err());
    }

    #[test]
    fn a_suse_without_rpm_or_a_mac_has_no_package_database_to_read() {
        let d = crate::utils::temp::TempDir::new("suse").unwrap();
        let net = Fake::offline();
        let mut s = scan(&net, &d);
        linux_updates(&mut s, &rel(&[("ID", "sles"), ("VERSION_ID", "15.6"), ("PRETTY_NAME", "SLES 15")])).unwrap();
        assert!(s.findings.iter().all(|f| f.kind == "unchecked"), "{:?}", kinds(&s));
        assert!(s.findings.iter().any(|f| f.component.starts_with("OS packages")), "{:?}", kinds(&s));
    }

    #[test]
    fn distro_advisories_become_os_findings() {
        let d = crate::utils::temp::TempDir::new("dnf").unwrap();
        let net = Fake::offline();
        let mut s = scan(&net, &d);
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
        distro(&mut s, &rel(&[("ID", "fedora")]), res);
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

    #[test]
    fn brew_vulns_findings_malicious_unfixed_and_manual() {
        let d = crate::utils::temp::TempDir::new("brew").unwrap();
        let net = Fake::offline();
        let mut s = scan(&net, &d);
        s.kev.insert("CVE-2026-7".into());
        let job = brew_vulns::BrewJob::new(&d.path().join("brew"), "fp", true);
        let ran = serde_json::json!({"checked": 3, "findings": [
            {"formula": "mise", "version": "2026.10.19", "vulnerabilities": [
                {"id": "GHSA-m", "severity": "high", "summary": "mise bug", "fixed_versions": ["2026.10.21"]}]},
            {"formula": "jq", "version": "1.7", "vulnerabilities": [
                {"id": "MAL-0001", "summary": "a backdoor"},
                {"id": "GHSA-nofix", "fixed_versions": []},
                {"id": "GHSA-cve", "aliases": ["CVE-2026-7"], "summary": "jq overflow",
                 "fixed_versions": ["1.8.1", "76b7feab363d547e06151c8a8aa0ca72ade0594a"]}]}]});
        brew(&mut s, Some(&job), Some(Ok(ran))).unwrap();
        assert_eq!(s.counts, [("Homebrew formulae".to_string(), 3)]);
        assert_eq!(s.unfixed, 1);
        assert_eq!(
            kinds(&s),
            [
                ("mise".to_string(), "GHSA-m".to_string(), "fail".to_string()),
                ("jq".to_string(), "MAL-0001".to_string(), "fail".to_string()),
                ("jq".to_string(), "CVE-2026-7".to_string(), "fail".to_string()),
            ]
        );
        let (mise, mal, jq) = (&s.findings[0], &s.findings[1], &s.findings[2]);
        assert_eq!(
            (mise.fix_cmd.as_str(), mise.fix_auto, mise.severity.as_str(), mise.fixed.as_str()),
            (MISE_FIX, false, "HIGH", "2026.10.21")
        );
        assert_eq!(
            (mal.severity.as_str(), mal.kev, mal.fix_cmd.as_str()),
            ("MALICIOUS", true, &*REMOVE.replace("{}", "jq"))
        );
        assert_eq!(
            (jq.fix_cmd.as_str(), jq.fix_auto, jq.kev, jq.fixed.as_str(), jq.note.as_str()),
            ("brew upgrade jq", true, true, "1.8.1", "jq overflow")
        );
        assert_eq!((jq.kind.as_str(), jq.location.as_str()), ("brew", "Homebrew"));
    }

    #[test]
    fn brew_vulns_missing_failing_or_absent() {
        let net = Fake::offline();
        let d = crate::utils::temp::TempDir::new("brew").unwrap();
        let mut s = scan(&net, &d);
        brew(&mut s, None, None).unwrap();
        assert!(s.findings.is_empty());
        let job = brew_vulns::BrewJob::new(&d.path().join("brew"), "fp", true);
        brew(&mut s, Some(&job), Some(Err(Error::Missing("brew vulns (run: brew update)".into())))).unwrap();
        let f = &s.findings[0];
        assert_eq!(
            (f.component.as_str(), f.vuln_id.as_str(), f.fix_cmd.as_str(), f.fix_auto),
            ("brew vulns", "MISSING", "brew update", true)
        );
        let d2 = crate::utils::temp::TempDir::new("brew").unwrap();
        let mut s2 = scan(&net, &d2);
        brew(&mut s2, Some(&job), Some(Err(Error::Failed("brew vulns failed: boom".into())))).unwrap();
        assert_eq!(unchecked_note(&s2, "Homebrew formulae (brew vulns)"), "brew vulns failed: boom");
        let d3 = crate::utils::temp::TempDir::new("brew").unwrap();
        let mut s3 = scan(&net, &d3);
        assert!(brew(&mut s3, Some(&job), Some(Err(Error::Cache(rusqlite::Error::InvalidQuery)))).is_err());
    }

    #[test]
    fn trust_stores_that_trust_a_distrusted_ca_fail() {
        let d = crate::utils::temp::TempDir::new("ca").unwrap();
        let net = Fake::offline();
        let mut s = scan(&net, &d);
        let store = |label: &str, trusts: bool, unchecked: Option<&str>| ca_trust::Store {
            label: label.into(),
            shown: format!("/etc/{label}"),
            trusts,
            unchecked: unchecked.map(str::to_string),
            hint: format!("fix {label}"),
        };
        ca_trust(
            &mut s,
            Ok(vec![
                store("system", true, None),
                store("java", false, Some("no keytool")),
                store("python", false, None),
            ]),
        );
        assert_eq!(s.counts, [("CA trust stores".to_string(), 3)]);
        assert_eq!(unchecked_note(&s, "CA trust: java /etc/java"), "no keytool");
        let f = s.findings.iter().find(|f| f.vuln_id == "DISTRUSTED-CA").unwrap();
        assert_eq!(
            (f.kind.as_str(), f.component.as_str(), f.fix_cmd.as_str()),
            ("config", "CA trust: system /etc/system", "fix system")
        );
        assert!(f.note.contains(ca_trust::ADVISORY));
        assert_eq!(s.findings.len(), 2);
        let mut s2 = scan(&net, &d);
        ca_trust(&mut s2, Err(Error::Missing("openssl".into())));
        assert_eq!(
            (s2.findings[0].component.as_str(), s2.findings[0].vuln_id.as_str(), s2.findings[0].fix_cmd.as_str()),
            ("openssl", "MISSING", "Install openssl")
        );
        let mut s3 = scan(&net, &d);
        ca_trust(&mut s3, Err(Error::Failed("openssl crashed".into())));
        assert_eq!(unchecked_note(&s3, "CA trust stores"), "openssl crashed");
    }

    #[test]
    fn downloads_and_desktop_are_read_when_present() {
        let home = crate::utils::files::test_home();
        let d = crate::utils::temp::TempDir::new("dl").unwrap();
        let net = Fake::offline();
        let mut s = scan(&net, &d);
        downloads(&mut s);
        assert!(s.findings.is_empty() && s.counts.is_empty(), "no folders, nothing read");
        let dl = crate::utils::files::home().join("Downloads");
        std::fs::create_dir_all(&dl).unwrap();
        std::fs::write(
            dl.join("invoice.pdf"),
            b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\n%%EOF",
        )
        .unwrap();
        std::fs::write(dl.join("notes.txt"), "plain").unwrap();
        downloads(&mut s);
        drop(home);
        assert!(
            s.counts.iter().any(|(k, n)| k == "documents and images in Downloads, Desktop and Documents" && *n == 1),
            "{:?}",
            s.counts
        );
        let doc = s.findings.iter().find(|f| f.kind == "document").expect("the PDF's script is a finding");
        assert_eq!(doc.component, "~/Downloads/invoice.pdf");
    }

    #[test]
    fn a_probe_result_is_joined() {
        assert_eq!(std::thread::scope(|s| joined(s.spawn(|| 41 + 1))), 42);
    }
}
