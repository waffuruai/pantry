//! Homebrew formulae built from a git repo, against their CVE records'
//! own version ranges. A C library's new CVE (libexpat's, say) reaches
//! CVE.org and OSV within hours, but OSV's record, generated from the CVE
//! list, carries only a GIT range (repo and commits) and a partial list of
//! tags, with no package name: `brew vulns` and OSV's answer for the
//! installed version miss every version the tag list leaves out.
//!
//! For each formula in the Cellar (from homebrew-core):
//!
//! 1. its upstream repo, from formulae.brew.sh ([`homebrew_formulae`]);
//! 2. OSV's GIT answer for the installed version, under the repo as the
//!    formula names it and lowercased (OSV's names are case-sensitive, and
//!    the conversion lowercases some); one that names a CVE is left to
//!    `brew vulns` and OSV, as PHP and Rust are ([`software_cves::OSV_FIRST`]);
//! 3. with none named, every OSV record for the repo, each judged by the
//!    version ranges OSV extracted from the CVE record ([`entry`]), with
//!    [`software_cves::judge`];
//! 4. a CVE found is checked against Homebrew's advisory database
//!    ([`homebrew_advisories`]): one Homebrew's patch resolves at or below
//!    the installed revision isn't reported, one it resolves later is fixed
//!    in that revision.
//!
//! A range whose versions can't be compared with the installed one is
//! "not checked", never clean. A record OSV extracted no version range
//! from is left to OSV's commit answer, which said no.
//!
//! Example: openshot-qt's CVE-2026-134704 lists tags down to `v2.0.3` but
//! none of 3.x, so OSV's answer for 3.3.0 is empty; the CVE record says
//! `lessThanOrEqual 4.1.1`, so 3.3.0 is affected.

use crate::checks::ecosystems::versions;
use crate::checks::machine::cellar::{self, version_of};
use crate::checks::machine::manual;
use crate::checks::machine::software_cves::{self, Verdict, dotted, judge, same_scheme};
use crate::checks::{Scan, display_id, is_kev};
use crate::db::severity_of;
use crate::error::Result;
use crate::finding::Finding;
use crate::sources::fetch;
use crate::sources::homebrew_advisories;
use crate::sources::homebrew_formulae::{self, Formula};
use crate::sources::osv::{self, Item};
use crate::utils::json::{arr_at, str_at};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// What the check's not-checked lines are called.
pub const WHAT: &str = "Homebrew formulae against CVE records";
/// The not-checked line for findings whose Homebrew patches couldn't be read.
pub const PATCHES: &str = "Homebrew's patches for CVE-record findings";

/// The sources of the version ranges OSV extracts from a CVE record, most
/// trusted first: the record's own `affected[].versions` (the CNA's
/// `lessThan` / `lessThanOrEqual`), NVD's CPE configuration, and the
/// description's words. Only the first a record has is read.
pub const RANGE_SOURCES: &[&str] = &["AFFECTED_FIELD", "CPE_RANGE", "DESCRIPTION"];

/// A formula installed in the Cellar: its newest version directory.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Installed {
    pub formula: String,
    /// The Cellar's version directory, revision and all (`2.7.1_1`).
    pub version: String,
    /// The keg's path.
    pub location: String,
}

/// The formulae in `cellar`, each at its newest version; a formula from
/// another tap than homebrew-core (by its keg's `INSTALL_RECEIPT.json`) is
/// left out, since formulae.brew.sh's formula of that name isn't it.
pub fn installed(cellar: &Path) -> Vec<Installed> {
    let Ok(entries) = std::fs::read_dir(cellar) else { return Vec::new() };
    let mut out: Vec<Installed> = Vec::new();
    for e in entries.filter_map(|e| e.ok()) {
        let formula = e.file_name().to_string_lossy().into_owned();
        if formula.starts_with('.') || !e.path().is_dir() {
            continue;
        }
        let newest = std::fs::read_dir(e.path())
            .into_iter()
            .flatten()
            .filter_map(|v| v.ok())
            .filter(|v| v.path().is_dir())
            .map(|v| v.file_name().to_string_lossy().into_owned())
            .filter(|v| !v.starts_with('.'))
            .max_by(|a, b| homebrew_advisories::cmp(a, b));
        let Some(version) = newest else { continue };
        let keg = e.path().join(&version);
        if !from_core(&keg) {
            continue;
        }
        out.push(Installed { formula, version, location: keg.to_string_lossy().into_owned() });
    }
    out.sort_by(|a, b| a.formula.cmp(&b.formula));
    out
}

/// Whether a keg's receipt says it came from homebrew-core, or says nothing
/// (mise's `brew:` engine may write none).
fn from_core(keg: &Path) -> bool {
    let Ok(bytes) = std::fs::read(keg.join("INSTALL_RECEIPT.json")) else { return true };
    let Ok(v) = crate::utils::json::parse(&bytes, 1 << 20) else { return true };
    match v["source"]["tap"].as_str() {
        Some(tap) if !tap.is_empty() => tap == "homebrew/core",
        _ => true,
    }
}

/// A record's version ranges for `repo`, as a CVE JSON 5 `affected[]`
/// entry [`judge`] reads: each interval OSV extracted from the first of
/// [`RANGE_SOURCES`] the record has, `fixed` as `lessThan`,
/// `last_affected` as `lessThanOrEqual`, an open one as `lessThan *`.
/// None when OSV extracted no version range.
///
/// Example: `{"source": "AFFECTED_FIELD", "range": [{"introduced": "0"},
/// {"last_affected": "4.1.1"}]}` is `{"status": "affected", "version": "0",
/// "lessThanOrEqual": "4.1.1"}`.
pub fn entry(rec: &Value, repo: &str) -> Option<Value> {
    let want = osv::norm_repo(repo);
    let mut extracted: Vec<&Value> = Vec::new();
    for a in arr_at(rec, "affected") {
        for r in arr_at(a, "ranges") {
            if str_at(r, "type") == "GIT" && osv::norm_repo(str_at(r, "repo")) == want {
                extracted.extend(arr_at(&r["database_specific"], "extracted_events"));
            }
        }
    }
    let source = RANGE_SOURCES.iter().find(|s| extracted.iter().any(|e| str_at(e, "source") == **s))?;
    let mut versions: Vec<Value> = Vec::new();
    for e in extracted.iter().filter(|e| str_at(e, "source") == *source) {
        let mut start: Option<String> = None;
        let mut push = |v: Value| {
            if !versions.contains(&v) {
                versions.push(v);
            }
        };
        for ev in arr_at(e, "range") {
            if let Some(v) = ev.get("introduced").and_then(Value::as_str) {
                if let Some(s) = start.replace(v.to_string()) {
                    push(json!({"status": "affected", "version": s, "lessThan": "*"}));
                }
            } else if let Some(v) = ev.get("fixed").and_then(Value::as_str) {
                let s = start.take().unwrap_or_else(|| "0".into());
                push(verbatim(&s, v).unwrap_or_else(|| json!({"status": "affected", "version": s, "lessThan": v})));
            } else if let Some(v) = ev.get("last_affected").and_then(Value::as_str) {
                let s = start.take().unwrap_or_else(|| "0".into());
                push(
                    verbatim(&s, v)
                        .unwrap_or_else(|| json!({"status": "affected", "version": s, "lessThanOrEqual": v})),
                );
            }
        }
        if let Some(s) = start {
            push(json!({"status": "affected", "version": s, "lessThan": "*"}));
        }
    }
    (!versions.is_empty()).then(|| json!({"versions": versions, "defaultStatus": "unaffected"}))
}

/// An interval OSV made of one `version` string the CVE record gives in
/// words (both ends the same, not a version): that string as the record's
/// `version`, a product name before it dropped, `=` meaning that version;
/// [`judge`] reads comparisons ([`software_cves::spelled`]). None otherwise.
///
/// Example: GitHub's records for Deno write `= 1.32.0` and `deno: < 1.42.0`,
/// which OSV extracts as `introduced` and `fixed` both `deno: < 1.42.0`;
/// read as `{"status": "affected", "version": "< 1.42.0"}`.
fn verbatim(start: &str, end: &str) -> Option<Value> {
    if start != end || dotted(start, false).is_some() {
        return None;
    }
    let at = start.find(['<', '>', '='])?;
    let (name, rest) = start.split_at(at);
    let name = name.trim().trim_end_matches(':');
    if name.contains(char::is_whitespace) {
        return None;
    }
    let rest = rest.trim();
    let version = match rest.strip_prefix('=') {
        Some(v) if !v.starts_with('=') => v.trim(),
        _ => rest,
    };
    Some(json!({"status": "affected", "version": version}))
}

/// The repo under the names OSV may file it: as the formula names it, and
/// lowercased when that differs.
fn spellings(repo: &str) -> Vec<String> {
    let lower = repo.to_lowercase();
    if lower == repo { vec![lower] } else { vec![repo.to_string(), lower] }
}

fn git(repo: &str, version: &str) -> Item {
    ("GIT".to_string(), repo.to_string(), version.to_string())
}

/// Whether any record names a CVE.
fn names_cve(recs: &[Value]) -> bool {
    recs.iter().any(|r| osv::ids_of(r).iter().any(|id| id.starts_with("CVE-")))
}

/// How to upgrade a formula: `brew upgrade` (or the catalog's manual step)
/// with brew; mise's, or words, without it. (command, whether `wpantry fix`
/// may run it)
pub fn fixer(has_brew: bool, mise_installs: PathBuf, cellar: PathBuf) -> impl Fn(&str) -> (String, bool) {
    move |formula: &str| {
        let safe = formula.split('@').all(versions::is_safe_token);
        if has_brew && safe {
            match manual(formula) {
                Some(m) => (m.to_string(), false),
                None => (format!("brew upgrade {formula}"), true),
            }
        } else if safe && mise_installs.join(format!("brew-{formula}")).is_dir() {
            (format!("mise upgrade brew:{formula}"), false)
        } else {
            (format!("Upgrade {formula} in the Cellar at {} (mise's brew: engine or brew)", cellar.display()), false)
        }
    }
}

/// The check on this machine: the Cellar's formulae, if it has one.
pub fn run(scan: &mut Scan) -> Result<()> {
    let Some(dir) = cellar::find_cellar() else { return Ok(()) };
    let formulae = installed(&dir);
    let fix = fixer(crate::utils::process::which("brew").is_some(), cellar::mise_installs(), dir);
    check(scan, &formulae, &fix)
}

/// One CVE a record's range puts the installed version in.
struct Hit<'a> {
    at: &'a Installed,
    repo: String,
    rec: Value,
    range: String,
    fixed: String,
}

/// The check over `formulae`; `fix` names each one's upgrade.
pub fn check(scan: &mut Scan, formulae: &[Installed], fix: &dyn Fn(&str) -> (String, bool)) -> Result<()> {
    if formulae.is_empty() {
        return Ok(());
    }
    if let Err(e) = fetch::on(homebrew_formulae::ID) {
        scan.unchecked(WHAT, &e.to_string());
        return Ok(());
    }
    let names: Vec<String> = formulae.iter().map(|f| f.formula.clone()).collect();
    scan.status(&format!("Asking formulae.brew.sh where {} formulae come from", names.len()));
    homebrew_formulae::prefetch(&scan.cache, scan.net, &names, scan.opts.offline)?;
    let mut unreached: BTreeSet<String> = BTreeSet::new();
    let mut subjects: Vec<(&Installed, Formula)> = Vec::new();
    for f in formulae {
        match homebrew_formulae::formula(&scan.cache, &f.formula)? {
            None => {
                unreached.insert(f.formula.clone());
            }
            Some(info) if !info.repo.is_empty() => subjects.push((f, info)),
            Some(_) => {}
        }
    }
    scan.count(WHAT, subjects.len() as i64);
    // OSV's answer for each installed version: one naming a CVE is OSV's
    // and brew vulns' to report.
    let items: Vec<Item> = subjects
        .iter()
        .flat_map(|(f, x)| spellings(&x.repo).into_iter().map(|r| git(&r, version_of(&f.version))))
        .collect();
    let answered = scan.lookup(&items, WHAT)?;
    subjects.retain(|(f, x)| {
        let items: Vec<Item> = spellings(&x.repo).iter().map(|r| git(r, version_of(&f.version))).collect();
        !names_cve(&osv::records_for(&answered, &items))
    });
    // Every record OSV has for each remaining repo.
    let mut all: Vec<Item> = subjects.iter().flat_map(|(_, x)| spellings(&x.repo)).map(|r| git(&r, "")).collect();
    all.sort();
    all.dedup();
    let records = scan.lookup(&all, WHAT)?;
    let mut unjudged: BTreeSet<String> = BTreeSet::new();
    let mut hits: Vec<Hit> = Vec::new();
    for (f, x) in &subjects {
        let items: Vec<Item> = spellings(&x.repo).iter().map(|r| git(r, "")).collect();
        let recs: Vec<Value> = osv::records_for(&records, &items)
            .into_iter()
            .filter(|r| osv::ids_of(r).iter().any(|id| id.starts_with("CVE-")))
            .collect();
        let entries: Vec<(Value, Value)> =
            recs.into_iter().filter_map(|r| entry(&r, &x.repo).map(|e| (r, e))).collect();
        let Some(parts) = dotted(version_of(&f.version), false) else {
            if !entries.is_empty() {
                unjudged.insert(f.formula.clone());
            }
            continue;
        };
        let stable = dotted(&x.stable, false);
        for (rec, e) in entries {
            let verdict = if same_scheme(&parts, &e) { judge(&parts, &e) } else { Verdict::Unknown };
            match verdict {
                Verdict::Affected { range, mut fixed } => {
                    // No fix in the record: the formula's current release,
                    // when the record's range leaves it out.
                    if fixed.is_empty()
                        && let Some(s) = &stable
                        && software_cves::cmp_parts(s, &parts) == std::cmp::Ordering::Greater
                        && same_scheme(s, &e)
                        && judge(s, &e) == Verdict::Unaffected
                    {
                        fixed = x.stable.clone();
                    }
                    hits.push(Hit { at: f, repo: x.repo.clone(), rec, range, fixed });
                }
                Verdict::Unknown => {
                    unjudged.insert(f.formula.clone());
                }
                Verdict::Unaffected => {}
            }
        }
    }
    // Homebrew's patches, for the formulae with a CVE found.
    let mut wanted: Vec<String> = hits.iter().map(|h| h.at.formula.clone()).collect();
    wanted.sort();
    wanted.dedup();
    let patches_on = fetch::on(homebrew_advisories::ID);
    if !wanted.is_empty() && patches_on.is_ok() {
        scan.status(&format!("Asking Homebrew's advisory database about {} formulae", wanted.len()));
        homebrew_advisories::prefetch(&scan.cache, scan.net, &wanted, scan.opts.offline)?;
    }
    let mut unpatched: BTreeSet<String> = BTreeSet::new();
    let mut found: Vec<Finding> = Vec::new();
    for h in hits {
        let formula = &h.at.formula;
        let id = display_id(&h.rec);
        let advisories = match &patches_on {
            Ok(()) => homebrew_advisories::advisories(&scan.cache, formula)?,
            Err(_) => None,
        };
        let mut fixed = h.fixed;
        let mut patch = String::new();
        match advisories.as_ref().and_then(|a| a.records.iter().find(|r| r.about(&id))) {
            Some(adv) => match adv.affects(&h.at.version) {
                // Homebrew's patch is in the installed revision.
                None => continue,
                Some(f) if !f.is_empty() => {
                    patch = format!("; Homebrew's patch ships in {f} ({})", adv.id);
                    fixed = f;
                }
                Some(_) => {}
            },
            None if advisories.is_none() => {
                unpatched.insert(formula.clone());
            }
            None => {}
        }
        // One finding per formula and CVE, and none brew vulns or OSV
        // already reported (under the formula or its catalog tool's name).
        let ids = osv::ids_of(&h.rec);
        let tool = cellar::catalog_tool(formula).map(|t| t.name);
        let same =
            |g: &Finding| (g.component == *formula || Some(g.component.as_str()) == tool) && ids.contains(&g.vuln_id);
        if scan.findings.iter().any(same) || found.iter().any(same) {
            continue;
        }
        let summary = match str_at(&h.rec, "summary") {
            "" => str_at(&h.rec, "details").chars().take(200).collect(),
            s => s.to_string(),
        };
        let installed = version_of(&h.at.version);
        let (fix_cmd, fix_auto) = if fixed.is_empty() {
            (
                format!(
                    "No fixed release named in the CVE record: check {} and upgrade {formula} once Homebrew ships one",
                    h.repo
                ),
                false,
            )
        } else {
            fix(formula)
        };
        let score = crate::utils::cvss::of_record(&h.rec);
        found.push(Finding {
            kind: "brew".into(),
            component: formula.clone(),
            version: h.at.version.clone(),
            location: h.at.location.clone(),
            vuln_id: id,
            status: if fixed.is_empty() { "warn" } else { "fail" }.into(),
            fixed,
            kev: is_kev(&h.rec, &scan.kev),
            severity: severity_of(&h.rec),
            note: format!(
                "{summary} (by the CVE record's versions; OSV's answer for {} {installed} names no CVE{patch})",
                h.repo
            ),
            fix_cmd,
            fix_auto,
            affected_range: h.range,
            cvss: score.as_ref().map(|s| s.value),
            cvss_version: score.map(|s| s.version).unwrap_or_default(),
            ..Default::default()
        });
    }
    for f in found {
        scan.add(f);
    }
    if let Err(e) = &patches_on
        && !unpatched.is_empty()
    {
        scan.unchecked(PATCHES, &e.to_string());
        unpatched.clear();
    }
    for (set, label) in [
        (&unreached, software_cves::unreached(WHAT)),
        (&unjudged, software_cves::unjudged(WHAT)),
        (&unpatched, software_cves::unreached(PATCHES)),
    ] {
        if !set.is_empty() {
            let shown: Vec<&str> = set.iter().take(4).map(String::as_str).collect();
            let more = if set.len() > 4 { format!(" and {} more", set.len() - 4) } else { String::new() };
            scan.unchecked(&label, &format!("{}{more}", shown.join(", ")));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "brew_cves_tests.rs"]
mod tests;
