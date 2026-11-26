//! `wpantry recheck ID --from-scan N`: is one finding of the latest scan
//! still there? It looks at the machine for that one component, at the
//! place the scan found it, with the functions the scan's own checks use,
//! and judges it against the advisory data the cache already holds. It
//! never asks the network, never scans, never runs a fix, and writes
//! nothing unless the finding is gone ([`crate::history::record_recheck`]).
//!
//! What it answers, and what each answer is built on:
//!
//! * `gone`: the check that made the finding was run again for this one
//!   component, from cached answers only, nothing it needed was missing,
//!   and the finding did not come back; or the component is no longer
//!   where the scan found it and the place it lived in is still there.
//! * `still_present`: the same check made the finding again.
//! * `unknown`: anything else. An answer that was never cached (OSV was
//!   never asked about the version now installed), a version that can't be
//!   compared, a copy whose version can't be read, a kind with no narrow
//!   check, a scan that is no longer the latest. Never `gone`.
//!
//! Kinds with a narrow check, all of them findings with an automatic fix:
//!
//! * catalog tools and runtimes ([`TOOLS`]: node, go, ruby, mise-installed
//!   or on PATH), read by [`tools::component_at`], the function a scan reads
//!   every copy with, and judged by the inventory's own OSV, end-of-life and
//!   latest-release checks and by the CVE-record check;
//! * Homebrew formulae, in the three ways a scan finds them: `brew vulns`'
//!   answer (location `Homebrew`), a formula's CVE records
//!   ([`brew_cves::check_with`]), and a Cellar read without `brew`
//!   ([`cellar::read`]).
//!
//! Everything else says `unsupported`; the list is in specs/cli-contract.md.

use crate::checks::ecosystems;
use crate::checks::ecosystems::versions;
use crate::checks::machine::catalog::{GITHUB_LATEST, TOOLS};
use crate::checks::machine::{brew_cves, brew_vulns, cellar, components, software_cves, tools};
use crate::checks::{Options, Scan};
use crate::component::Component;
use crate::db::Cache;
use crate::error::{Error, Result};
use crate::finding::Finding;
use crate::sources::osv;
use crate::utils::files;
use crate::utils::json::{arr_at, str_at};
use crate::utils::net::{Net, Request, Response};
use crate::utils::privacy;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// What a re-check decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Gone,
    StillPresent,
    Unknown,
}

impl State {
    /// The word the JSON and the text carry.
    pub fn name(self) -> &'static str {
        match self {
            State::Gone => "gone",
            State::StillPresent => "still_present",
            State::Unknown => "unknown",
        }
    }

    /// The exit code: 0 gone, 1 still present, 3 could not tell or refused.
    pub fn exit(self) -> i32 {
        match self {
            State::Gone => 0,
            State::StillPresent => 1,
            State::Unknown => 3,
        }
    }
}

/// A state, why in one lowercase word, and one plain sentence.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub state: State,
    pub reason: &'static str,
    pub detail: String,
}

impl Verdict {
    fn new(state: State, reason: &'static str, detail: impl Into<String>) -> Verdict {
        Verdict { state, reason, detail: detail.into() }
    }

    fn gone(reason: &'static str, detail: impl Into<String>) -> Verdict {
        Verdict::new(State::Gone, reason, detail)
    }

    fn still(reason: &'static str, detail: impl Into<String>) -> Verdict {
        Verdict::new(State::StillPresent, reason, detail)
    }

    /// A refusal or a doubt: never `gone`.
    pub fn unknown(reason: &'static str, detail: impl Into<String>) -> Verdict {
        Verdict::new(State::Unknown, reason, detail)
    }
}

/// A finished re-check: what was asked, what it covered, what it decided.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcome {
    /// The finding id as asked (`F-` and ten hex digits, upper case).
    pub finding: String,
    pub scan: i64,
    pub verdict: Verdict,
    /// The finding keys it covered (`kind|component|location|vuln_id`).
    pub keys: Vec<String>,
}

/// The network a re-check has: none. Everything it reads is in the cache,
/// and the scan it borrows its checks through is built `offline`; this is
/// the second lock on the same door.
struct NoNet;

impl Net for NoNet {
    fn send(&self, req: &Request) -> Result<Response> {
        Err(Error::Offline(format!("{}: a re-check never asks the network", req.url)))
    }
}

/// One row of a scan's findings, as far as a re-check needs it.
#[derive(Clone, Debug)]
struct Row {
    kind: String,
    component: String,
    location: String,
    vuln_id: String,
    fix_cmd: String,
    fix_auto: bool,
}

impl Row {
    /// The finding this row is, as far as its key goes.
    fn finding(&self) -> Finding {
        Finding {
            kind: self.kind.clone(),
            component: self.component.clone(),
            location: self.location.clone(),
            vuln_id: self.vuln_id.clone(),
            ..Default::default()
        }
    }

    fn key(&self) -> String {
        self.finding().key()
    }
}

/// The rows of finding `id` in scan `scan`: see [`rows_for`].
#[cfg(test)]
fn rows(cache: &Cache, id: &str, scan: i64) -> Result<Vec<Row>> {
    Ok(rows_for(cache, &[id.to_string()], scan)?.remove(&id.to_ascii_lowercase()).unwrap_or_default())
}

/// The rows of each of `ids` (by lower-cased id) in scan `scan`: the latest
/// view first (what `fix` reads), then, for an id the view lacks, the scan's
/// kept copy, which still holds a finding a re-check already took out of the
/// view. Only the four identifying columns of every row are read, so a cache
/// of tens of thousands of findings costs one pass and one id hash per row
/// for all the ids together.
fn rows_for(cache: &Cache, ids: &[String], scan: i64) -> Result<std::collections::HashMap<String, Vec<Row>>> {
    let mut wanted: std::collections::HashSet<String> = ids.iter().map(|i| i.to_ascii_lowercase()).collect();
    let mut out = std::collections::HashMap::new();
    for (table, filter) in [("findings", ""), ("run_findings", " WHERE scan_id = ?1")] {
        if wanted.is_empty() {
            break;
        }
        let mut stmt =
            cache.conn.prepare(&format!("SELECT rowid, kind, component, location, vuln_id FROM {table}{filter}"))?;
        let text = |r: &rusqlite::Row<'_>, i: usize| r.get::<_, Option<String>>(i).map(Option::unwrap_or_default);
        let map = |r: &rusqlite::Row<'_>| Ok((r.get::<_, i64>(0)?, text(r, 1)?, text(r, 2)?, text(r, 3)?, text(r, 4)?));
        let all: Vec<_> = if filter.is_empty() {
            stmt.query_map([], map)?.collect::<rusqlite::Result<_>>()?
        } else {
            stmt.query_map([scan], map)?.collect::<rusqlite::Result<_>>()?
        };
        let hits: Vec<(i64, String)> = all
            .iter()
            .filter_map(|(rowid, k, c, l, v)| {
                let id = Finding::id_for(k, c, l, v).to_ascii_lowercase();
                wanted.contains(&id).then_some((*rowid, id))
            })
            .collect();
        let mut full = cache.conn.prepare(&format!(
            "SELECT kind, component, location, vuln_id, fix_cmd, fix_auto FROM {table} WHERE rowid = ?1"
        ))?;
        for (rowid, id) in hits {
            let row = full.query_row([rowid], |r| {
                Ok(Row {
                    kind: text(r, 0)?,
                    component: text(r, 1)?,
                    location: text(r, 2)?,
                    vuln_id: text(r, 3)?,
                    fix_cmd: text(r, 4)?,
                    fix_auto: r.get::<_, Option<i64>>(5)?.unwrap_or(0) != 0,
                })
            })?;
            out.entry(id).or_insert_with(Vec::new).push(row);
        }
        wanted.retain(|id| !out.contains_key(id));
    }
    Ok(out)
}

/// The scan's recorded scope says it left the personal folders out
/// (`--no-personal-files`).
fn left_personal_out(cache: &Cache, scan: i64) -> Result<bool> {
    let scope: Option<String> = cache
        .conn
        .query_row("SELECT scope FROM scans WHERE id = ?", [scan], |r| r.get::<_, Option<String>>(0))
        .map_err(Error::Cache)?;
    Ok(scope.is_some_and(|s| s.contains("no-personal-files")))
}

/// A finding id as the report spells it (`F-` and ten lower-case hex
/// digits); anything that is not one is returned as given.
pub fn canonical(id: &str) -> String {
    if crate::remediation::queue::is_id(id) { format!("F-{}", id[2..].to_ascii_lowercase()) } else { id.to_string() }
}

/// A re-check that could not finish: the id it was on and why. Ids answered
/// before it are recorded (when gone) and stay so.
#[derive(Debug)]
pub struct Failed {
    pub id: String,
    pub error: Error,
}

/// Re-check finding `id` of scan `scan`, which must be the latest. Reads
/// the cache and the one component's place on the machine; when the
/// finding is gone, records that ([`crate::history::record_recheck`]) and
/// commits; otherwise changes nothing. `cache` is closed either way.
pub fn recheck(cache: Cache, id: &str, scan: i64) -> Result<Outcome> {
    let mut got = None;
    recheck_many(cache, &[id.to_string()], scan, false, &mut |o| got = Some(o)).map_err(|f| f.error)?;
    Ok(got.expect("one id was asked, one outcome came back"))
}

/// [`recheck`] for several ids with the cache opened once and the scan's
/// rows read once. Each id is decided as it would be alone, in the order
/// given and, when it is gone, recorded before the next (a duplicate id is
/// answered each time it is named, the same way). `answer` gets each outcome
/// as soon as it is decided. With `stop_at_present` the run ends after the
/// first `still_present`, and the ids after it are not answered. An error
/// ends the run with the cache closed, so what was recorded stays recorded;
/// the [`Failed`] names the id it was on.
pub fn recheck_many(
    cache: Cache,
    ids: &[String],
    scan: i64,
    stop_at_present: bool,
    answer: &mut dyn FnMut(Outcome),
) -> std::result::Result<(), Failed> {
    let first = ids.first().cloned().unwrap_or_default();
    let fail = |id: &str, error: Error| Failed { id: canonical(id), error };
    let stale = (|| -> Result<Option<Verdict>> {
        let exists: bool =
            cache.conn.query_row("SELECT EXISTS(SELECT 1 FROM scans WHERE id = ?)", [scan], |r| r.get(0))?;
        if !exists {
            return Ok(Some(Verdict::unknown("stale", format!("there is no scan {scan}"))));
        }
        if crate::history::latest_scan(&cache)? != Some(scan) {
            let why = "A newer scan is available: a re-check answers for the latest scan only.";
            return Ok(Some(Verdict::unknown("stale", why)));
        }
        Ok(None)
    })()
    .map_err(|e| fail(&first, e))?;
    if let Some(verdict) = stale {
        for id in ids {
            answer(Outcome { finding: canonical(id), scan, verdict: verdict.clone(), keys: Vec::new() });
            if stop_at_present && verdict.state == State::StillPresent {
                break;
            }
        }
        return cache.close().map_err(|e| fail(&first, e));
    }
    let all = rows_for(&cache, ids, scan).map_err(|e| fail(&first, e))?;
    // The folders the scan never opened stay unopened.
    let left_out = left_personal_out(&cache, scan)
        .map_err(|e| fail(&first, e))?
        .then(|| privacy::leave_out(privacy::folders(&files::home(), cfg!(target_os = "macos")), Vec::new()));
    let log = |_: &str| {};
    let mut scratch =
        Scan::new(Options { offline: true, machine: true, ..Default::default() }, cache, &NoNet, &log, &log);
    for id in ids {
        let finding = canonical(id);
        let Some(found) = all.get(&id.to_ascii_lowercase()).filter(|f| !f.is_empty()) else {
            let why = format!("scan {scan} has no finding {finding}.");
            answer(Outcome { finding, scan, verdict: Verdict::unknown("unlisted", why), keys: Vec::new() });
            continue;
        };
        match decide(&mut scratch, found, scan, &finding, left_out.is_some()) {
            Ok((verdict, keys)) => {
                let present = verdict.state == State::StillPresent;
                answer(Outcome { finding, scan, verdict, keys });
                if present && stop_at_present {
                    break;
                }
            }
            Err(e) => {
                let _ = scratch.cache.close();
                return Err(fail(id, e));
            }
        }
    }
    scratch.cache.close().map_err(|e| fail(&first, e))
}

/// One finding's verdict and keys from its rows, recorded when gone.
fn decide(
    scratch: &mut Scan,
    found: &[Row],
    scan: i64,
    finding: &str,
    left_out: bool,
) -> Result<(Verdict, Vec<String>)> {
    let mut keys: Vec<String> = found.iter().map(Row::key).collect();
    keys.sort();
    keys.dedup();
    let mut verdicts = Vec::new();
    for row in found {
        scratch.findings.clear();
        verdicts.push(judge(scratch, row, left_out)?);
    }
    // Gone only when every key is; one still there is still there.
    let pick = |state: State| verdicts.iter().find(|v| v.state == state).cloned();
    let verdict = pick(State::StillPresent)
        .or_else(|| pick(State::Unknown))
        .unwrap_or_else(|| verdicts.into_iter().next().expect("a row was found"));
    if verdict.state == State::Gone {
        let covered: Vec<Finding> = found.iter().map(Row::finding).collect();
        let cache = &scratch.cache;
        cache.conn.execute_batch("SAVEPOINT recheck")?;
        match crate::history::record_recheck(cache, scan, finding, &covered, verdict.reason) {
            Ok(()) => cache.conn.execute_batch("RELEASE recheck")?,
            Err(e) => {
                let _ = cache.conn.execute_batch("ROLLBACK TO recheck; RELEASE recheck");
                return Err(e);
            }
        }
        // Recorded before the next id, so a failure later keeps it.
        cache.commit()?;
    }
    Ok((verdict, keys))
}

/// Whether a plain-word kind of finding has a narrow check.
fn unsupported(row: &Row, why: &str) -> Verdict {
    Verdict::unknown("unsupported", format!("{} {} has {why}; only a scan checks it.", row.kind, row.component))
}

/// One finding's verdict, from its kind.
fn judge(scan: &mut Scan, row: &Row, personal_left_out: bool) -> Result<Verdict> {
    if row.kind == "secret" || row.kind == "unchecked" || !row.fix_auto || row.fix_cmd.is_empty() {
        return Ok(unsupported(row, "no automatic fix"));
    }
    if personal_left_out && privacy::is_left_out(&row.location) {
        return Ok(Verdict::unknown(
            "excluded",
            "The scan left that folder out (--no-personal-files), so the re-check does not open it.",
        ));
    }
    if row.kind == "brew" {
        return judge_brew(scan, row);
    }
    match TOOLS.iter().find(|t| t.name == row.component && t.kind == row.kind) {
        Some(_) if Path::new(&row.location).is_absolute() => judge_tool(scan, row),
        _ => Ok(unsupported(row, "no narrow check")),
    }
}

/// Where the thing a finding names went: gone when the place it lived in
/// is still there and it is not, unknown when the place itself can't be
/// reached (an unmounted volume says nothing about what was on it).
fn vanished(location: &Path, anchor: &Path) -> Verdict {
    if anchor.is_dir() {
        Verdict::gone("removed", format!("{} is no longer there.", location.display()))
    } else {
        Verdict::unknown(
            "unreachable",
            format!("{} is not there, and neither is {}.", location.display(), anchor.display()),
        )
    }
}

/// The place a catalog tool's copy lives in: the version manager's
/// `installs` folder for a mise runtime, else the folder holding the file.
fn anchor_of(location: &Path) -> PathBuf {
    let text = location.to_string_lossy();
    match text.find("/installs/") {
        Some(at) if text.contains("/mise/") => PathBuf::from(&text[..at + "/installs".len()]),
        _ => location.parent().map(Path::to_path_buf).unwrap_or_default(),
    }
}

/// A catalog tool's copy at `row.location`: read again the way the scan
/// reads it, then judged as the inventory is.
fn judge_tool(scan: &mut Scan, row: &Row) -> Result<Verdict> {
    let t = TOOLS.iter().find(|t| t.name == row.component && t.kind == row.kind).expect("judge found the tool");
    let shown = Path::new(&row.location);
    match std::fs::symlink_metadata(shown) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vanished(shown, &anchor_of(shown))),
        Err(e) => return Ok(Verdict::unknown("unreadable", format!("{} can't be read: {e}.", shown.display()))),
    }
    let real = files::realpath(&row.location);
    let Some(c) = tools::component_at(t, &row.location, &real, false) else {
        let why =
            format!("{} is there, but its version can't be read or something else vouches for it.", shown.display());
        return Ok(Verdict::unknown("unreadable", why));
    };
    judge_component(scan, &c, row, true)
}

/// A component's findings from the cache alone, the way the inventory makes
/// them. An end-of-life or latest-release finding is the end-of-life and
/// latest-release checks run again. An advisory is OSV's cached answer for
/// the version now installed, through the inventory's own checks, when the
/// cache has one (a scan asks about the version it finds, and about the
/// later release tags of an upstream repo); else the cached advisory
/// record's own version ranges ([`judge_by_records`]). `same_place` says a
/// finding is the same finding only at the same location (a program's
/// copy), not at any (a formula's).
fn judge_component(scan: &mut Scan, c: &Component, row: &Row, same_place: bool) -> Result<Verdict> {
    if versions::numbers(&c.version).is_empty() {
        let why = format!("{} {} has no version number to compare.", c.name, c.version);
        return Ok(Verdict::unknown("uncomparable", why));
    }
    if row.vuln_id == "EOL" || row.vuln_id == "OUTDATED" {
        if c.eol.is_some() {
            scan.eol(c, false)?;
        }
        if let Some((_, repo)) = GITHUB_LATEST.iter().find(|(name, _)| *name == c.name) {
            components::latest(scan, c, repo, false)?;
        }
        return Ok(classify(scan, row, c, same_place));
    }
    let mut asked = true;
    for (eco, pkg, version) in c.osv.iter().chain(&c.osv_also) {
        asked &= scan.cache.query(eco, pkg, version)?.is_some();
    }
    if !asked {
        return judge_by_records(scan, c, row);
    }
    let answers = components::components(scan, std::slice::from_ref(c))?;
    software_cves::tools(scan, std::slice::from_ref(c), &answers)?;
    Ok(classify(scan, row, c, same_place))
}

/// The cached OSV records that are advisory `id`: the record of that id, and
/// any that lists it as an alias.
fn cached_records(cache: &Cache, id: &str) -> Result<Vec<Value>> {
    let mut stmt =
        cache.conn.prepare("SELECT id FROM vulns WHERE id = ?1 OR (' ' || COALESCE(aliases, '') || ' ') LIKE ?2")?;
    let ids: Vec<String> = stmt
        .query_map(rusqlite::params![id, format!("% {id} %")], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut out = Vec::new();
    for id in ids {
        out.extend(cache.vuln(&id)?);
    }
    Ok(out)
}

/// Whether OSV's record names version ranges this package's installed
/// version can be compared with: a SEMVER or ECOSYSTEM range, as opposed to
/// a range of git commits or a list of tags, which never says a version is
/// not affected (OSV's tag lists leave tags out).
fn comparable_ranges(rec: &Value, eco: &str, pkg: &str) -> bool {
    arr_at(rec, "affected")
        .iter()
        .filter(|a| osv::matches(a, eco, pkg))
        .any(|a| arr_at(a, "ranges").iter().any(|r| matches!(str_at(r, "type"), "SEMVER" | "ECOSYSTEM")))
}

/// An advisory finding when the cache has no OSV answer for the version
/// installed now (a fix to a version nobody scanned): the cached record's
/// own ranges say whether that version is in one ([`osv::affected_range`],
/// the function the findings' range column is read with). A record with no
/// range to compare with says nothing, and neither does a record the cache
/// lacks. Where the version is in a range, the inventory's own advisory
/// check ([`Scan::advisories`]) makes the finding.
fn judge_by_records(scan: &mut Scan, c: &Component, row: &Row) -> Result<Verdict> {
    let recs = cached_records(&scan.cache, &row.vuln_id)?;
    let asked: Vec<&(String, String, String)> = c.osv.iter().chain(&c.osv_also).collect();
    let tag = asked.first().map(|a| a.2.clone()).unwrap_or_else(|| c.version.clone());
    let unasked =
        |why: &str| Verdict::unknown("uncached", format!("OSV was never asked about {} {tag}, and {why}.", c.name));
    if recs.is_empty() {
        return Ok(unasked(&format!("its record for {} is not cached", row.vuln_id)));
    }
    let mut affected: Vec<Value> = Vec::new();
    for rec in recs {
        let hit = asked.iter().any(|(eco, pkg, v)| {
            !osv::affected_range(&rec, eco, pkg, v, |a, b| ecosystems::order(eco).cmp(a, b)).is_empty()
        });
        if hit {
            affected.push(rec);
        } else if !asked.iter().any(|(eco, pkg, _)| comparable_ranges(&rec, eco, pkg)) {
            return Ok(unasked(&format!("{} lists no version ranges that can be compared", row.vuln_id)));
        }
    }
    if affected.is_empty() {
        return Ok(Verdict::gone(
            "fixed",
            format!("{} {} is outside every affected range of {}.", c.name, c.version, row.vuln_id),
        ));
    }
    scan.advisories(c, &affected, None, "fail", None);
    let verdict = classify(scan, row, c, true);
    Ok(match verdict.state {
        // In a range, yet no finding: the record can't be read as the scan reads it.
        State::Gone => Verdict::unknown(
            "ambiguous",
            format!("{} {} is in a range of {}, but the check makes no finding of it.", c.name, c.version, row.vuln_id),
        ),
        _ => verdict,
    })
}

/// What a scratch scan's findings say about `row`.
fn classify(scan: &Scan, row: &Row, c: &Component, same_place: bool) -> Verdict {
    let same = |g: &Finding| {
        g.kind != "unchecked"
            && g.vuln_id == row.vuln_id
            && g.component == row.component
            && g.kind == row.kind
            && (!same_place || g.location == row.location)
    };
    if let Some(g) = scan.findings.iter().find(|g| same(g)) {
        let where_ = if g.location == row.location { String::new() } else { format!(" at {}", g.location) };
        return Verdict::still(
            "affected",
            format!("{} {}{where_} is still affected by {}.", g.component, c.version, g.vuln_id),
        );
    }
    let outdated_kind = row.vuln_id == "EOL" || row.vuln_id == "OUTDATED";
    let cve_records_not_cached = software_cves::unreached(software_cves::TOOLS_WHAT);
    let gaps: Vec<&Finding> = scan
        .findings
        .iter()
        .filter(|g| g.is_gap())
        .filter(|g| {
            // An end-of-life or latest-release source matters to a finding of that
            // kind and to no other, as an advisory source matters to an advisory.
            let dates = g.component.starts_with("end of life for") || g.component.starts_with("latest ");
            dates == outdated_kind
        })
        // The CVE records were never cached: nothing could have come from them.
        .filter(|g| g.component != cve_records_not_cached)
        // OSV's answers are older than a day: the advisory this finding is
        // about was in them when the scan ran, and an answer can't lose it.
        .filter(|g| {
            !(g.vuln_id == "UNCHECKED"
                && g.note.split("; ").all(|part| part.contains(crate::sources::osv::OUT_OF_DATE)))
        })
        .collect();
    if let Some(g) = gaps.first() {
        let reason = if gaps.iter().any(|g| g.vuln_id == "UNREACHABLE") { "uncached" } else { "unchecked" };
        return Verdict::unknown(reason, format!("{}: {}.", g.component, g.note.trim_end_matches('.')));
    }
    Verdict::gone("fixed", format!("{} {} is not affected by {}.", c.name, c.version, row.vuln_id))
}

/// A Homebrew formula's finding, by how the scan found it: `brew vulns`
/// (location `Homebrew`), the formula's CVE records (the keg's path), or a
/// Cellar read without `brew` (the formula's folder).
fn judge_brew(scan: &mut Scan, row: &Row) -> Result<Verdict> {
    let location = Path::new(&row.location);
    if row.location == "Homebrew" {
        let Some(cellar) = cellar::find_cellar() else {
            return Ok(Verdict::unknown("unavailable", "No Homebrew Cellar is set or found here."));
        };
        return judge_brew_vulns(scan, row, &cellar);
    }
    // The Cellar the location is in, and how deep: `<cellar>/<formula>` or
    // `<cellar>/<formula>/<version>`.
    let cellar = cellar::find_cellar()
        .filter(|c| location.starts_with(c))
        .or_else(|| location.ancestors().find(|a| a.file_name().is_some_and(|n| n == "Cellar")).map(Path::to_path_buf));
    let Some(cellar) = cellar else {
        return Ok(unsupported(row, "a location outside any Homebrew Cellar"));
    };
    let depth = location.strip_prefix(&cellar).map(|r| r.components().count()).unwrap_or(0);
    match depth {
        1 => judge_cellar_inventory(scan, row, &cellar),
        2 => judge_brew_cves(scan, row, &cellar),
        _ => Ok(unsupported(row, "a location outside any Homebrew Cellar")),
    }
}

/// The versions installed under `<cellar>/<formula>`, as the scan names
/// them (a revision suffix dropped), or the verdict when there are none.
fn installed_versions(cellar: &Path, formula: &str) -> std::result::Result<Vec<String>, Verdict> {
    let dir = cellar.join(formula);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Err(vanished(&dir, cellar));
    };
    let mut found: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|v| !v.starts_with('.'))
        .collect();
    found.sort();
    if found.is_empty() { Err(vanished(&dir, cellar)) } else { Ok(found) }
}

/// A finding `brew vulns` made: the cached answer's fixed versions against
/// every version of the formula still installed. Gone when every one is at
/// or past all of them, still present when every fix is ahead of some
/// installed version, unknown when a version sits between the fixes of
/// different release lines (only OSV's answer for it could say).
fn judge_brew_vulns(scan: &mut Scan, row: &Row, cellar: &Path) -> Result<Verdict> {
    let installed = match installed_versions(cellar, &row.component) {
        Ok(v) => v,
        Err(verdict) => return Ok(verdict),
    };
    let Some(fixes) = brew_vulns::cached_fixes(&scan.cache, &row.component, &row.vuln_id)? else {
        let why = format!("The cached brew vulns answer does not list {} for {}.", row.vuln_id, row.component);
        return Ok(Verdict::unknown("uncached", why));
    };
    if fixes.is_empty() || fixes.iter().any(|f| versions::numbers(f).is_empty()) {
        return Ok(Verdict::unknown(
            "uncomparable",
            format!("brew vulns names no fixed version of {} to compare with.", row.component),
        ));
    }
    let mut ambiguous = None;
    for dir in &installed {
        let v = cellar::version_of(dir);
        if versions::numbers(v).is_empty() {
            return Ok(Verdict::unknown(
                "uncomparable",
                format!("{} {v} has no version number to compare.", row.component),
            ));
        }
        let ahead = fixes.iter().filter(|f| versions::lt(v, f)).count();
        if ahead == fixes.len() {
            return Ok(Verdict::still(
                "affected",
                format!("{} {v} is older than every release that fixes {}.", row.component, row.vuln_id),
            ));
        }
        if ahead > 0 {
            ambiguous = Some(v.to_string());
        }
    }
    Ok(match ambiguous {
        Some(v) => Verdict::unknown(
            "ambiguous",
            format!(
                "{} {v} is between the releases that fix {} on different lines; only OSV can say.",
                row.component, row.vuln_id
            ),
        ),
        None => Verdict::gone(
            "fixed",
            format!("Every installed {} is at or past the releases that fix {}.", row.component, row.vuln_id),
        ),
    })
}

/// A finding the formula's CVE records made: the newest installed version
/// judged again by [`brew_cves::check_with`] from the cache.
fn judge_brew_cves(scan: &mut Scan, row: &Row, cellar: &Path) -> Result<Verdict> {
    if let Err(verdict) = installed_versions(cellar, &row.component) {
        return Ok(verdict);
    }
    let Some(now) = brew_cves::installed(cellar).into_iter().find(|i| i.formula == row.component) else {
        let why = format!("{} is installed, but not from homebrew-core, which the check reads.", row.component);
        return Ok(Verdict::unknown("unreadable", why));
    };
    let c = Component::new("brew", &row.component, cellar::version_of(&now.version), &now.location);
    if versions::numbers(&c.version).is_empty() {
        let why = format!("{} {} has no version number to compare.", c.name, c.version);
        return Ok(Verdict::unknown("uncomparable", why));
    }
    brew_cves::check_with(scan, std::slice::from_ref(&now), &|_| (String::new(), false), false)?;
    Ok(classify(scan, row, &c, false))
}

/// A finding made from a Cellar read without `brew`: the formula read again
/// ([`cellar::read`]) and judged as a catalog tool.
fn judge_cellar_inventory(scan: &mut Scan, row: &Row, cellar: &Path) -> Result<Verdict> {
    let formula_dir = Path::new(&row.location);
    let formula = formula_dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if let Err(verdict) = installed_versions(cellar, &formula) {
        return Ok(verdict);
    }
    let inventory = cellar::read(cellar, &cellar::mise_installs());
    let Some(c) = inventory.components.into_iter().find(|c| c.path == row.location) else {
        let why = format!("{formula} is installed, but wpantry maps it to no catalog tool now.");
        return Ok(Verdict::unknown("unreadable", why));
    };
    judge_component(scan, &c, row, true)
}

#[cfg(test)]
#[path = "recheck_tests.rs"]
mod tests;
