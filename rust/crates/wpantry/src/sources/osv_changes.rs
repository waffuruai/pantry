//! OSV's answers kept current from its change lists, so a version asked
//! about once isn't asked again: OSV publishes, per ecosystem, every
//! advisory id with the time it last changed, newest first
//! (`osv-vulnerabilities.storage.googleapis.com/<ecosystem>/modified_id.csv`).
//!
//! Each ecosystem keeps a cursor: the newest change applied. A scan or a
//! `sync` reads the top of the list down to the cursor (a few kilobytes a
//! week, with a day's overlap for records exported late), downloads the
//! records that changed (the ones held only when OSV changed them), and
//! applies each to the cached answers of this machine's versions of the
//! packages it names, matching the versions locally with the ecosystem's
//! own order. A record that can't be matched here (a range of git
//! commits, an ecosystem without a known order) sends those versions back
//! to OSV's query API instead.
//!
//! An answer stays good for as long as its ecosystem's chain of change
//! lists is unbroken, however long ago it was asked: the chain starts when
//! the first list is read and every version answered before that is asked
//! once more. A chain breaks, and every version of the ecosystem is asked
//! again, when more changed than [`MAX_CHANGES`] since the last read (a
//! long time away), or `--refresh` asks for it. A list read in the last
//! 15 minutes isn't read again (the other checks of the same scan). What is sent: the
//! ecosystem's name in the list's path, and the ids of changed advisories.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::sources::osv::{self, Fetched, Item};
use crate::sources::{fetch, file};
use crate::utils::json::{arr_at, str_at};
use crate::utils::net::Net;
use crate::utils::os::now;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Bytes read from a change list at a time.
const CHUNK: u64 = 64 * 1024;
/// More changes than this since the last read: ask OSV again instead.
pub const MAX_CHANGES: usize = 5000;
/// A list read this recently isn't read again.
const RECENT: f64 = 15.0 * 60.0;
/// How far before the cursor a list is read again: a record exported late
/// still shows up.
const OVERLAP: f64 = 86400.0;

/// What reading the change lists left: per ecosystem directory, when its
/// chain started (an answer from then on is current); the versions to ask
/// OSV about again; and the lists that couldn't be read.
#[derive(Debug, Default)]
pub struct Synced {
    pub since: BTreeMap<String, f64>,
    pub reask: BTreeSet<Item>,
    pub failed: Vec<String>,
}

/// The directory an OSV ecosystem's list is in: the name before any colon
/// ("Debian:12" is `Debian`). None for what has no list (git repos).
pub fn directory(eco: &str) -> Option<String> {
    let dir = eco.split(':').next().unwrap_or_default();
    (!dir.is_empty() && dir != "GIT").then(|| dir.to_string())
}

/// Seconds since the epoch for an RFC 3339 time (`2026-11-05T09:00:02.64Z`);
/// None when it isn't one.
pub fn seconds(stamp: &str) -> Option<f64> {
    let (date, time) = stamp.get(..19)?.split_once('T')?;
    let day = crate::utils::dates::parse_date(date)?;
    let mut hms = time.split(':').map(|p| p.parse::<i64>().ok());
    let (h, m, s) = (hms.next()??, hms.next()??, hms.next()??);
    Some((day * 86400 + h * 3600 + m * 60 + s) as f64)
}

/// What a change list says since a time.
#[derive(Debug, PartialEq)]
pub enum Listed {
    /// The changes since then, newest first, each `(time, id)`, and the
    /// newest time listed.
    Changes(Vec<(String, String)>, String),
    /// More than [`MAX_CHANGES`]: the newest time listed.
    TooMany(String),
    /// OSV publishes no list for the ecosystem.
    NoList,
}

/// The changes listed at or after `after` (a time in seconds), read a
/// chunk at a time from `url`.
pub fn changes(net: &dyn Net, url: &str, after: f64) -> Result<Listed> {
    let mut out = Vec::new();
    let mut newest = String::new();
    let mut carry = String::new();
    let mut offset = 0u64;
    loop {
        let range = format!("bytes={offset}-{}", offset + CHUNK - 1);
        let resp = fetch::request(net, "osv-changes", url, None, &[("Range", &range), ("Accept", "text/csv")], None)?;
        if resp.status == 404 {
            return Ok(Listed::NoList);
        }
        let whole = resp.status == 200; // the server sent all of it
        let got = resp.body.len() as u64;
        carry.push_str(&String::from_utf8_lossy(&resp.body));
        let last = whole || got < CHUNK;
        // Every complete line; the last part waits for the next chunk.
        let cut = if last { carry.len() } else { carry.rfind('\n').map_or(0, |i| i + 1) };
        let lines: String = carry.drain(..cut).collect();
        for line in lines.lines().filter(|l| !l.trim().is_empty()) {
            let (stamp, id) =
                line.split_once(',').ok_or_else(|| Error::Invalid(format!("{url}: not a change list")))?;
            let t = seconds(stamp).ok_or_else(|| Error::Invalid(format!("{url}: not a change list")))?;
            if newest.is_empty() {
                newest = stamp.to_string();
            }
            if t < after {
                return Ok(Listed::Changes(out, newest));
            }
            out.push((stamp.to_string(), id.trim().to_string()));
            if out.len() > MAX_CHANGES {
                return Ok(Listed::TooMany(newest));
            }
        }
        if last {
            return Ok(Listed::Changes(out, newest));
        }
        offset += got;
    }
}

/// Whether `version` of `pkg` is affected by `rec`, matched here: Some
/// answer, or None when only OSV can tell (a git range, an unknown order).
pub fn affects(rec: &Value, eco: &str, pkg: &str, version: &str) -> Option<bool> {
    if rec.get("withdrawn").is_some_and(|w| !w.is_null()) {
        return Some(false);
    }
    let named: Vec<&Value> = arr_at(rec, "affected").iter().filter(|a| osv::matches(a, eco, pkg)).collect();
    if named.is_empty() {
        return Some(false);
    }
    crate::checks::ecosystems::Ecosystem::of(eco)?;
    for a in &named {
        let ranges = arr_at(a, "ranges");
        let comparable = ranges.iter().any(|r| matches!(str_at(r, "type"), "SEMVER" | "ECOSYSTEM"));
        let listed = !crate::utils::json::strs_at(a, "versions").is_empty();
        if !comparable && !listed && !ranges.is_empty() {
            return None;
        }
        if !comparable && !listed && ranges.is_empty() {
            // Every version: a malicious package names none.
            return Some(true);
        }
    }
    let order = crate::checks::ecosystems::order(eco);
    Some(!osv::affected_range(rec, eco, pkg, version, |a, b| order.cmp(a, b)).is_empty())
}

/// Read each ecosystem's change list (the ecosystems of `items`), apply
/// what changed to the cached answers, and say which answers are current.
/// `restart` (`--refresh`) starts every chain again.
pub fn sync(
    cache: &Cache,
    net: &dyn Net,
    items: &BTreeSet<&Item>,
    restart: bool,
    status: crate::component::Status,
) -> Result<Synced> {
    let mut out = Synced::default();
    if fetch::on("osv-changes").is_err() || osv::endpoints().iter().any(|(id, _)| id != "osv") {
        // Turned off, or the user's own advisory APIs too: ask as before.
        return Ok(out);
    }
    let mut by_dir: BTreeMap<String, Vec<&Item>> = BTreeMap::new();
    for it in items {
        if let Some(d) = directory(&it.0) {
            by_dir.entry(d).or_default().push(it);
        }
    }
    let base = file::url("osv-changes").trim_end_matches('/').to_string();
    for (dir, mine) in by_dir {
        status(&format!("Reading OSV's changes for {dir}"));
        let (cursor_key, since_key) = (format!("osv_cursor:{dir}"), format!("osv_since:{dir}"));
        let cursor = cache.get(&cursor_key)?.and_then(|c| seconds(&c));
        let since = cache.get(&since_key)?.and_then(|s| s.parse::<f64>().ok());
        let url = format!("{base}/{}/modified_id.csv", dir.replace(' ', "%20"));
        let chained = match (cursor, since) {
            (Some(c), Some(s)) if !restart => Some((c, s)),
            _ => None,
        };
        // Read moments ago (another check of this scan, or the scan before):
        // nothing new is worth a request.
        let read = cache.get(&format!("osv_read:{dir}"))?.and_then(|r| r.parse::<f64>().ok());
        if let (Some((_, since)), Some(read)) = (chained, read)
            && read >= now() - RECENT
        {
            out.since.insert(dir, since);
            continue;
        }
        // With a chain, everything since the cursor (and a day before it);
        // without, only the newest time, to start one.
        let after = chained.map_or(f64::INFINITY, |(c, _)| c - OVERLAP);
        let listed = match changes(net, &url, after) {
            Ok(l) => l,
            Err(e) if e.is_source() => {
                out.failed.push(format!("{dir}: {e}"));
                continue;
            }
            Err(e) => return Err(e),
        };
        let started = now();
        match (listed, chained) {
            (Listed::NoList, _) => {}
            (Listed::Changes(lines, newest), Some((_, since))) => {
                // What the overlap shows again and was applied last time is skipped.
                let done_key = format!("osv_done:{dir}");
                let done: BTreeSet<String> =
                    cache.get(&done_key)?.unwrap_or_default().lines().map(String::from).collect();
                let line = |(t, id): &(String, String)| format!("{t},{id}");
                let ids: Vec<String> =
                    lines.iter().filter(|l| !done.contains(&line(l))).map(|(_, id)| id.clone()).collect();
                match apply(cache, net, &ids, &mine, &mut out.reask, status) {
                    Ok(()) => {}
                    Err(e) if e.is_source() => {
                        out.failed.push(format!("{dir}: {e}"));
                        continue;
                    }
                    Err(e) => return Err(e),
                }
                if !newest.is_empty() {
                    cache.set(&cursor_key, &newest)?;
                }
                let window = seconds(&newest).unwrap_or(0.0) - OVERLAP;
                let recent: BTreeSet<String> = lines
                    .iter()
                    .map(line)
                    .chain(done)
                    .filter(|l| l.split(',').next().and_then(seconds).is_some_and(|t| t >= window))
                    .collect();
                cache.set(&done_key, &recent.into_iter().collect::<Vec<_>>().join("\n"))?;
                cache.set(&format!("osv_read:{dir}"), &started.to_string())?;
                out.since.insert(dir, since);
            }
            // No chain yet, a fresh start, or too much changed since the
            // last read: a chain from now; every answer from before it is
            // asked once more.
            (Listed::Changes(_, newest) | Listed::TooMany(newest), _) => {
                if !newest.is_empty() {
                    // The answers asked from now include the changes before
                    // it: the overlap's are applied already.
                    let window = seconds(&newest).unwrap_or(0.0) - OVERLAP;
                    if let Ok(Listed::Changes(lines, _)) = changes(net, &url, window) {
                        let done: Vec<String> = lines.iter().map(|(t, id)| format!("{t},{id}")).collect();
                        cache.set(&format!("osv_done:{dir}"), &done.join("\n"))?;
                    }
                    cache.set(&cursor_key, &newest)?;
                    cache.set(&since_key, &started.to_string())?;
                    cache.set(&format!("osv_read:{dir}"), &started.to_string())?;
                    out.since.insert(dir, started);
                }
            }
        }
        cache.commit()?;
    }
    Ok(out)
}

/// Whether an answer given at `at` about a version in `eco` is current: its
/// ecosystem's chain started no later, and its change list was read within
/// `max_age` seconds.
pub fn current(cache: &Cache, eco: &str, at: f64, max_age: f64) -> Result<bool> {
    let Some(dir) = directory(eco) else { return Ok(false) };
    let num = |k: String| -> Result<Option<f64>> { Ok(cache.get(&k)?.and_then(|v| v.parse::<f64>().ok())) };
    Ok(match (num(format!("osv_since:{dir}"))?, num(format!("osv_read:{dir}"))?) {
        (Some(since), Some(read)) => at >= since && read >= now() - max_age,
        _ => false,
    })
}

/// Download the changed records that concern this machine (held already,
/// or naming one of its packages) and apply each to the answers of the
/// versions it names; a version only OSV can judge goes into `reask`.
fn apply(
    cache: &Cache,
    net: &dyn Net,
    ids: &[String],
    mine: &[&Item],
    reask: &mut BTreeSet<Item>,
    status: crate::component::Status,
) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let ids: BTreeSet<&String> = ids.iter().collect();
    let base = ("osv".to_string(), file::url("osv").trim_end_matches('/').to_string());
    let want: Vec<osv::Want> = ids
        .iter()
        .map(|id| Ok(((*id).clone(), cache.get(&format!("vuln_etag:{id}"))?, base.clone())))
        .collect::<Result<_>>()?;
    for (id, fetched) in osv::fetch_records(net, &want, status)? {
        let Fetched::Record(rec, _) = &fetched else {
            // Not modified since we stored it, or not served: nothing changed here.
            continue;
        };
        let names_mine = mine.iter().any(|it| arr_at(rec, "affected").iter().any(|a| osv::matches(a, &it.0, &it.1)));
        if !names_mine && cache.vuln(&id)?.is_none() {
            continue;
        }
        let rec = rec.clone();
        osv::keep(cache, &id, fetched, None)?;
        for it in mine {
            let Some((at, listed)) = cache.query(&it.0, &it.1, &it.2)? else { continue };
            let had = listed.split_whitespace().any(|l| l == id);
            match affects(&rec, &it.0, &it.1, &it.2) {
                Some(affected) if affected != had => {
                    let mut kept: Vec<String> =
                        listed.split_whitespace().filter(|l| *l != id).map(String::from).collect();
                    if affected {
                        kept.push(id.clone());
                    }
                    cache.put_query_at(&it.0, &it.1, &it.2, &kept, at)?;
                }
                Some(_) => {}
                None => {
                    reask.insert((*it).clone());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "osv_changes_tests.rs"]
mod tests;
