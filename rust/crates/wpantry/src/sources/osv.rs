//! OSV.dev lookups (F8): one `querybatch` per 1000 (ecosystem, package,
//! version) answers which advisories apply, with ids and modified times only;
//! a record is downloaded only when it is new or OSV changed it since, at
//! most 8 at a time, with the stored ETag. An answer is kept current from
//! OSV's change lists ([`crate::sources::osv_changes`]) and isn't asked
//! again; where there is no list (git repos, the user's own advisory APIs)
//! it is reused for a day. Failures are never cached.

use crate::checks::ecosystems::versions;
use crate::component::Status;
use crate::db::Cache;
use crate::error::{Error, Result};
use crate::sources::fetch;
use crate::sources::file::url;
use crate::utils::json::{self, arr_at, str_at};
use crate::utils::net::Net;
use crate::utils::os::now;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::Duration;

pub const QUERY_TTL: f64 = 86400.0;
pub const TAGS_TTL: f64 = 7.0 * 86400.0;
pub const BATCH: usize = 1000;
pub const PARALLEL: usize = 8;

/// (ecosystem, package, version)
pub type Item = (String, String, String);

/// OSV's answers for some items, and what makes them incomplete.
#[derive(Debug, Default)]
pub struct Answers {
    /// Every item answered, cached or fresh, with its (not withdrawn)
    /// records. An item never answered (offline on a first run) is left
    /// out, so the caller reports it unchecked rather than clean.
    pub found: HashMap<Item, Vec<Value>>,
    /// Why some answers can't be trusted as complete: advisories OSV named
    /// whose records couldn't be downloaded, or answers older than a day that
    /// couldn't be asked again. The findings they do give still stand.
    pub gaps: Vec<String>,
}

/// OSV's answers for `items`. Only a cache failure is an error.
pub fn lookup(
    cache: &Cache,
    net: &dyn Net,
    items: &[Item],
    refresh: bool,
    offline: bool,
    log: &dyn Fn(&str),
    status: Status,
) -> Result<Answers> {
    let items: BTreeSet<&Item> = items.iter().collect();
    // OSV's change lists first: what changed since the last read is applied
    // to the answers held, so those needn't be asked again.
    let synced = if offline {
        crate::sources::osv_changes::Synced::default()
    } else {
        crate::sources::osv_changes::sync(cache, net, &items, refresh, status)?
    };
    for f in &synced.failed {
        log(&format!("  ⚠ OSV's change list unreachable, asking OSV instead ({f})"));
    }
    let current = |it: &Item, at: f64| -> Result<bool> {
        Ok(at >= now() - QUERY_TTL || crate::sources::osv_changes::current(cache, &it.0, at, QUERY_TTL)?)
    };
    let mut stale = Vec::new();
    for it in &items {
        match cache.query(&it.0, &it.1, &it.2)? {
            Some((at, _)) if !refresh && !synced.reask.contains(*it) && current(it, at)? => {}
            _ => stale.push((*it).clone()),
        }
    }
    let mut failure = offline.then(|| "--offline".to_string());
    if !stale.is_empty() && !offline {
        status(&format!("Asking OSV about {} package versions", stale.len()));
        match refresh_items(cache, net, &stale, status) {
            Ok(()) => {}
            Err(e) if e.is_source() => {
                log(&format!("  ⚠ OSV unreachable, using cached answers ({e})"));
                failure = Some(format!("OSV unreachable: {e}"));
            }
            Err(e) => return Err(e),
        }
    }
    // Records OSV named that aren't here (a download that failed before, or
    // a record OSV couldn't serve), and records OSV changed whose new
    // revision couldn't be downloaded (the old one is kept and still
    // counts). Ask again while online.
    let missing = |cache: &Cache| -> Result<(BTreeSet<String>, BTreeSet<String>)> {
        let (mut absent, mut stale) = (BTreeSet::new(), BTreeSet::new());
        for it in &items {
            if let Some((_, listed)) = cache.query(&it.0, &it.1, &it.2)? {
                for id in listed.split_whitespace() {
                    if cache.vuln(id)?.is_none() {
                        absent.insert(id.to_string());
                    } else if cache.get(&want_key(id))?.is_some() {
                        stale.insert(id.to_string());
                    }
                }
            }
        }
        Ok((absent, stale))
    };
    let (mut absent, mut stale) = missing(cache)?;
    if !(absent.is_empty() && stale.is_empty()) && failure.is_none() {
        let first = endpoints().into_iter().next().unwrap_or_else(|| ("osv".into(), url("osv").to_string()));
        let ids: Vec<Want> = absent.iter().chain(&stale).map(|id| (id.clone(), None, first.clone())).collect();
        let retry = || -> Result<()> {
            for group in ids.chunks(PARALLEL) {
                for (id, f) in fetch_records(net, group, status)? {
                    keep(cache, &id, f, None)?;
                }
                cache.commit()?;
            }
            Ok(())
        };
        match retry() {
            Ok(()) => {}
            Err(e) if e.is_source() => failure = Some(format!("OSV unreachable: {e}")),
            Err(e) => return Err(e),
        }
        (absent, stale) = missing(cache)?;
    }
    let mut out = Answers::default();
    let mut old = 0;
    for it in items {
        let Some((at, ids)) = cache.query(&it.0, &it.1, &it.2)? else { continue };
        if !current(it, at)? {
            old += 1;
        }
        let mut recs = Vec::new();
        for id in ids.split_whitespace() {
            if let Some(mut r) = cache.vuln(id)?
                && r.get("withdrawn").is_none_or(Value::is_null)
            {
                // The cache retains the original record. Each query only needs
                // its own package/release, not every distro in a kernel record.
                if let Some(affected) = r.get_mut("affected").and_then(Value::as_array_mut) {
                    affected.retain(|a| matches(a, &it.0, &it.1));
                }
                recs.push(r);
            }
        }
        out.found.insert(it.clone(), recs);
    }
    if !absent.is_empty() {
        let ids: Vec<&str> = absent.iter().map(String::as_str).collect();
        out.gaps.push(format!("OSV lists advisories it couldn't serve here: {}", ids.join(", ")));
    }
    if !stale.is_empty() {
        let ids: Vec<&str> = stale.iter().map(String::as_str).collect();
        out.gaps.push(format!("OSV changed advisories whose new revision couldn't be downloaded: {}", ids.join(", ")));
    }
    if old > 0 {
        let why = failure.unwrap_or_else(|| "OSV wasn't asked again".into());
        out.gaps.push(format!("{old} answers are more than a day out of date and couldn't be refreshed ({why})"));
    }
    Ok(out)
}

fn store_record(cache: &Cache, rec: &Value, etag: Option<&str>) -> Result<()> {
    cache.put_vuln(rec)?;
    if let Some(e) = etag {
        cache.set(&format!("vuln_etag:{}", str_at(rec, "id")), e)?;
    }
    Ok(())
}

/// The meta key that marks a stored record as older than the revision OSV
/// reports (`wanted`, its `modified`), until that revision is downloaded.
fn want_key(id: &str) -> String {
    format!("vuln_want:{id}")
}

/// What a download of `id` leaves in the cache: the record (and no mark),
/// or, when OSV couldn't serve the revision it reported (`wanted`) and an
/// older one is stored, the old record marked stale so the scan reports
/// the gap and the next run asks again. A record OSV never served at all
/// is left absent, which [`lookup`] reports on its own.
pub(crate) fn keep(cache: &Cache, id: &str, fetched: Fetched, wanted: Option<&str>) -> Result<()> {
    match fetched {
        Fetched::Record(rec, etag) => {
            store_record(cache, &rec, etag.as_deref())?;
            cache.unset(&want_key(id))
        }
        Fetched::NotModified => cache.unset(&want_key(id)),
        Fetched::Missing => match wanted {
            Some(w) if cache.vuln(id)?.is_some() => cache.set(&want_key(id), w),
            _ => Ok(()),
        },
    }
}

fn query(it: &Item) -> Value {
    json!({"package": {"ecosystem": it.0, "name": it.1}, "version": it.2})
}

/// (id, modified) pairs from a querybatch or query answer for `what`. OSV
/// leaves `vulns` out when no advisory applies; present, it must be a list
/// of advisories each with an id, or the answer is no answer: anything
/// else cached as "none" would be a clean check of nothing.
fn hits(v: &Value, what: &str) -> Result<Vec<(String, String)>> {
    let vulns = match v.get("vulns") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        Some(other) => return Err(Error::Invalid(format!("OSV answered {what} with vulns {other}"))),
    };
    vulns
        .iter()
        .map(|h| match h.get("id").and_then(Value::as_str) {
            Some(id) if !id.is_empty() => Ok((id.to_string(), str_at(h, "modified").to_string())),
            _ => Err(Error::Invalid(format!("OSV answered {what} with an advisory without an id: {h}"))),
        })
        .collect()
}

/// The OSV-compatible APIs in use, in order: OSV.dev (unless turned off)
/// and any of the user's own (`format = "osv-api"`). Each is asked; the
/// advisories they name are merged.
pub(crate) fn endpoints() -> Vec<(String, String)> {
    crate::sources::file::effective()
        .sources
        .iter()
        .filter(|s| s.format == "osv-api" && crate::sources::file::active(&s.id))
        .map(|s| (s.id.clone(), s.url.trim_end_matches('/').to_string()))
        .collect()
}

fn refresh_items(cache: &Cache, net: &dyn Net, stale: &[Item], status: Status) -> Result<()> {
    let endpoints = endpoints();
    if endpoints.is_empty() {
        return Err(Error::Offline("no advisory source is on (sources.toml)".into()));
    }
    let mut answers: Vec<(Item, Vec<(String, String)>)> = stale.iter().map(|it| (it.clone(), Vec::new())).collect();
    // Which API named each advisory first: its record is downloaded there.
    let mut named_by: BTreeMap<String, usize> = BTreeMap::new();
    for (e, (sid, base)) in endpoints.iter().enumerate() {
        for (vulns, it) in refresh_from(net, sid, base, stale)?.into_iter().zip(stale) {
            let answer = &mut answers.iter_mut().find(|(i, _)| i == it).expect("every stale item").1;
            for v in vulns {
                named_by.entry(v.0.clone()).or_insert(e);
                if !answer.iter().any(|(id, _)| *id == v.0) {
                    answer.push(v);
                }
            }
        }
    }
    finish_refresh(cache, net, &endpoints, &named_by, answers, status)
}

/// Each stale item's advisories `(id, modified)` from one OSV-compatible API.
fn refresh_from(net: &dyn Net, sid: &str, base: &str, stale: &[Item]) -> Result<Vec<Vec<(String, String)>>> {
    let mut answers: Vec<Vec<(String, String)>> = Vec::new();
    for chunk in stale.chunks(BATCH) {
        let body = json!({"queries": chunk.iter().map(query).collect::<Vec<_>>()});
        let res = fetch::post_json(net, sid, &format!("{base}/querybatch"), &body)?;
        let results = arr_at(&res, "results");
        if results.len() != chunk.len() {
            return Err(Error::Invalid(format!(
                "OSV querybatch answered {} of {} queries",
                results.len(),
                chunk.len()
            )));
        }
        for (it, r) in chunk.iter().zip(results) {
            let what = format!("{}@{}", it.1, it.2);
            if !r.is_object() {
                return Err(Error::Invalid(format!("OSV querybatch answered {r} for {what}")));
            }
            let mut vulns = hits(r, &what)?;
            let mut token = str_at(r, "next_page_token").to_string();
            let mut seen = BTreeSet::new();
            while !token.is_empty() {
                // Keep pagination on querybatch: /query returns full records,
                // which can consume gigabytes for distro kernel/browser packages.
                if !seen.insert(token.clone()) || seen.len() > 128 {
                    return Err(Error::Invalid(format!("OSV pagination did not finish for {what}")));
                }
                let mut q = query(it);
                q["page_token"] = Value::String(token);
                let response = fetch::post_json(net, sid, &format!("{base}/querybatch"), &json!({"queries": [q]}))?;
                let pages = arr_at(&response, "results");
                if pages.len() != 1 || !pages[0].is_object() {
                    return Err(Error::Invalid(format!("OSV answered {response} for a page of {what}")));
                }
                let page = &pages[0];
                vulns.extend(hits(page, &what)?);
                token = str_at(page, "next_page_token").to_string();
            }
            answers.push(vulns);
        }
    }
    Ok(answers)
}

/// Download the records named that aren't stored at their revision, each
/// from the API that named it, and keep every item's answer.
fn finish_refresh(
    cache: &Cache,
    net: &dyn Net,
    endpoints: &[(String, String)],
    named_by: &BTreeMap<String, usize>,
    answers: Vec<(Item, Vec<(String, String)>)>,
    status: Status,
) -> Result<()> {
    // The revision OSV reports for each advisory named; a record stored at
    // another revision is downloaded again.
    let mut wanted: BTreeMap<String, String> = BTreeMap::new();
    for (_, vulns) in &answers {
        for (id, modified) in vulns {
            if cache.modified(id)?.as_deref() != Some(modified.as_str()) {
                wanted.insert(id.clone(), modified.clone());
            }
        }
    }
    let etags: Vec<(String, Option<String>, (String, String))> = wanted
        .keys()
        .map(|id| {
            let ep = endpoints[named_by.get(id).copied().unwrap_or(0)].clone();
            Ok((id.clone(), cache.get(&format!("vuln_etag:{id}"))?, ep))
        })
        .collect::<Result<_>>()?;
    // Persist bounded groups rather than retaining every full advisory.
    // Successfully fetched records survive a later download failure.
    for group in etags.chunks(PARALLEL) {
        for (id, fetched) in fetch_records(net, group, status)? {
            keep(cache, &id, fetched, wanted.get(&id).map(String::as_str))?;
        }
        cache.commit()?;
    }
    for (it, vulns) in &answers {
        let ids: Vec<String> = vulns.iter().map(|(id, _)| id.clone()).collect();
        cache.put_query(&it.0, &it.1, &it.2, &ids)?;
    }
    cache.commit()
}

/// One record download.
#[derive(Debug)]
pub(crate) enum Fetched {
    Record(Value, Option<String>),
    /// 304: the cached record stands.
    NotModified,
    /// A 404, or a body that isn't the record asked for: nothing is stored,
    /// so the next run asks again and the scan reports the gap meanwhile.
    Missing,
}

/// GET /v1/vulns/{id} for each id, at most [`PARALLEL`] in flight, each
/// with its stored ETag, from the API `(source, base)` that named it.
pub(crate) type Want = (String, Option<String>, (String, String));

pub(crate) fn fetch_records(net: &dyn Net, ids: &[Want], status: Status) -> Result<Vec<(String, Fetched)>> {
    let queue = Mutex::new(ids.iter());
    let results = Mutex::new(Vec::new());
    let first_error = Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..PARALLEL.min(ids.len()) {
            s.spawn(|| {
                loop {
                    if first_error.lock().expect("lock").is_some() {
                        return;
                    }
                    let Some((id, etag, (sid, base))) = queue.lock().expect("lock").next() else { return };
                    let url = format!("{base}/vulns/{id}");
                    let got = fetch::request(net, sid, &url, None, &[], etag.as_deref()).map(|r| match r.status {
                        200 => match json::parse(&r.body, json::MAX_DOCUMENT) {
                            Ok(rec) if str_at(&rec, "id") == id => Fetched::Record(rec, r.etag),
                            _ => Fetched::Missing,
                        },
                        304 => Fetched::NotModified,
                        _ => Fetched::Missing,
                    });
                    match got {
                        Ok(rec) => {
                            let mut done = results.lock().expect("lock");
                            done.push((id.clone(), rec));
                            status(&format!("Downloading advisories from OSV ({}/{}): {id}", done.len(), ids.len()));
                        }
                        Err(e) => {
                            first_error.lock().expect("lock").get_or_insert(e);
                            return;
                        }
                    }
                }
            });
        }
    });
    if let Some(e) = first_error.into_inner().expect("lock") {
        return Err(e);
    }
    let mut out = results.into_inner().expect("lock");
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn norm_repo(url: &str) -> String {
    let u = url.to_lowercase();
    let u = u.strip_suffix('/').unwrap_or(&u);
    u.strip_suffix(".git").unwrap_or(u).to_string()
}

pub(crate) fn matches(affected: &Value, eco: &str, pkg: &str) -> bool {
    let p = affected.get("package").cloned().unwrap_or(Value::Null);
    if eco == "GIT" {
        let want = norm_repo(pkg);
        return arr_at(affected, "ranges").iter().any(|r| norm_repo(str_at(r, "repo")) == want)
            || norm_repo(str_at(&p, "name")) == want;
    }
    if str_at(&p, "name") != pkg {
        return false;
    }
    // A distro release ("Debian:13", "Ubuntu:24.04") only takes fixes for
    // that release, however the record suffixes it ("Ubuntu:24.04:LTS"; not
    // "Ubuntu:Pro:…", which needs a subscription). A plain ecosystem
    // ("PyPI") matches however the record qualifies it.
    let have = str_at(&p, "ecosystem");
    if eco.contains(':') {
        return have == eco || have.starts_with(&format!("{eco}:"));
    }
    have.split(':').next() == Some(eco)
}

/// The affected range of `rec` for this package that `installed` falls in,
/// written as a reader expects (`>=7.2.0, <9.0.0`; `>=1.0.0, <=1.0.3` for a
/// `last_affected` bound; `>=2.0.0` open-ended; `=1.2.3` when the record
/// lists versions one by one), compared with `order`. "" when the record
/// has no such range (a GIT range of commits, or a record that doesn't
/// name this package).
pub fn affected_range(
    rec: &Value,
    eco: &str,
    pkg: &str,
    installed: &str,
    order: impl Fn(&str, &str) -> std::cmp::Ordering,
) -> String {
    use std::cmp::Ordering::{Greater, Less};
    let ge = |a: &str, b: &str| order(a, b) != Less; // a >= b
    for a in arr_at(rec, "affected").iter().filter(|a| matches(a, eco, pkg)) {
        for r in arr_at(a, "ranges").iter().filter(|r| matches!(str_at(r, "type"), "SEMVER" | "ECOSYSTEM")) {
            // Events in order open and close intervals: introduced, then
            // fixed or last_affected.
            let mut start: Option<String> = None;
            let mut intervals: Vec<(String, Option<(bool, String)>)> = Vec::new();
            for e in arr_at(r, "events") {
                if let Some(v) = e.get("introduced").and_then(Value::as_str) {
                    if let Some(s) = start.take() {
                        intervals.push((s, None));
                    }
                    start = Some(v.to_string());
                } else if let Some(v) = e.get("fixed").and_then(Value::as_str) {
                    intervals.push((start.take().unwrap_or_else(|| "0".into()), Some((false, v.to_string()))));
                } else if let Some(v) = e.get("last_affected").and_then(Value::as_str) {
                    intervals.push((start.take().unwrap_or_else(|| "0".into()), Some((true, v.to_string()))));
                }
            }
            if let Some(s) = start.take() {
                intervals.push((s, None));
            }
            for (from, to) in intervals {
                let after_start = from == "0" || ge(installed, &from);
                let before_end = match &to {
                    None => true,
                    Some((true, last)) => order(installed, last) != Greater,
                    Some((false, fixed)) => order(installed, fixed) == Less,
                };
                if after_start && before_end {
                    let lower = if from == "0" { String::new() } else { format!(">={from}") };
                    let upper = match &to {
                        None => String::new(),
                        Some((true, last)) => format!("<={last}"),
                        Some((false, fixed)) => format!("<{fixed}"),
                    };
                    return match (lower.is_empty(), upper.is_empty()) {
                        (false, false) => format!("{lower}, {upper}"),
                        (true, false) => upper,
                        (false, true) => lower,
                        (true, true) => ">=0".into(),
                    };
                }
            }
        }
        if json::strs_at(a, "versions").iter().any(|v| v == installed) {
            return format!("={installed}");
        }
    }
    String::new()
}

/// A version string, not a commit hash standing in for an unreleased fix.
pub fn released(version: &str) -> bool {
    let hash = (12..=40).contains(&version.len()) && version.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    !version.is_empty() && !hash
}

/// Released versions that fix `rec` for this package (choose one with
/// [`versions::pick_safe_by`]). Empty when no release fixes it: an advisory
/// whose only fix is a commit counts as unfixed.
///
/// For an upstream git repo, `newer` is {tag: advisory ids OSV reports for
/// that tag} for the releases after the installed one; a tag fixes `rec`
/// when OSV no longer reports it for that tag.
pub fn fixed_versions(rec: &Value, eco: &str, pkg: &str, newer: Option<&BTreeMap<String, Vec<String>>>) -> Vec<String> {
    let mut out = Vec::new();
    for a in arr_at(rec, "affected") {
        if !matches(a, eco, pkg) {
            continue;
        }
        for r in arr_at(a, "ranges") {
            if matches!(str_at(r, "type"), "SEMVER" | "ECOSYSTEM") {
                for e in arr_at(r, "events") {
                    if let Some(f) = e.get("fixed").and_then(Value::as_str)
                        && released(f)
                    {
                        out.push(f.to_string());
                    }
                }
            }
        }
    }
    if eco == "GIT"
        && out.is_empty()
        && let Some(newer) = newer
    {
        let mut ids = vec![str_at(rec, "id").to_string()];
        ids.extend(json::strs_at(rec, "aliases"));
        out =
            newer.iter().filter(|(_, found)| !found.iter().any(|f| ids.contains(f))).map(|(t, _)| t.clone()).collect();
    }
    out
}

/// The record's id, aliases and (distro records) upstream CVE ids.
pub fn ids_of(rec: &Value) -> Vec<String> {
    let mut ids = vec![str_at(rec, "id").to_string()];
    ids.extend(json::strs_at(rec, "aliases"));
    ids.extend(json::strs_at(rec, "upstream"));
    ids
}

/// Records grouped by alias (id, aliases, upstream), so one vulnerability
/// from two databases is one finding. Groups keep the records' order.
pub fn group_by_alias(recs: &[Value]) -> Vec<Vec<Value>> {
    let mut parent: Vec<usize> = (0..recs.len()).collect();
    fn root(p: &mut [usize], mut i: usize) -> usize {
        while p[i] != i {
            p[i] = p[p[i]];
            i = p[i];
        }
        i
    }
    let mut owner: HashMap<String, usize> = HashMap::new();
    for (i, r) in recs.iter().enumerate() {
        for id in ids_of(r).into_iter().filter(|id| !id.is_empty()) {
            match owner.get(&id) {
                Some(&j) => {
                    let (a, b) = (root(&mut parent, i), root(&mut parent, j));
                    parent[a.max(b)] = a.min(b);
                }
                None => {
                    owner.insert(id, i);
                }
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<Value>> = BTreeMap::new();
    for (i, r) in recs.iter().enumerate() {
        let g = root(&mut parent, i);
        groups.entry(g).or_default().push(r.clone());
    }
    groups.into_values().collect()
}

fn shape(tag: &str) -> String {
    let mut out = String::new();
    let mut digit = false;
    for c in tag.chars() {
        if c.is_ascii_digit() {
            if !digit {
                out.push('N');
            }
            digit = true;
        } else {
            out.push(c);
            digit = false;
        }
    }
    out
}

/// Release tags after `installed` worth asking OSV about: the rest of its
/// release line, plus the newest tag of each later line.
pub fn candidates(cache: &Cache, repo: &str, installed: &str, offline: bool) -> Result<Vec<String>> {
    const PER_LINE: usize = 25;
    const LINES: usize = 6;
    let want = shape(installed);
    let newer: Vec<String> =
        tags(cache, repo, offline)?.into_iter().filter(|t| shape(t) == want && versions::lt(installed, t)).collect();
    let n = versions::numbers(installed).len().saturating_sub(1).max(1);
    let mut same: Vec<&String> = newer.iter().filter(|t| versions::common_prefix(installed, t) >= n).collect();
    same.sort_by(|a, b| versions::cmp(a, b));
    let mut later: BTreeMap<Vec<String>, &String> = BTreeMap::new();
    for t in &newer {
        if versions::common_prefix(installed, t) < n {
            let line: Vec<String> = versions::numbers(t).into_iter().take(n).collect();
            match later.get(&line) {
                Some(cur) if !versions::lt(cur, t) => {}
                _ => {
                    later.insert(line, t);
                }
            }
        }
    }
    let mut later: Vec<&String> = later.into_values().collect();
    later.sort_by(|a, b| versions::cmp(a, b));
    Ok(same.into_iter().take(PER_LINE).chain(later.into_iter().take(LINES)).cloned().collect())
}

/// Release tags of an upstream repo, from `git ls-remote`, cached a week;
/// none when they can't be listed.
pub fn tags(cache: &Cache, repo: &str, offline: bool) -> Result<Vec<String>> {
    let fetch = || -> Result<Value> {
        let out = crate::utils::process::exec(
            &["git".as_ref(), "ls-remote".as_ref(), "--tags".as_ref(), "--refs".as_ref(), repo.as_ref()],
            &[("GIT_TERMINAL_PROMPT", "0")],
            Duration::from_secs(60),
        )
        .map_err(|e| Error::Offline(e.to_string()))?;
        if out.code != Some(0) {
            return Err(Error::Offline(out.stderr.trim().chars().take(200).collect()));
        }
        let tags: Vec<Value> = out
            .stdout
            .lines()
            .filter_map(|l| l.split_once("refs/tags/").map(|(_, t)| Value::String(t.to_string())))
            .collect();
        Ok(Value::Array(tags))
    };
    let fetch = || {
        let r = fetch();
        fetch::note("osv-git-tags", &r);
        r
    };
    match fetch::memo(cache, "osv-git-tags", &format!("tags:{repo}"), fetch, "", false, offline) {
        Ok(v) => Ok(v
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default()),
        Err(e) if e.is_source() => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "osv_tests.rs"]
mod tests;
