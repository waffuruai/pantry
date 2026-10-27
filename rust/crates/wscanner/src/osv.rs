//! OSV.dev lookups (F8): one `querybatch` per 1000 (ecosystem, package,
//! version) answers which advisories apply, with ids and modified times only;
//! a record is downloaded only when it is new or OSV changed it since, at
//! most 8 at a time, with the stored ETag. Answers are reused for a day, so a
//! second run the same day makes no OSV calls at all. Failures are never
//! cached.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::json::{self, arr_at, str_at};
use crate::net::{self, Net};
use crate::system::now;
use crate::versions;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::Duration;

pub const API: &str = "https://api.osv.dev/v1";
pub const QUERY_TTL: f64 = 86400.0;
pub const TAGS_TTL: f64 = 7.0 * 86400.0;
pub const BATCH: usize = 1000;
pub const PARALLEL: usize = 8;

/// (ecosystem, package, version)
pub type Item = (String, String, String);

/// OSV's answers for `items`: every item answered, cached or fresh, maps to
/// its (not withdrawn) records; an item never answered (offline on a first
/// run) is left out, so the caller reports it unchecked rather than clean.
/// Only a cache failure is an error.
pub fn lookup(
    cache: &Cache,
    net: &dyn Net,
    items: &[Item],
    refresh: bool,
    offline: bool,
    log: &dyn Fn(&str),
) -> Result<HashMap<Item, Vec<Value>>> {
    let items: BTreeSet<&Item> = items.iter().collect();
    let mut stale = Vec::new();
    for it in &items {
        match cache.query(&it.0, &it.1, &it.2)? {
            Some((at, _)) if !refresh && at >= now() - QUERY_TTL => {}
            _ => stale.push((*it).clone()),
        }
    }
    if !stale.is_empty() && !offline {
        match refresh_items(cache, net, &stale) {
            Ok(()) => {}
            Err(e) if e.is_source() => log(&format!("  ⚠ OSV unreachable, using cached answers ({e})")),
            Err(e) => return Err(e),
        }
    }
    let mut out = HashMap::new();
    for it in items {
        let Some((_, ids)) = cache.query(&it.0, &it.1, &it.2)? else { continue };
        let mut recs = Vec::new();
        for id in ids.split_whitespace() {
            if let Some(r) = cache.vuln(id)?
                && r.get("withdrawn").is_none_or(Value::is_null)
            {
                recs.push(r);
            }
        }
        out.insert(it.clone(), recs);
    }
    Ok(out)
}

fn query(it: &Item) -> Value {
    json!({"package": {"ecosystem": it.0, "name": it.1}, "version": it.2})
}

/// (id, modified) pairs from a querybatch or query answer.
fn hits(v: &Value) -> Vec<(String, String)> {
    arr_at(v, "vulns")
        .iter()
        .filter(|h| !str_at(h, "id").is_empty())
        .map(|h| (str_at(h, "id").to_string(), str_at(h, "modified").to_string()))
        .collect()
}

fn refresh_items(cache: &Cache, net: &dyn Net, stale: &[Item]) -> Result<()> {
    let mut answers: Vec<(Item, Vec<(String, String)>)> = Vec::new();
    for chunk in stale.chunks(BATCH) {
        let body = json!({"queries": chunk.iter().map(query).collect::<Vec<_>>()});
        let res = net::post_json(net, &format!("{API}/querybatch"), &body)?;
        let results = arr_at(&res, "results");
        if results.len() != chunk.len() {
            return Err(Error::Invalid(format!(
                "OSV querybatch answered {} of {} queries",
                results.len(),
                chunk.len()
            )));
        }
        for (it, r) in chunk.iter().zip(results) {
            let mut vulns = hits(r);
            let mut token = str_at(r, "next_page_token").to_string();
            while !token.is_empty() {
                // Rare: more than one page of advisories for one version.
                let mut q = query(it);
                q["page_token"] = Value::String(token);
                let page = net::post_json(net, &format!("{API}/query"), &q)?;
                vulns.extend(hits(&page));
                token = str_at(&page, "next_page_token").to_string();
            }
            answers.push((it.clone(), vulns));
        }
    }
    let mut need = BTreeSet::new();
    for (_, vulns) in &answers {
        for (id, modified) in vulns {
            if cache.modified(id)?.as_deref() != Some(modified.as_str()) {
                need.insert(id.clone());
            }
        }
    }
    let etags: Vec<(String, Option<String>)> =
        need.into_iter().map(|id| Ok((id.clone(), cache.get(&format!("vuln_etag:{id}"))?))).collect::<Result<_>>()?;
    for (id, fetched) in fetch_records(net, &etags)? {
        if let Some((rec, etag)) = fetched {
            cache.put_vuln(&rec)?;
            if let Some(e) = etag {
                cache.set(&format!("vuln_etag:{id}"), &e)?;
            }
        }
    }
    for (it, vulns) in &answers {
        let ids: Vec<String> = vulns.iter().map(|(id, _)| id.clone()).collect();
        cache.put_query(&it.0, &it.1, &it.2, &ids)?;
    }
    cache.commit()
}

type Fetched = Option<(Value, Option<String>)>;

/// GET /v1/vulns/{id} for each id, at most [`PARALLEL`] in flight, each
/// with its stored ETag. None for a 404 or a 304 (the cached record stands).
fn fetch_records(net: &dyn Net, ids: &[(String, Option<String>)]) -> Result<Vec<(String, Fetched)>> {
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
                    let Some((id, etag)) = queue.lock().expect("lock").next() else { return };
                    let url = format!("{API}/vulns/{id}");
                    let got = net::request(net, &url, None, &[], etag.as_deref()).and_then(|r| match r.status {
                        200 => Ok(Some((json::parse(&r.body, json::MAX_DOCUMENT)?, r.etag))),
                        _ => Ok(None),
                    });
                    match got {
                        Ok(rec) => results.lock().expect("lock").push((id.clone(), rec)),
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

fn matches(affected: &Value, eco: &str, pkg: &str) -> bool {
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
        let out = crate::system::exec(
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
    match cache.memo(&format!("tags:{repo}"), fetch, TAGS_TTL, "", false, offline) {
        Ok(v) => Ok(v
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default()),
        Err(e) if e.is_source() => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{Fake, Response};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const GIT: &str = "https://github.com/python/cpython.git";

    fn rec(id: &str, ranges: Value, aliases: &[&str], pkg: Option<(&str, &str)>) -> Value {
        let mut affected = json!({"ranges": ranges, "versions": []});
        if let Some((e, n)) = pkg {
            affected["package"] = json!({"ecosystem": e, "name": n});
        }
        json!({"id": id, "aliases": aliases, "summary": format!("{id} summary"),
               "modified": "2026-10-01T00:00:00Z", "affected": [affected]})
    }

    fn cache() -> (crate::system::TempDir, Cache) {
        let d = crate::system::TempDir::new("osv").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        (d, c)
    }

    fn item(e: &str, n: &str, v: &str) -> Item {
        (e.into(), n.into(), v.into())
    }

    // The Python test vectors (python/test_wscanner.py `Fixes`).
    #[test]
    fn semver_fix() {
        let r = rec(
            "RUSTSEC-1",
            json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.10"}]}]),
            &[],
            Some(("crates.io", "webpki-roots")),
        );
        assert_eq!(fixed_versions(&r, "crates.io", "webpki-roots", None), ["1.0.10"]);
        assert!(fixed_versions(&r, "crates.io", "other", None).is_empty());
    }

    #[test]
    fn distro_release_only_takes_its_own_fix() {
        let r = json!({"id": "DEBIAN-CVE-1", "upstream": ["CVE-1"], "affected": [
            {"package": {"ecosystem": "Debian:13", "name": "acl"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
            {"package": {"ecosystem": "Debian:14", "name": "acl"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.4.0-1"}]}]}]});
        assert!(fixed_versions(&r, "Debian:13", "acl", None).is_empty());
        assert_eq!(fixed_versions(&r, "Debian:14", "acl", None), ["2.4.0-1"]);
        assert!(ids_of(&r).contains(&"CVE-1".to_string()));
    }

    #[test]
    fn ubuntu_release_suffix_matches_but_pro_does_not() {
        let r = json!({"id": "USN-1", "affected": [
            {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "glibc"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.39-0ubuntu8.9"}]}]},
            {"package": {"ecosystem": "Ubuntu:Pro:24.04:LTS", "name": "glibc"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.39-0ubuntu8.9+esm1"}]}]}]});
        assert_eq!(fixed_versions(&r, "Ubuntu:24.04", "glibc", None), ["2.39-0ubuntu8.9"]);
    }

    #[test]
    fn commit_hash_is_not_a_release() {
        let r = rec(
            "OSV-1",
            json!([{"type": "ECOSYSTEM", "events": [{"fixed": "76b7feab363d547e06151c8a8aa0ca72ade0594a"}]}]),
            &[],
            Some(("npm", "x")),
        );
        assert!(fixed_versions(&r, "npm", "x", None).is_empty());
        assert!(!released("76b7feab363d547e06151c8a8aa0ca72ade0594a"));
        assert!(released("1.2.3"));
    }

    #[test]
    fn git_fix_is_the_tag_osv_stops_reporting() {
        let r = rec("CVE-2026-1", json!([{"type": "GIT", "repo": GIT, "events": [{"introduced": "abc"}]}]), &[], None);
        let newer: BTreeMap<String, Vec<String>> = [
            ("v3.12.14".to_string(), vec!["CVE-2026-1".to_string()]),
            ("v3.12.15".to_string(), vec![]),
            ("v3.13.9".to_string(), vec!["OTHER".to_string()]),
        ]
        .into();
        assert_eq!(fixed_versions(&r, "GIT", GIT, Some(&newer)), ["v3.12.15", "v3.13.9"]);
        let only: BTreeMap<_, _> = [("v3.12.14".to_string(), vec!["CVE-2026-1".to_string()])].into();
        assert!(fixed_versions(&r, "GIT", GIT, Some(&only)).is_empty());
        let r = rec(
            "PSF-1",
            json!([{"type": "GIT", "repo": GIT, "events": [{"introduced": "abc"}]}]),
            &["CVE-2026-2"],
            None,
        );
        let aliased: BTreeMap<_, _> = [("v3.14.5".to_string(), vec!["CVE-2026-2".to_string()])].into();
        assert!(fixed_versions(&r, "GIT", GIT, Some(&aliased)).is_empty(), "matches aliases");
    }

    #[test]
    fn candidates_from_cached_tags() {
        let (_d, c) = cache();
        let tags =
            json!(["v3.12.12", "v3.12.13", "v3.12.14", "v3.12.15", "v3.13.0", "v3.13.9", "v3.14.0rc1", "v3.14.5"]);
        c.put_run(&format!("tags:{GIT}"), "", &tags).unwrap();
        assert_eq!(candidates(&c, GIT, "v3.12.13", true).unwrap(), ["v3.12.14", "v3.12.15", "v3.13.9", "v3.14.5"]);
    }

    #[test]
    fn groups_aliases_transitively() {
        let a = json!({"id": "GHSA-1", "aliases": ["CVE-1"]});
        let b = json!({"id": "RUSTSEC-1", "aliases": ["CVE-1"]});
        let c = json!({"id": "DEBIAN-CVE-2", "upstream": ["CVE-2"]});
        let d = json!({"id": "CVE-2"});
        let g = group_by_alias(&[a, b, c, d]);
        let ids: Vec<Vec<&str>> = g.iter().map(|g| g.iter().map(|r| r["id"].as_str().unwrap()).collect()).collect();
        assert_eq!(ids, [vec!["GHSA-1", "RUSTSEC-1"], vec!["DEBIAN-CVE-2", "CVE-2"]]);
    }

    #[test]
    fn lookup_offline_uses_cached_answers() {
        let (_d, c) = cache();
        c.put_vuln(&rec("CVE-2026-3", json!([]), &[], Some(("PyPI", "pip")))).unwrap();
        c.put_query("PyPI", "pip", "26.0.1", &["CVE-2026-3".into()]).unwrap();
        let net = Fake::new(|_| panic!("offline lookups make no requests"));
        let got = lookup(&c, &net, &[item("PyPI", "pip", "26.0.1"), item("PyPI", "uv", "0.1.0")], false, true, &|_| {})
            .unwrap();
        assert_eq!(got[&item("PyPI", "pip", "26.0.1")][0]["id"], "CVE-2026-3");
        assert!(!got.contains_key(&item("PyPI", "uv", "0.1.0")), "never answered: unknown, not clean");
    }

    #[test]
    fn lookup_batches_pages_fetches_changed_records_and_caches() {
        let (_d, c) = cache();
        // GHSA-old is cached with the modified time OSV still reports: not refetched.
        c.put_vuln(&json!({"id": "GHSA-old", "modified": "2026-01-01T00:00:00Z", "affected": []})).unwrap();
        let fetched = Arc::new(Mutex::new(Vec::new()));
        let batches = Arc::new(AtomicUsize::new(0));
        let (f, b) = (fetched.clone(), batches.clone());
        let net = Fake::new(move |r| {
            let body: Value = r.body.as_ref().map(|b| serde_json::from_slice(b).unwrap()).unwrap_or(Value::Null);
            if r.url.ends_with("/querybatch") {
                b.fetch_add(1, Ordering::SeqCst);
                let qs = body["queries"].as_array().unwrap();
                let results: Vec<Value> = qs
                    .iter()
                    .map(|q| match q["package"]["name"].as_str().unwrap() {
                        "vite" => json!({"vulns": [{"id": "GHSA-new", "modified": "2026-10-01T00:00:00Z"},
                                                   {"id": "GHSA-old", "modified": "2026-01-01T00:00:00Z"}],
                                         "next_page_token": "p2"}),
                        _ => json!({}),
                    })
                    .collect();
                return Ok(Response::ok(json!({"results": results}).to_string()));
            }
            if r.url.ends_with("/v1/query") {
                assert_eq!(body["page_token"], "p2");
                return Ok(Response::ok(
                    json!({"vulns": [{"id": "MAL-1", "modified": "2026-10-02T00:00:00Z"}]}).to_string(),
                ));
            }
            let id = r.url.rsplit('/').next().unwrap().to_string();
            f.lock().unwrap().push(id.clone());
            Ok(Response {
                status: 200,
                body: json!({"id": id, "modified": "x", "affected": []}).to_string().into_bytes(),
                etag: Some(format!("\"{id}\"")),
            })
        });
        let mut items: Vec<Item> = (0..1500).map(|i| item("npm", &format!("pkg{i}"), "1.0.0")).collect();
        items.push(item("npm", "vite", "8.0.0"));
        let got = lookup(&c, &net, &items, false, false, &|_| {}).unwrap();
        assert_eq!(batches.load(Ordering::SeqCst), 2, "1501 queries take two batches");
        let mut ids: Vec<&str> = got[&item("npm", "vite", "8.0.0")].iter().map(|r| r["id"].as_str().unwrap()).collect();
        ids.sort();
        assert_eq!(ids, ["GHSA-new", "GHSA-old", "MAL-1"]);
        let mut f = fetched.lock().unwrap().clone();
        f.sort();
        assert_eq!(f, ["GHSA-new", "MAL-1"]);
        assert_eq!(c.get("vuln_etag:GHSA-new").unwrap().as_deref(), Some("\"GHSA-new\""));
        assert!(got[&item("npm", "pkg7", "1.0.0")].is_empty(), "answered clean");
        // A second lookup the same day asks nothing.
        let quiet = Fake::new(|_| panic!("fresh answers are not refetched"));
        assert_eq!(lookup(&c, &quiet, &items, false, false, &|_| {}).unwrap().len(), items.len());
    }

    #[test]
    fn unreachable_osv_leaves_items_unanswered() {
        let (_d, c) = cache();
        let logged = Mutex::new(Vec::new());
        let got = lookup(&c, &Fake::offline(), &[item("npm", "a", "1")], false, false, &|m| {
            logged.lock().unwrap().push(m.to_string())
        })
        .unwrap();
        assert!(got.is_empty());
        assert!(logged.lock().unwrap()[0].contains("OSV unreachable"));
    }
}
