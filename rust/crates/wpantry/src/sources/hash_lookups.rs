//! Hash lookups for a flagged file, only after the user said yes once: the
//! file's SHA-256, never the file, goes to YARAify (CC0, no key), url("circl-hashlookup")
//! hashlookup (known-good software, no key) and, with the user's own
//! `ABUSECH_AUTH_KEY`, MalwareBazaar. Answers are cached a day.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::sources::fetch;
use crate::sources::file::url;
use crate::sources::indicator_lists::MAX_AGE;
use crate::utils::json;
use crate::utils::net::{self, Net};

/// Whether the user lets flagged files' hashes be looked up: decided once,
/// asked when someone can be asked, kept in the cache.
pub fn consent(cache: &Cache, ask: Option<crate::checks::email::Ask>, flagged: usize) -> Result<Option<bool>> {
    match cache.get("online_hash_consent")?.as_deref() {
        Some("yes") => return Ok(Some(true)),
        Some("no") => return Ok(Some(false)),
        _ => {}
    }
    let Some(ask) = ask else { return Ok(None) };
    let mal = if std::env::var("ABUSECH_AUTH_KEY").is_ok_and(|k| !k.is_empty()) { " and MalwareBazaar" } else { "" };
    let Some(yes) = ask(&format!(
        "Look up the SHA-256 of {flagged} flagged file(s) at YARAify and CIRCL hashlookup{mal}? Only the hash is sent, never the file."
    )) else {
        return Ok(None);
    };
    cache.set("online_hash_consent", if yes { "yes" } else { "no" })?;
    cache.commit()?;
    Ok(Some(yes))
}

pub const VERDICT_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS hash_verdict (
  sha256 TEXT, source TEXT, verdict TEXT, family TEXT, checked_at REAL,
  PRIMARY KEY (sha256, source));
";

/// Each source's verdict, and each source that couldn't be asked with why.
pub type Verdicts = Vec<(&'static str, Verdict)>;
pub type Failures = Vec<(&'static str, String)>;

/// A source to ask: its name and the question.
type Source<'a> = (&'static str, Box<dyn Fn() -> Result<Verdict> + 'a>);

/// A user lookup's id as the report names it: each allocated once.
fn label(id: &str) -> &'static str {
    static SEEN: std::sync::LazyLock<std::sync::Mutex<Vec<&'static str>>> = std::sync::LazyLock::new(Default::default);
    let mut seen = SEEN.lock().expect("lock");
    if let Some(s) = seen.iter().find(|s| **s == id) {
        return s;
    }
    let s: &'static str = Box::leak(id.to_string().into_boxed_str());
    seen.push(s);
    s
}

/// What a database said about a hash.
#[derive(Clone, Debug, PartialEq)]
pub enum Verdict {
    /// Known malware, with its family when the source names one.
    Malware(String),
    /// Known, ordinary software.
    KnownGood,
    Unknown,
}

/// Ask every source (cached a day) about `sha256`: `(source, verdict)`; a
/// source that can't be reached is left out and returned as failed.
pub fn verify(cache: &Cache, net: &dyn Net, sha256: &str) -> (Verdicts, Failures) {
    let mut out = Vec::new();
    let mut failed = Vec::new();
    let key = std::env::var("ABUSECH_AUTH_KEY").ok().filter(|k| !k.is_empty());
    let sources: Vec<Source> = {
        let mut s: Vec<Source> = vec![
            ("YARAify", Box::new(|| yaraify(net, "yaraify", url("yaraify"), sha256))),
            ("CIRCL hashlookup", Box::new(|| circl(net, "circl-hashlookup", url("circl-hashlookup"), sha256))),
        ];
        // The user's own lookups, each said yes to ([`crate::sources::user`]).
        let effective = crate::sources::file::effective();
        for u in effective.sources.iter().filter(|u| u.kind == "hash-lookup" && effective.user.contains(&u.id)) {
            if !crate::sources::file::active(&u.id) {
                continue;
            }
            let (id, at) = (u.id.clone(), u.url.clone());
            let name = label(&u.id);
            if u.format == "yaraify" {
                s.push((name, Box::new(move || yaraify(net, &id, &at, sha256))));
            } else {
                s.push((name, Box::new(move || circl(net, &id, &at, sha256))));
            }
        }
        if let Some(k) = key.clone() {
            s.push(("MalwareBazaar", Box::new(move || malwarebazaar(net, sha256, &k))));
        }
        s
    };
    for (source, ask) in sources {
        if let Some(v) = cached(cache, sha256, source) {
            out.push((source, v));
            continue;
        }
        match ask() {
            Ok(v) => {
                let (verdict, family) = match &v {
                    Verdict::Malware(f) => ("malware", f.as_str()),
                    Verdict::KnownGood => ("good", ""),
                    Verdict::Unknown => ("unknown", ""),
                };
                let _ = cache.conn.execute(
                    "INSERT OR REPLACE INTO hash_verdict VALUES (?, ?, ?, ?, ?)",
                    rusqlite::params![sha256, source, verdict, family, crate::utils::os::now()],
                );
                out.push((source, v));
            }
            Err(e) => failed.push((source, e.to_string())),
        }
    }
    let _ = cache.commit();
    (out, failed)
}

fn cached(cache: &Cache, sha256: &str, source: &str) -> Option<Verdict> {
    let (verdict, family, at): (String, String, f64) = cache
        .conn
        .query_row(
            "SELECT verdict, family, checked_at FROM hash_verdict WHERE sha256=? AND source=?",
            [sha256, source],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok()?;
    let now = crate::utils::os::now();
    if at < now - MAX_AGE || at > now + crate::db::CLOCK_SKEW {
        return None;
    }
    Some(match verdict.as_str() {
        "malware" => Verdict::Malware(family),
        "good" => Verdict::KnownGood,
        _ => Verdict::Unknown,
    })
}

/// The ClamAV signatures YARAify's analyses of a file found, in order.
fn clamav_names(v: &serde_json::Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let tasks = v.get("data").and_then(|d| d.get("tasks")).and_then(|t| t.as_array()).cloned().unwrap_or_default();
    for t in &tasks {
        for name in t.get("clamav_results").and_then(|c| c.as_array()).into_iter().flatten().filter_map(|n| n.as_str())
        {
            if !out.iter().any(|o| o == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// Whether a ClamAV signature names malware, not a hacking tool, an
/// unwanted program or a vulnerable (but legitimate) driver.
fn names_malware(sig: &str) -> bool {
    let s = sig.to_ascii_lowercase();
    !["pua", "hacktool", "vulndriver", "riskware", "adware", "tool.", "heuristics.", "unofficial"]
        .iter()
        .any(|w| s.contains(w))
}

/// YARAify knows a file once anyone submitted it, so being known says
/// nothing; the ClamAV signatures its analysis found are the verdict.
/// YARAify's answer, or an API of the user's in its format (`id` at `url`).
fn yaraify(net: &dyn Net, id: &str, url: &str, sha256: &str) -> Result<Verdict> {
    let resp = fetch::post_json(net, id, url, &serde_json::json!({"query": "lookup_hash", "search_term": sha256}))?;
    match resp.get("query_status").and_then(|s| s.as_str()) {
        Some("ok") => Ok(match clamav_names(&resp).into_iter().find(|n| names_malware(n)) {
            Some(sig) => Verdict::Malware(sig),
            None => Verdict::Unknown,
        }),
        Some("no_results") | Some("hash_not_found") => Ok(Verdict::Unknown),
        other => Err(Error::Invalid(format!("YARAify: {}", other.unwrap_or("no status")))),
    }
}

/// CIRCL hashlookup's answer, or an API of the user's in its format.
fn circl(net: &dyn Net, id: &str, url: &str, sha256: &str) -> Result<Verdict> {
    let resp = fetch::request(net, id, &format!("{url}{sha256}"), None, &[], None)?;
    Ok(if resp.status == 200 { Verdict::KnownGood } else { Verdict::Unknown })
}

fn malwarebazaar(net: &dyn Net, sha256: &str, key: &str) -> Result<Verdict> {
    // A form post with the key in its own header, as abuse.ch's API takes it.
    let req = net::Request {
        method: "POST",
        url: url("malwarebazaar").into(),
        headers: vec![
            ("User-Agent".into(), net::USER_AGENT.into()),
            ("Content-Type".into(), "application/x-www-form-urlencoded".into()),
            ("Auth-Key".into(), key.into()),
        ],
        body: Some(format!("query=get_info&hash={sha256}").into_bytes()),
        limit: crate::sources::file::source("malwarebazaar").max_bytes,
    };
    let r = net.send(&req);
    fetch::note("malwarebazaar", &r);
    let r = r?;
    if !(200..300).contains(&r.status) {
        return Err(Error::Offline(format!("MalwareBazaar: HTTP {}", r.status)));
    }
    let resp = json::parse(&r.body, json::MAX_DOCUMENT)?;
    match resp.get("query_status").and_then(|s| s.as_str()) {
        Some("ok") => {
            let family = resp
                .get("data")
                .and_then(|d| d.as_array())
                .and_then(|d| d.first())
                .and_then(|d| d.get("signature"))
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Verdict::Malware(family))
        }
        Some("hash_not_found") | Some("no_results") => Ok(Verdict::Unknown),
        other => Err(Error::Invalid(format!("MalwareBazaar: {}", other.unwrap_or("no status")))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::testing::cache_in;
    use crate::utils::net::{Fake, Response};
    use crate::utils::temp::TempDir;

    #[test]
    fn lookups_ask_once_cache_a_day_and_read_each_source() {
        let d = TempDir::new("iocs").unwrap();
        let cache = cache_in(&d);
        assert_eq!(consent(&cache, None, 2).unwrap(), None, "undecided, nobody to ask");
        assert_eq!(consent(&cache, Some(&|q| Some(q.contains("Only the hash is sent"))), 2).unwrap(), Some(true));
        assert_eq!(consent(&cache, Some(&|_| panic!("asked once")), 2).unwrap(), Some(true));
        let net = Fake::new(|r| {
            if r.url == url("yaraify") {
                let body: serde_json::Value = serde_json::from_slice(r.body.as_ref().unwrap()).unwrap();
                return Ok(Response::ok(match body["search_term"].as_str() {
                    Some("aa") => {
                        r#"{"query_status": "ok", "data": {"tasks": [{"clamav_results": ["Win.Coinminer.Generic-1", "Win.Coinminer.Generic-1"], "static_results": [{"rule_name": "DebuggerCheck"}]}]}}"#
                    }
                    // Known to YARAify, but only as a vulnerable driver: no verdict.
                    Some("dd") => {
                        r#"{"query_status": "ok", "data": {"tasks": [{"clamav_results": ["SecuriteInfo.com.HackTool.VulnDriver.x64"]}, {"clamav_results": []}]}}"#
                    }
                    _ => r#"{"query_status": "no_results"}"#,
                }));
            }
            if r.url == format!("{}bb", url("circl-hashlookup")) {
                return Ok(Response::ok(r#"{"FileName": "ls"}"#));
            }
            Ok(Response { status: 404, body: br#"{"message": "Non existing SHA-256"}"#.to_vec(), etag: None })
        });
        let (v, failed) = verify(&cache, &net, "aa");
        assert!(failed.is_empty());
        assert_eq!(
            v,
            [("YARAify", Verdict::Malware("Win.Coinminer.Generic-1".into())), ("CIRCL hashlookup", Verdict::Unknown)]
        );
        let (v, _) = verify(&cache, &net, "dd");
        assert_eq!(v[0], ("YARAify", Verdict::Unknown), "a hacking tool's signature isn't a malware verdict");
        let (v, _) = verify(&cache, &net, "bb");
        assert_eq!(v, [("YARAify", Verdict::Unknown), ("CIRCL hashlookup", Verdict::KnownGood)]);
        let asked = net.requests().len();
        verify(&cache, &net, "aa");
        assert_eq!(net.requests().len(), asked, "answers are cached a day");
        let down = Fake::offline();
        let (v, failed) = verify(&cache, &down, "cc");
        assert!(v.is_empty());
        assert_eq!(failed.len(), 2);
        cache.set("online_hash_consent", "no").unwrap();
        assert_eq!(consent(&cache, Some(&|_| panic!("decided")), 1).unwrap(), Some(false));
    }

    #[test]
    fn malwarebazaar_needs_the_users_key() {
        let net = Fake::new(|r| {
            assert_eq!(r.header("auth-key"), Some("k"));
            assert_eq!(r.body.as_deref(), Some(&b"query=get_info&hash=aa"[..]));
            Ok(Response::ok(r#"{"query_status": "ok", "data": [{"signature": "XMRig"}]}"#))
        });
        assert_eq!(malwarebazaar(&net, "aa", "k").unwrap(), Verdict::Malware("XMRig".into()));
        let missing = Fake::new(|_| Ok(Response::ok(r#"{"query_status": "hash_not_found"}"#)));
        assert_eq!(malwarebazaar(&missing, "aa", "k").unwrap(), Verdict::Unknown);
        let refused = Fake::new(|_| Ok(Response { status: 401, body: vec![], etag: None }));
        assert!(malwarebazaar(&refused, "aa", "k").is_err());
        let odd = Fake::new(|_| Ok(Response::ok(r#"{"query_status": "illegal_hash"}"#)));
        assert!(malwarebazaar(&odd, "aa", "k").is_err());
        let odd = Fake::new(|_| Ok(Response::ok(r#"{"query_status": "unknown_auth_key"}"#)));
        assert!(yaraify(&odd, "yaraify", url("yaraify"), "aa").is_err());
    }
}
