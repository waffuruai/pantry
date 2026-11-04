//! Indicators of compromise beside the YARA rules, and verification of a
//! flagged file by its hash against open malware databases.
//!
//! Offline, refreshed daily into the rules directory: signature-base's hash,
//! filename and C2 lists (Florian Roth, Detection Rule License 1.1) and
//! abuse.ch Feodo Tracker's botnet C2 addresses (CC0). Hashes and filenames
//! are checked per file; C2 hosts become a YARA rule, so a config or script
//! naming one is found like any other string.
//!
//! Online, and only for files a rule or list already flagged, and only after
//! the user said yes once: the file's SHA-256, never the file, goes to
//! YARAify (CC0, no key), CIRCL hashlookup (known-good software, no key) and,
//! with the user's own `ABUSECH_AUTH_KEY`, MalwareBazaar.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::json;
use crate::net::{self, Net};
use std::collections::HashMap;
use std::path::Path;
use wpantry_yara::pattern::{Node, Syntax, parse_regex};

pub const SIGNATURE_BASE: &str = "https://api.github.com/repos/Neo23x0/signature-base/contents/iocs/";
const SIGNATURE_BASE_FILES: &[&str] = &["hash-iocs.txt", "filename-iocs.txt", "c2-iocs.txt"];
pub const FEODO: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";
pub const YARAIFY: &str = "https://yaraify-api.abuse.ch/api/v1/";
pub const CIRCL: &str = "https://hashlookup.circl.lu/lookup/sha256/";
pub const MALWAREBAZAAR: &str = "https://mb-api.abuse.ch/api/v1/";
const MAX_AGE: f64 = 86_400.0;
/// A filename indicator scored at least this names malware outright.
const MALWARE_SCORE: i64 = 80;

/// Fetch the lists into `dir` when older than a day (or `refresh`); each
/// source that fails is returned with its error, the rest still update.
pub fn update(cache: &Cache, net: &dyn Net, dir: &Path, refresh: bool) -> Vec<(&'static str, Error)> {
    let mut failed = Vec::new();
    if let Err(e) = std::fs::create_dir_all(dir) {
        failed.push(("IOC lists", e.into()));
        return failed;
    }
    let fresh = |key: &str, file: &Path| !refresh && file.is_file() && cache.fresh(key, MAX_AGE).unwrap_or(false);
    let headers = net::github_headers();
    let mut h: Vec<(&str, &str)> =
        headers.iter().filter(|(k, _)| k != "Accept").map(|(k, v)| (k.as_str(), v.as_str())).collect();
    h.push(("Accept", "application/vnd.github.raw"));
    for name in SIGNATURE_BASE_FILES {
        let file = dir.join(name);
        let key = format!("iocs:{name}");
        if fresh(&key, &file) {
            continue;
        }
        match net::request(net, &format!("{SIGNATURE_BASE}{name}"), None, &h, None) {
            Ok(r) if r.status == 200 => {
                if let Err(e) = std::fs::write(&file, &r.body).map_err(Error::from).and_then(|_| cache.touch(&key)) {
                    failed.push(("signature-base IOCs", e));
                }
            }
            Ok(r) => failed.push(("signature-base IOCs", Error::Offline(format!("{name}: HTTP {}", r.status)))),
            Err(e) => failed.push(("signature-base IOCs", e)),
        }
    }
    let feodo = dir.join("feodo-ipblocklist.json");
    if !fresh("iocs:feodo", &feodo) {
        match net::request(net, FEODO, None, &[], None) {
            Ok(r) if r.status == 200 => {
                if let Err(e) =
                    std::fs::write(&feodo, &r.body).map_err(Error::from).and_then(|_| cache.touch("iocs:feodo"))
                {
                    failed.push(("Feodo Tracker", e));
                }
            }
            Ok(r) => failed.push(("Feodo Tracker", Error::Offline(format!("HTTP {}", r.status)))),
            Err(e) => failed.push(("Feodo Tracker", e)),
        }
    }
    let _ = cache.commit();
    failed
}

/// The lists, loaded.
#[derive(Default)]
pub struct Iocs {
    /// Lowercase hex (MD5, SHA-1 or SHA-256) to what it is.
    pub hashes: HashMap<String, String>,
    /// Path regexes with their score.
    pub filenames: Vec<(Node, i64, String)>,
    /// C2 hosts and addresses, with where each came from.
    pub c2: Vec<(String, &'static str)>,
}

/// Lines that aren't blank or comments.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'))
}

pub fn load(dir: &Path) -> Iocs {
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    let mut iocs = Iocs::default();
    for line in lines(&read("hash-iocs.txt")) {
        let (hash, what) = line.split_once(';').unwrap_or((line, ""));
        let hash = hash.trim().to_ascii_lowercase();
        if matches!(hash.len(), 32 | 40 | 64) && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            iocs.hashes.insert(hash, what.trim().to_string());
        }
    }
    for line in lines(&read("filename-iocs.txt")) {
        let Some((re, score)) = line.rsplit_once(';') else { continue };
        let Ok(score) = score.trim().parse::<i64>() else { continue };
        let (re, nocase) = match re.strip_prefix("(?i)") {
            Some(r) => (r, true),
            None => (re, false),
        };
        if let Ok(node) = parse_regex(re.as_bytes(), nocase, false, Syntax::Relaxed, 0) {
            iocs.filenames.push((node, score, re.to_string()));
        }
    }
    for line in lines(&read("c2-iocs.txt")) {
        let host = line.split(';').next().unwrap_or(line).trim();
        if host.len() >= 6 && host.contains('.') && !host.contains(char::is_whitespace) {
            iocs.c2.push((host.to_ascii_lowercase(), "signature-base"));
        }
    }
    if let Ok(v) = json::parse(read("feodo-ipblocklist.json").as_bytes(), json::MAX_DOCUMENT)
        && let Some(entries) = v.as_array()
    {
        for e in entries {
            if let Some(ip) = e.get("ip_address").and_then(|i| i.as_str()) {
                iocs.c2.push((ip.to_string(), "Feodo Tracker"));
            }
        }
    }
    iocs.c2.sort();
    iocs.c2.dedup_by(|a, b| a.0 == b.0);
    iocs
}

impl Iocs {
    /// The C2 hosts as one YARA rule per source: any of them, as a whole
    /// word, in ASCII or UTF-16.
    pub fn c2_rules(&self) -> String {
        let mut out = String::new();
        for (source, rule) in
            [("signature-base", "IOC_C2_Host_SignatureBase"), ("Feodo Tracker", "IOC_C2_Host_FeodoTracker")]
        {
            let hosts: Vec<&str> = self.c2.iter().filter(|(_, s)| *s == source).map(|(h, _)| h.as_str()).collect();
            if hosts.is_empty() {
                continue;
            }
            out.push_str(&format!(
                "rule {rule}\n{{\n    meta:\n        description = \"names a known command-and-control host ({source})\"\n        category = \"suspicious\"\n        score = 70\n        os = \"any\"\n    strings:\n"
            ));
            for (i, h) in hosts.iter().enumerate() {
                let escaped: String = h.chars().filter(|c| c.is_ascii_graphic() && *c != '"' && *c != '\\').collect();
                out.push_str(&format!("        $c{i} = \"{escaped}\" ascii wide fullword\n"));
            }
            out.push_str("    condition:\n        any of them\n}\n");
        }
        out
    }

    /// What the file's hashes match, if anything.
    pub fn hash_match(&self, data: &[u8]) -> Option<&str> {
        if self.hashes.is_empty() {
            return None;
        }
        let lengths: Vec<usize> = self.hashes.keys().map(String::len).collect();
        let mut digests = vec![crate::sha256::hex(data)];
        if lengths.contains(&32) {
            digests.push(wpantry_yara::modules::hex(&wpantry_yara::modules::hash::md5(data)));
        }
        if lengths.contains(&40) {
            digests.push(wpantry_yara::modules::hex(&wpantry_yara::modules::hash::sha1(data)));
        }
        digests.iter().find_map(|d| self.hashes.get(d).map(String::as_str))
    }

    /// The highest-scoring filename indicator the path matches.
    pub fn filename_match(&self, path: &Path) -> Option<(i64, &str)> {
        let p = path.to_string_lossy();
        self.filenames
            .iter()
            .filter(|(node, _, _)| wpantry_yara::matcher::search(node, p.as_bytes()))
            .map(|(_, score, re)| (*score, re.as_str()))
            .max_by_key(|(score, _)| *score)
    }
}

/// The category a filename indicator's score means.
pub fn filename_category(score: i64) -> &'static str {
    if score >= MALWARE_SCORE { "malware" } else { "suspicious" }
}

// --------------------------------------------------------------- online

/// Whether the user lets flagged files' hashes be looked up: decided once,
/// asked when someone can be asked, kept in the cache.
pub fn consent(cache: &Cache, ask: Option<crate::breach::Ask>, flagged: usize) -> Result<Option<bool>> {
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
        let mut s: Vec<Source> =
            vec![("YARAify", Box::new(|| yaraify(net, sha256))), ("CIRCL hashlookup", Box::new(|| circl(net, sha256)))];
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
                    rusqlite::params![sha256, source, verdict, family, crate::system::now()],
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
    let now = crate::system::now();
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
fn yaraify(net: &dyn Net, sha256: &str) -> Result<Verdict> {
    let resp = net::post_json(net, YARAIFY, &serde_json::json!({"query": "lookup_hash", "search_term": sha256}))?;
    match resp.get("query_status").and_then(|s| s.as_str()) {
        Some("ok") => Ok(match clamav_names(&resp).into_iter().find(|n| names_malware(n)) {
            Some(sig) => Verdict::Malware(sig),
            None => Verdict::Unknown,
        }),
        Some("no_results") | Some("hash_not_found") => Ok(Verdict::Unknown),
        other => Err(Error::Invalid(format!("YARAify: {}", other.unwrap_or("no status")))),
    }
}

fn circl(net: &dyn Net, sha256: &str) -> Result<Verdict> {
    let resp = net::request(net, &format!("{CIRCL}{sha256}"), None, &[], None)?;
    Ok(if resp.status == 200 { Verdict::KnownGood } else { Verdict::Unknown })
}

fn malwarebazaar(net: &dyn Net, sha256: &str, key: &str) -> Result<Verdict> {
    // A form post with the key in its own header, as abuse.ch's API takes it.
    let req = net::Request {
        method: "POST",
        url: MALWAREBAZAAR.into(),
        headers: vec![
            ("User-Agent".into(), net::USER_AGENT.into()),
            ("Content-Type".into(), "application/x-www-form-urlencoded".into()),
            ("Auth-Key".into(), key.into()),
        ],
        body: Some(format!("query=get_info&hash={sha256}").into_bytes()),
    };
    let r = net.send(&req)?;
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
mod tests;
