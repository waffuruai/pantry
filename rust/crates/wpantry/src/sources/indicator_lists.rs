//! Indicator lists, refreshed daily into the rules directory:
//! signature-base's hash, filename and C2 lists (Florian Roth, Detection
//! Rule License 1.1) and abuse.ch Feodo Tracker's botnet C2 addresses (CC0).

use crate::db::Cache;
use crate::error::Error;
use crate::sources::fetch;
use crate::sources::file::source;
use crate::sources::file::url;
use crate::utils::json;
use crate::utils::net::{self, Net};
use std::collections::HashMap;
use std::path::Path;
use wpantry_yara::pattern::{Node, Syntax, parse_regex};

const SIGNATURE_BASE_FILES: &[&str] = &["hash-iocs.txt", "filename-iocs.txt", "c2-iocs.txt"];
pub(crate) const MAX_AGE: f64 = 86_400.0;

/// Fetch the lists into `dir` when older than a day (or `refresh`); each
/// source that fails is returned with its error, the rest still update.
pub fn update(cache: &Cache, net: &dyn Net, dir: &Path, refresh: bool) -> Vec<(&'static str, Error)> {
    let mut failed = Vec::new();
    if let Err(e) = std::fs::create_dir_all(dir) {
        failed.push(("IOC lists", e.into()));
        return failed;
    }
    let fresh = |key: &str, file: &Path| {
        !refresh
            && file.is_file()
            && cache
                .fresh(key, source(if key == "iocs:feodo" { "feodo" } else { "signature-base" }).refresh)
                .unwrap_or(false)
    };
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
        match fetch::request(net, "signature-base", &format!("{}{name}", url("signature-base")), None, &h, None) {
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
        match fetch::request(net, "feodo", url("feodo"), None, &[], None) {
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
    pub c2: Vec<(String, String)>,
}

/// Lines that aren't blank or comments.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// The lists in `dir`: signature-base's, Feodo's, and the user's own
/// (`user-<id>.<kind>.txt`, [`crate::sources::user`]).
pub fn load(dir: &Path) -> Iocs {
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    let mut iocs = Iocs::default();
    hashes(&mut iocs, &read("hash-iocs.txt"), "");
    filenames(&mut iocs, &read("filename-iocs.txt"));
    hosts(&mut iocs, &read("c2-iocs.txt"), "signature-base");
    if let Ok(v) = json::parse(read("feodo-ipblocklist.json").as_bytes(), json::MAX_DOCUMENT)
        && let Some(entries) = v.as_array()
    {
        for e in entries {
            if let Some(ip) = e.get("ip_address").and_then(|i| i.as_str()) {
                iocs.c2.push((ip.to_string(), "Feodo Tracker".into()));
            }
        }
    }
    let mut users: Vec<std::path::PathBuf> =
        std::fs::read_dir(dir).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default();
    users.sort();
    for p in users {
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let Some(rest) = name.strip_prefix("user-").and_then(|r| r.strip_suffix(".txt")) else { continue };
        let Some((id, kind)) = rest.rsplit_once('.') else { continue };
        let text = crate::utils::files::read_capped(&p, json::MAX_DOCUMENT as u64).unwrap_or_default();
        match kind {
            "hashes" => hashes(&mut iocs, &text, id),
            "filenames" => filenames(&mut iocs, &text),
            "hosts" => hosts(&mut iocs, &text, id),
            _ => {}
        }
    }
    iocs.c2.sort();
    iocs.c2.dedup_by(|a, b| a.0 == b.0);
    iocs
}

/// `hash[;what]` lines: MD5, SHA-1 or SHA-256; `source` names a user's list.
fn hashes(iocs: &mut Iocs, text: &str, source: &str) {
    for line in lines(text) {
        let (hash, what) = line.split_once(';').unwrap_or((line, ""));
        let hash = hash.trim().to_ascii_lowercase();
        if matches!(hash.len(), 32 | 40 | 64) && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            let what = match (what.trim(), source) {
                (w, "") => w.to_string(),
                ("", s) => s.to_string(),
                (w, s) => format!("{w} ({s})"),
            };
            iocs.hashes.insert(hash, what);
        }
    }
}

/// `regex;score` lines: path patterns malware uses.
fn filenames(iocs: &mut Iocs, text: &str) {
    for line in lines(text) {
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
}

/// `host[;...]` lines: command-and-control hosts and addresses.
fn hosts(iocs: &mut Iocs, text: &str, source: &str) {
    for line in lines(text) {
        let host = line.split(';').next().unwrap_or(line).trim();
        if host.len() >= 6 && host.contains('.') && !host.contains(char::is_whitespace) {
            iocs.c2.push((host.to_ascii_lowercase(), source.to_string()));
        }
    }
}
