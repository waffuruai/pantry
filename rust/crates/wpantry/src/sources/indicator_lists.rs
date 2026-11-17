//! Indicator lists, refreshed daily into the rules directory:
//! signature-base's hash, filename and C2 lists (Florian Roth, Detection
//! Rule License 1.1) and abuse.ch Feodo Tracker's botnet C2 addresses (CC0),
//! beside the user's own lists ([`crate::sources::user`]).
//!
//! The hashes, hosts, addresses and URLs go into the indicator store
//! ([`crate::sources::indicator_store`]) and are matched by lookup; the
//! file-name patterns stay regexes, matched against each path.

use crate::db::Cache;
use crate::error::Error;
use crate::sources::fetch;
use crate::sources::file::source;
use crate::sources::file::url;
use crate::sources::indicator_store::Store;
use crate::utils::json;
use crate::utils::net::{self, Net};
use std::path::{Path, PathBuf};
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

/// The file-name indicators: path regexes, each with its score.
#[derive(Default)]
pub struct Iocs {
    pub filenames: Vec<(Node, i64, String)>,
}

/// Whether a user's source is used this run, by its id.
pub type Active<'a> = &'a dyn Fn(&str) -> bool;

/// The most a user's list may hold once inflated (a gzip bomb guard).
const MAX_LIST: usize = 1 << 30;

/// Lines that aren't blank or comments.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// The user's lists in `dir` (`user-<id>.<kind>.txt`, [`crate::sources::user`])
/// that `active` says are used this run: `(path, id, kind)`, by name.
fn user_lists(dir: &Path, active: Active) -> Vec<(PathBuf, String, String)> {
    let mut found: Vec<(PathBuf, String, String)> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.path()).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| {
            let name = p.file_name()?.to_string_lossy().into_owned();
            let (id, kind) = name.strip_prefix("user-")?.strip_suffix(".txt")?.rsplit_once('.')?;
            Some((p.clone(), id.to_string(), kind.to_string()))
        })
        .filter(|(_, id, _)| active(id))
        .collect();
    found.sort();
    found
}

/// A user's list as text: gzip is inflated.
fn user_text(path: &Path) -> String {
    let bytes = crate::utils::files::read_capped_bytes(path, json::MAX_DOCUMENT as u64).unwrap_or_default();
    let bytes = if crate::utils::archive::gzip::is_gzip(&bytes) {
        crate::utils::archive::gzip::gunzip(&bytes, MAX_LIST).unwrap_or_default()
    } else {
        bytes
    };
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The files the file-name indicators come from, for the rules' digest.
pub fn filename_files(dir: &Path, active: Active) -> Vec<PathBuf> {
    std::iter::once(dir.join("filename-iocs.txt"))
        .chain(user_lists(dir, active).into_iter().filter(|(_, _, k)| k == "filenames").map(|(p, _, _)| p))
        .collect()
}

/// The file-name indicators in `dir`: signature-base's and the user's.
pub fn load(dir: &Path, active: Active) -> Iocs {
    let mut iocs = Iocs::default();
    for p in filename_files(dir, active) {
        filenames(&mut iocs, &std::fs::read_to_string(p).unwrap_or_default());
    }
    iocs
}

/// A rule name's part from a source's id.
fn rule_part(id: &str) -> String {
    id.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect()
}

/// Where the built store is kept, beside the lists it was built from.
const STORE_FILE: &str = "store.bin";

/// Every hash, host, address and URL in `dir`'s lists, ours first, then the
/// user's in name order: read from the store built last time while the
/// lists (their names, sizes and times) and this code are the same, built
/// and kept otherwise.
pub fn store(dir: &Path, active: Active) -> Store {
    let mut inputs: Vec<PathBuf> =
        ["hash-iocs.txt", "c2-iocs.txt", "feodo-ipblocklist.json"].iter().map(|n| dir.join(n)).collect();
    inputs.extend(user_lists(dir, active).into_iter().filter(|(_, _, k)| k != "filenames").map(|(p, _, _)| p));
    let mut digest = crate::utils::sha256::Sha256::new();
    digest.update(crate::VERSION.as_bytes());
    digest.update(include_str!("indicator_lists.rs").as_bytes());
    digest.update(include_str!("indicator_store.rs").as_bytes());
    for p in &inputs {
        let meta = std::fs::metadata(p).ok();
        let when =
            meta.as_ref().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
        digest.update(
            format!("{}\t{:?}\t{:?}\n", p.display(), meta.map(|m| m.len()), when.map(|d| d.as_nanos())).as_bytes(),
        );
    }
    let digest = digest.hex();
    let kept = dir.join(STORE_FILE);
    if let Some(s) = Store::load(&kept, &digest) {
        return s;
    }
    let s = build(dir, active);
    if dir.is_dir() {
        let _ = s.save(&kept, &digest);
    }
    s
}

fn build(dir: &Path, active: Active) -> Store {
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    let mut store = Store::new();
    let o = store.origin("Hash_IOC_SignatureBase", "signature-base");
    hashes(&mut store, &read("hash-iocs.txt"), o);
    let o = store.origin("IOC_C2_Host_SignatureBase", "signature-base");
    hosts(&mut store, &read("c2-iocs.txt"), o);
    let o = store.origin("IOC_C2_Host_FeodoTracker", "Feodo Tracker");
    if let Ok(v) = json::parse(read("feodo-ipblocklist.json").as_bytes(), json::MAX_DOCUMENT)
        && let Some(entries) = v.as_array()
    {
        for e in entries {
            if let Some(ip) = e.get("ip_address").and_then(|i| i.as_str()) {
                let family = e.get("malware").and_then(|m| m.as_str()).unwrap_or_default();
                let what = if family.is_empty() { String::new() } else { format!("{family} command-and-control") };
                store.add(ip, &what, o);
            }
        }
    }
    for (path, id, kind) in user_lists(dir, active) {
        let text = user_text(&path);
        let part = rule_part(&id);
        match kind.as_str() {
            "hashes" => {
                let o = store.origin(&format!("Hash_IOC_User_{part}"), &id);
                hashes(&mut store, &text, o);
            }
            "hosts" => {
                let o = store.origin(&format!("IOC_C2_Host_User_{part}"), &id);
                hosts(&mut store, &text, o);
            }
            "indicators" => {
                let o = store.origin(&format!("IOC_Host_User_{part}"), &id);
                maltrail(&mut store, &text, o);
            }
            _ => {}
        }
    }
    store.seal();
    store
}

/// `hash[;what]` lines: MD5, SHA-1 or SHA-256.
fn hashes(store: &mut Store, text: &str, origin: u32) {
    for line in lines(text) {
        let (hash, what) = line.split_once(';').unwrap_or((line, ""));
        if crate::sources::indicator_store::is_hash(hash.trim()) {
            store.add(hash, what.trim(), origin);
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

/// `host[;...]` lines: command-and-control hosts, addresses and URLs.
fn hosts(store: &mut Store, text: &str, origin: u32) {
    for line in lines(text) {
        let host = line.split(';').next().unwrap_or(line).trim();
        if !crate::sources::indicator_store::is_hash(host) {
            store.add(host, "", origin);
        }
    }
}

/// Maltrail's trails (`trails.csv`): `value,what,reference` lines, each a
/// domain, address or URL and the family it belongs to.
fn maltrail(store: &mut Store, text: &str, origin: u32) {
    for line in lines(text) {
        let mut fields = line.splitn(3, ',');
        let value = fields.next().unwrap_or_default().trim_matches('"');
        let what = fields.next().unwrap_or_default().trim().trim_matches('"');
        if !crate::sources::indicator_store::is_hash(value) {
            store.add(value, what, origin);
        }
    }
}
