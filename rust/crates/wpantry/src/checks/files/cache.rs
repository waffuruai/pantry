//! The files pass's cache: each check's result for each file, kept while
//! the file is unchanged (its device, inode, size and modification time)
//! and the check's code is the same, so a scan reads only what changed.
//!
//! One record per root, read in one query and written back only when it
//! changed: the files by folder, each with a fingerprint of its identity
//! and each check's result under it. A repo of a hundred thousand files is
//! a few megabytes, not a row per file and check.

use super::pass::{Check, Job, Out};
use super::{Read, Stat};
use crate::checks::documents::Doc;
use crate::checks::hidden::Hidden;
use crate::checks::malware::targets::{Scanned, Scope};
use crate::checks::malware::yara::Hit;
use crate::checks::supply_chain::mptcp::Facts;
use crate::checks::suspects::{FileResult, Kind, Suspect};
use crate::db::{Cache, DAY};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

pub const SCHEMA: &str = "
DROP TABLE IF EXISTS file_results;
CREATE TABLE IF NOT EXISTS file_cache (root TEXT PRIMARY KEY, seen REAL, data TEXT);
";

/// How long a file's results are kept once no scan sees it.
const KEEP: f64 = 30.0 * DAY;

/// The check's name in the cache.
fn name(check: Check) -> &'static str {
    match check {
        Check::Hidden => "hidden",
        Check::Suspects(Kind::Repo) => "suspects:repo",
        Check::Suspects(Kind::Installed) => "suspects:installed",
        Check::Mptcp => "mptcp",
        Check::Documents => "documents",
        Check::Malware(Scope::Programs) => "malware:programs",
        Check::Malware(Scope::All) => "malware:all",
        Check::Malware(Scope::File) => "malware:file",
    }
}

/// The source a check's per-file step is built from: a change to any of
/// it changes the check's version, and with it every cached result.
fn sources(check: Check) -> &'static [&'static str] {
    match check {
        Check::Hidden => &[
            include_str!("../hidden/mod.rs"),
            include_str!("../hidden/bait.rs"),
            include_str!("../hidden/html.rs"),
            include_str!("../hidden/instructions.rs"),
            include_str!("../hidden/links.rs"),
            include_str!("../hidden/names.rs"),
            include_str!("../hidden/unicode.rs"),
            include_str!("../../../assets/defaults/bait.toml"),
        ],
        Check::Suspects(_) => &[
            include_str!("../suspects/mod.rs"),
            include_str!("../suspects/blobs.rs"),
            include_str!("../suspects/cardholder.rs"),
            include_str!("../suspects/clipper.rs"),
            include_str!("../suspects/credentials.rs"),
            include_str!("../suspects/escalation.rs"),
            include_str!("../suspects/keylogger.rs"),
            include_str!("../suspects/network.rs"),
            include_str!("../suspects/obfuscation.rs"),
            include_str!("../suspects/profiling.rs"),
            include_str!("../suspects/scripts.rs"),
            include_str!("../suspects/secrets_weak.rs"),
            include_str!("../suspects/wallet.rs"),
            include_str!("../../utils/addresses.rs"),
            include_str!("../../../assets/defaults/weak-passwords.txt"),
        ],
        Check::Mptcp => &[include_str!("../supply_chain/mptcp.rs")],
        Check::Documents => &[
            include_str!("../documents/mod.rs"),
            include_str!("../documents/image.rs"),
            include_str!("../documents/ole.rs"),
            include_str!("../documents/ooxml.rs"),
            include_str!("../documents/pdf.rs"),
            include_str!("../documents/rtf.rs"),
            include_str!("../documents/svg.rs"),
            include_str!("../../utils/archive/mod.rs"),
            include_str!("../../utils/archive/zip.rs"),
            include_str!("../../utils/archive/deflate.rs"),
        ],
        Check::Malware(_) => &[include_str!("../malware/targets.rs"), include_str!("../malware/yara.rs")],
    }
}

/// The check's version: wpantry's, a hash of its source and the pass's,
/// and `salt` (the malware rules' hash).
pub fn version(check: Check, salt: &str) -> String {
    let base = base_version(check);
    if matches!(check, Check::Malware(_)) { format!("{base}:{salt}") } else { base }
}

fn base_version(check: Check) -> String {
    static VERSIONS: LazyLock<Mutex<std::collections::HashMap<&'static str, String>>> = LazyLock::new(Default::default);
    VERSIONS
        .lock()
        .expect("lock")
        .entry(name(check))
        .or_insert_with(|| {
            let mut h = crate::utils::sha256::Sha256::new();
            h.update(crate::VERSION.as_bytes());
            for s in sources(check)
                .iter()
                .chain([include_str!("pass.rs"), include_str!("view.rs"), include_str!("mod.rs")].iter())
            {
                h.update(s.as_bytes());
            }
            h.hex()
        })
        .clone()
}

/// A file's identity as the cache keeps it: a hash of its device, inode,
/// size and modification time.
fn fingerprint(stat: &Stat) -> u64 {
    let (dev, ino, size, mtime) = stat.id;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in [dev.to_le_bytes(), ino.to_le_bytes(), size.to_le_bytes(), mtime.to_bits().to_le_bytes()].concat() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// One file's results, all under one fingerprint: `(check, role, JSON)`.
#[derive(Clone, Debug, Default, PartialEq)]
struct Entry {
    print: u64,
    results: Vec<(String, u8, String)>,
}

/// One root's record: each check's version, and each file (by folder,
/// then name, relative to the root) with its results.
#[derive(Clone, Debug, Default, PartialEq)]
struct Record {
    versions: BTreeMap<String, String>,
    files: BTreeMap<String, BTreeMap<String, Entry>>,
}

const MAGIC: &str = "wpantry-files 1";

impl Record {
    fn text(&self) -> String {
        let mut out = String::from(MAGIC);
        out.push('\n');
        for (check, v) in &self.versions {
            out.push_str(&format!("c\t{check}\t{v}\n"));
        }
        for (dir, files) in &self.files {
            out.push_str(&format!("d\t{}\n", json!(dir)));
            for (name, e) in files {
                out.push_str(&format!("{}\t{:016x}", json!(name), e.print));
                for (check, role, result) in &e.results {
                    out.push_str(&format!("\t{check}/{role}={result}"));
                }
                out.push('\n');
            }
        }
        out
    }

    /// A record read back; an unreadable one is empty.
    fn parse(text: &str) -> Record {
        let mut lines = text.lines();
        let mut r = Record::default();
        if lines.next() != Some(MAGIC) {
            return r;
        }
        let mut dir = String::new();
        for line in lines {
            let mut parts = line.split('\t');
            let first = parts.next().unwrap_or("");
            match first {
                "c" => {
                    if let (Some(check), Some(v)) = (parts.next(), parts.next()) {
                        r.versions.insert(check.into(), v.into());
                    }
                }
                "d" => dir = parts.next().and_then(|d| serde_json::from_str(d).ok()).unwrap_or_default(),
                name => {
                    let Some(name) = serde_json::from_str::<String>(name).ok() else { return Record::default() };
                    let Some(print) = parts.next().and_then(|p| u64::from_str_radix(p, 16).ok()) else {
                        return Record::default();
                    };
                    let results = parts
                        .filter_map(|p| {
                            let (key, result) = p.split_once('=')?;
                            let (check, role) = key.split_once('/')?;
                            Some((check.to_string(), role.parse().ok()?, result.to_string()))
                        })
                        .collect();
                    r.files.entry(dir.clone()).or_default().insert(name, Entry { print, results });
                }
            }
        }
        r
    }
}

/// Where a file sits in its root's record: (folder, name).
fn place(root: &Path, path: &Path) -> (String, String) {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let dir = rel.parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
    let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    (dir, name)
}

/// The records of the roots a pass reads, and what it found this time.
pub(super) struct Store {
    /// The malware rules' hash, part of the malware scan's version.
    salt: String,
    old: HashMap<PathBuf, (String, Record)>,
    new: HashMap<PathBuf, Record>,
    /// The checks each root ran this time.
    ran: HashMap<PathBuf, HashSet<String>>,
}

impl Store {
    /// The records of `jobs`' roots.
    pub fn load(cache: &Cache, jobs: &[Job], salt: &str) -> Store {
        let mut old = HashMap::new();
        let mut ran: HashMap<PathBuf, HashSet<String>> = HashMap::new();
        for job in jobs {
            ran.entry(job.root.clone()).or_default().insert(name(job.check).into());
            if old.contains_key(&job.root) {
                continue;
            }
            let text: Option<String> = cache
                .conn
                .query_row("SELECT data FROM file_cache WHERE root=?", params![job.root.to_string_lossy()], |r| {
                    r.get(0)
                })
                .optional()
                .ok()
                .flatten();
            let text = text.unwrap_or_default();
            let record = Record::parse(&text);
            old.insert(job.root.clone(), (text, record));
        }
        Store { salt: salt.to_string(), old, new: HashMap::new(), ran }
    }

    /// `read`'s cached result in `job`, while the file and the check are
    /// unchanged.
    pub fn get(&self, job: &Job, read: &Read, stat: &Stat) -> Option<Out> {
        let (_, record) = self.old.get(&job.root)?;
        let check = name(job.check);
        if record.versions.get(check)? != &version(job.check, &self.salt) {
            return None;
        }
        let (dir, file) = place(&job.root, &read.path);
        let entry = record.files.get(&dir)?.get(&file)?;
        if entry.print != fingerprint(stat) {
            return None;
        }
        let (_, _, result) = entry.results.iter().find(|(c, r, _)| c == check && *r == read.role)?;
        from_json(job.check, &serde_json::from_str(result).ok()?, &read.path)
    }

    /// Keep `out` as `read`'s result in `job` this time.
    pub fn put(&mut self, job: &Job, read: &Read, stat: &Stat, out: &Out) {
        let check = name(job.check);
        let record = self.new.entry(job.root.clone()).or_default();
        record.versions.insert(check.into(), version(job.check, &self.salt));
        let (dir, file) = place(&job.root, &read.path);
        let entry = record.files.entry(dir).or_default().entry(file).or_default();
        let print = fingerprint(stat);
        if entry.print != print {
            *entry = Entry { print, results: Vec::new() };
        }
        entry.results.push((check.into(), read.role, to_json(out).to_string()));
    }

    /// Write back each root's record that changed: this time's results,
    /// and the results of checks that didn't run this time for files that
    /// haven't changed. Every root read is marked seen; a root no scan has
    /// seen for [`KEEP`] is dropped.
    pub fn save(mut self, cache: &Cache, started: f64) {
        for (root, (text, old)) in self.old {
            let mut record = self.new.remove(&root).unwrap_or_default();
            let ran = self.ran.get(&root).cloned().unwrap_or_default();
            for (check, v) in &old.versions {
                if !ran.contains(check) {
                    record.versions.entry(check.clone()).or_insert_with(|| v.clone());
                }
            }
            for (dir, files) in &old.files {
                for (name, e) in files {
                    let kept: Vec<_> = e.results.iter().filter(|(c, _, _)| !ran.contains(c)).cloned().collect();
                    if kept.is_empty() {
                        continue;
                    }
                    let entry = record
                        .files
                        .entry(dir.clone())
                        .or_default()
                        .entry(name.clone())
                        .or_insert_with(|| Entry { print: e.print, results: Vec::new() });
                    if entry.print == e.print {
                        entry.results.extend(kept);
                    }
                }
            }
            let new = record.text();
            let _ = if new != text {
                cache.conn.execute(
                    "INSERT OR REPLACE INTO file_cache VALUES (?, ?, ?)",
                    params![root.to_string_lossy(), started, new],
                )
            } else {
                cache
                    .conn
                    .execute("UPDATE file_cache SET seen=? WHERE root=?", params![started, root.to_string_lossy()])
            };
        }
        let _ = cache.conn.execute("DELETE FROM file_cache WHERE seen < ?", params![started - KEEP]);
        let _ = cache.commit();
    }
}

/// A `&'static str` for an id read back from the cache: each distinct
/// one is allocated once.
fn intern(s: &str) -> &'static str {
    static SEEN: LazyLock<Mutex<HashSet<&'static str>>> = LazyLock::new(Default::default);
    let mut seen = SEEN.lock().expect("lock");
    if let Some(&s) = seen.get(s) {
        return s;
    }
    let s: &'static str = Box::leak(s.to_owned().into_boxed_str());
    seen.insert(s);
    s
}

fn str_of(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn hidden_json(h: &Hidden) -> Value {
    json!({"file": h.file, "id": h.id, "note": h.note, "line": h.line, "hard": h.hard})
}

fn hidden_of(v: &Value) -> Hidden {
    Hidden {
        file: str_of(v, "file"),
        id: intern(&str_of(v, "id")),
        note: str_of(v, "note"),
        line: v.get("line").and_then(Value::as_u64).unwrap_or(0) as usize,
        hard: v.get("hard").and_then(Value::as_bool).unwrap_or(false),
    }
}

fn suspect_json(s: &Suspect) -> Value {
    json!({"file": s.file, "id": s.id, "line": s.line, "note": s.note, "hard": s.hard})
}

fn suspect_of(v: &Value) -> Suspect {
    Suspect {
        file: str_of(v, "file"),
        id: intern(&str_of(v, "id")),
        line: v.get("line").and_then(Value::as_u64).unwrap_or(0) as usize,
        note: str_of(v, "note"),
        hard: v.get("hard").and_then(Value::as_bool).unwrap_or(false),
    }
}

fn suspects_of(v: Option<&Value>) -> Vec<Suspect> {
    v.and_then(Value::as_array).map(|a| a.iter().map(suspect_of).collect()).unwrap_or_default()
}

fn doc_json(d: &Doc) -> Value {
    json!({"file": d.file, "id": d.id, "note": d.note, "hard": d.hard})
}

fn doc_of(v: &Value) -> Doc {
    Doc {
        file: str_of(v, "file"),
        id: intern(&str_of(v, "id")),
        note: str_of(v, "note"),
        hard: v.get("hard").and_then(Value::as_bool).unwrap_or(false),
    }
}

/// A needle and its line (`["net.Listen(", 12]`).
fn found_json(f: &Option<(&'static str, usize)>) -> Value {
    f.map_or(Value::Null, |(n, l)| json!([n, l]))
}

fn found_of(v: Option<&Value>) -> Option<(&'static str, usize)> {
    let a = v?.as_array()?;
    Some((intern(a.first()?.as_str()?), a.get(1)?.as_u64()? as usize))
}

fn to_json(out: &Out) -> Value {
    match out {
        Out::Hidden(v) => Value::Array(v.iter().map(hidden_json).collect()),
        Out::Suspects(f) => json!({
            "found": f.found.iter().map(suspect_json).collect::<Vec<_>>(),
            "wallet": f.wallet,
            "scripts": f.scripts.as_ref().map(|(a, b)| json!([
                a.iter().map(suspect_json).collect::<Vec<_>>(),
                b.iter().map(suspect_json).collect::<Vec<_>>()
            ])),
            "not_binary": f.not_binary,
        }),
        Out::Mptcp(None) => Value::Null,
        Out::Mptcp(Some(f)) => json!({
            "opts_out": f.opts_out,
            "go": f.go.as_ref().map(|(a, b, l)| json!([a, b, l])),
            "opt_in": found_json(&f.opt_in),
            "listen": found_json(&f.listen),
        }),
        Out::Documents(v) => Value::Array(v.iter().map(doc_json).collect()),
        // Nearly every file: the bare `target`, nothing found.
        Out::Malware(s) if s.hits.is_empty() => Value::Bool(s.target),
        Out::Malware(s) => json!({
            "target": s.target,
            "hits": s.hits.iter().map(|h| json!([h.namespace, h.rule, h.category, h.description, h.sha256])).collect::<Vec<_>>(),
        }),
    }
}

fn from_json(check: Check, v: &Value, path: &std::path::Path) -> Option<Out> {
    Some(match check {
        Check::Hidden => Out::Hidden(v.as_array()?.iter().map(hidden_of).collect()),
        Check::Suspects(_) => Out::Suspects(FileResult {
            found: suspects_of(v.get("found")),
            wallet: v.get("wallet")?.as_bool()?,
            scripts: v
                .get("scripts")
                .and_then(Value::as_array)
                .map(|a| (suspects_of(a.first()), suspects_of(a.get(1)))),
            not_binary: v.get("not_binary").and_then(Value::as_str).map(str::to_string),
        }),
        Check::Mptcp if v.is_null() => Out::Mptcp(None),
        Check::Mptcp => Out::Mptcp(Some(Facts {
            opts_out: v.get("opts_out")?.as_bool()?,
            go: v
                .get("go")
                .and_then(Value::as_array)
                .and_then(|a| Some((a.first()?.as_u64()?, a.get(1)?.as_u64()?, a.get(2)?.as_str()?.to_string()))),
            opt_in: found_of(v.get("opt_in")),
            listen: found_of(v.get("listen")),
        })),
        Check::Documents => Out::Documents(v.as_array()?.iter().map(doc_of).collect()),
        Check::Malware(_) if v.is_boolean() => Out::Malware(Scanned { target: v.as_bool()?, hits: Vec::new() }),
        Check::Malware(_) => Out::Malware(Scanned {
            target: v.get("target")?.as_bool()?,
            hits: v
                .get("hits")?
                .as_array()?
                .iter()
                .map(|h| {
                    let s = |i: usize| h.get(i).and_then(Value::as_str).unwrap_or_default().to_string();
                    Hit {
                        path: path.to_path_buf(),
                        namespace: s(0),
                        rule: s(1),
                        category: s(2),
                        description: s(3),
                        sha256: s(4),
                    }
                })
                .collect(),
        }),
    })
}

/// How many files `root`'s record holds a result of `check` for (for tests).
#[cfg(test)]
pub(super) fn rows(cache: &Cache, check: Check, root: &Path) -> usize {
    let text: String = cache
        .conn
        .query_row("SELECT data FROM file_cache WHERE root=?", params![root.to_string_lossy()], |r| r.get(0))
        .unwrap_or_default();
    Record::parse(&text)
        .files
        .values()
        .flat_map(|f| f.values())
        .filter(|e| e.results.iter().any(|(c, _, _)| c == name(check)))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_result_reads_back_as_it_was_kept() {
        let s = |id: &'static str| Suspect { file: "a.js".into(), id, line: 3, note: "n".into(), hard: true };
        let outs = [
            Out::Hidden(vec![Hidden { file: "x.md".into(), id: "HIDDEN-BIDI", note: "n".into(), line: 2, hard: true }]),
            Out::Suspects(FileResult {
                found: vec![s("SUSPECT-WALLET-SIGNING")],
                wallet: true,
                scripts: Some((vec![], vec![s("SUSPECT-THIRD-PARTY-SCRIPT")])),
                not_binary: None,
            }),
            Out::Suspects(FileResult { not_binary: Some("why".into()), ..Default::default() }),
            Out::Mptcp(None),
            Out::Mptcp(Some(Facts {
                opts_out: true,
                go: Some((1, 24, "go 1.24.0".into())),
                opt_in: Some(("SetMultipathTCP(true)", 4)),
                listen: None,
            })),
            Out::Documents(vec![Doc { file: "a.pdf".into(), id: "DOC-JS-ON-OPEN", note: "n".into(), hard: true }]),
            Out::Malware(Scanned { target: false, hits: Vec::new() }),
            Out::Malware(Scanned {
                target: true,
                hits: vec![Hit {
                    path: "/x/a.sh".into(),
                    namespace: "ns".into(),
                    rule: "R".into(),
                    category: "miner".into(),
                    description: "d".into(),
                    sha256: "ab".into(),
                }],
            }),
        ];
        let checks = [
            Check::Hidden,
            Check::Suspects(Kind::Repo),
            Check::Suspects(Kind::Installed),
            Check::Mptcp,
            Check::Mptcp,
            Check::Documents,
            Check::Malware(Scope::Programs),
            Check::Malware(Scope::All),
        ];
        for (check, out) in checks.iter().zip(&outs) {
            assert_eq!(
                from_json(*check, &to_json(out), std::path::Path::new("/x/a.sh")).as_ref(),
                Some(out),
                "{check:?}"
            );
        }
        assert_eq!(from_json(Check::Malware(Scope::All), &json!("garbage"), std::path::Path::new("/x")), None);
        assert!(std::ptr::eq(intern("SUSPECT-X"), intern(&String::from("SUSPECT-X"))));
    }

    #[test]
    fn a_record_reads_back_as_it_was_written() {
        let mut r = Record::default();
        r.versions.insert("hidden".into(), "v1".into());
        r.files.entry(String::new()).or_default().insert(
            "odd\tname\n.md".into(),
            Entry { print: 7, results: vec![("hidden".into(), 0, "[]".into()), ("mptcp".into(), 2, "null".into())] },
        );
        r.files.entry("a/b".into()).or_default().insert("c.rs".into(), Entry { print: u64::MAX, results: vec![] });
        assert_eq!(Record::parse(&r.text()), r);
        assert_eq!(Record::parse("not a record"), Record::default());
        assert_eq!(
            Record::parse(&format!("{MAGIC}\nnot json\t0\n")),
            Record::default(),
            "a broken line drops the record"
        );
    }

    #[test]
    fn versions_differ_by_check_and_hold_still() {
        assert_ne!(version(Check::Hidden, ""), version(Check::Documents, ""));
        assert_eq!(version(Check::Suspects(Kind::Repo), ""), version(Check::Suspects(Kind::Installed), ""));
        assert_eq!(version(Check::Mptcp, "a"), version(Check::Mptcp, "b"), "only the malware scan's rules salt it");
        assert_ne!(version(Check::Malware(Scope::All), "a"), version(Check::Malware(Scope::All), "b"));
    }
}
