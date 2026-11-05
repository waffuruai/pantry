//! The files pass's cache: each check's result for each file, kept while
//! the file is unchanged (its device, inode, size and modification time)
//! and the check's code is the same, so a scan reads only what changed.

use super::pass::{Check, Job, Out};
use super::{Read, Stat};
use crate::checks::documents::Doc;
use crate::checks::hidden::Hidden;
use crate::checks::supply_chain::mptcp::Facts;
use crate::checks::suspects::{FileResult, Kind, Suspect};
use crate::db::{Cache, DAY};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS file_results (
  checker TEXT, root TEXT, path TEXT, role INTEGER,
  dev INTEGER, ino INTEGER, size INTEGER, mtime REAL,
  version TEXT, result TEXT, seen REAL,
  PRIMARY KEY (checker, root, path, role));
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
        Check::Programs => "programs",
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
        Check::Programs => &[include_str!("../malware/mod.rs")],
    }
}

/// The check's version: wpantry's, and a hash of its source and the pass's.
pub fn version(check: Check) -> String {
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

/// A cached result for `read` in `job`, while the file and the check are
/// unchanged.
pub(super) fn get(cache: &Cache, job: &Job, read: &Read, stat: &Stat) -> Option<Out> {
    let (dev, ino, size, mtime) = stat.id;
    let mut stmt = cache
        .conn
        .prepare_cached(
            "SELECT result FROM file_results WHERE checker=? AND root=? AND path=? AND role=? \
             AND dev=? AND ino=? AND size=? AND mtime=? AND version=?",
        )
        .ok()?;
    let row: Option<String> = stmt
        .query_row(
            params![
                name(job.check),
                job.root.to_string_lossy(),
                read.path.to_string_lossy(),
                read.role,
                dev,
                ino,
                size,
                mtime,
                version(job.check)
            ],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten();
    from_json(job.check, &serde_json::from_str(&row?).ok()?)
}

/// Keep `out` for `read` in `job`, seen at `seen`.
pub(super) fn put(cache: &Cache, job: &Job, read: &Read, stat: &Stat, out: &Out, seen: f64) {
    let (dev, ino, size, mtime) = stat.id;
    let Ok(mut stmt) =
        cache.conn.prepare_cached("INSERT OR REPLACE INTO file_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    else {
        return;
    };
    let _ = stmt.execute(params![
        name(job.check),
        job.root.to_string_lossy(),
        read.path.to_string_lossy(),
        read.role,
        dev,
        ino,
        size,
        mtime,
        version(job.check),
        to_json(out).to_string(),
        seen
    ]);
}

/// Mark a cached result seen at `seen`.
pub(super) fn touch(cache: &Cache, job: &Job, read: &Read, seen: f64) {
    let Ok(mut stmt) =
        cache.conn.prepare_cached("UPDATE file_results SET seen=? WHERE checker=? AND root=? AND path=? AND role=?")
    else {
        return;
    };
    let _ = stmt.execute(params![
        seen,
        name(job.check),
        job.root.to_string_lossy(),
        read.path.to_string_lossy(),
        read.role
    ]);
}

/// Drop the results of files these jobs no longer read (deleted, moved,
/// past a limit), and of any file no scan has seen for [`KEEP`].
pub(super) fn prune(cache: &Cache, jobs: &[Job], started: f64) {
    for job in jobs {
        let _ = cache.conn.execute(
            "DELETE FROM file_results WHERE checker=? AND root=? AND seen < ?",
            params![name(job.check), job.root.to_string_lossy(), started],
        );
    }
    let _ = cache.conn.execute("DELETE FROM file_results WHERE seen < ?", params![started - KEEP]);
    let _ = cache.commit();
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
        Out::Program(b) => Value::Bool(*b),
    }
}

fn from_json(check: Check, v: &Value) -> Option<Out> {
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
        Check::Programs => Out::Program(v.as_bool()?),
    })
}

/// Whether `root` has results cached for `check` (for tests).
#[cfg(test)]
pub(super) fn rows(cache: &Cache, check: Check, root: &std::path::Path) -> i64 {
    cache
        .conn
        .query_row(
            "SELECT count(*) FROM file_results WHERE checker=? AND root=?",
            params![name(check), root.to_string_lossy()],
            |r| r.get(0),
        )
        .unwrap_or(0)
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
            Out::Program(true),
        ];
        let checks = [
            Check::Hidden,
            Check::Suspects(Kind::Repo),
            Check::Suspects(Kind::Installed),
            Check::Mptcp,
            Check::Mptcp,
            Check::Documents,
            Check::Programs,
        ];
        for (check, out) in checks.iter().zip(&outs) {
            assert_eq!(from_json(*check, &to_json(out)).as_ref(), Some(out), "{check:?}");
        }
        assert_eq!(from_json(Check::Programs, &json!("garbage")), None);
        assert!(std::ptr::eq(intern("SUSPECT-X"), intern(&String::from("SUSPECT-X"))));
    }

    #[test]
    fn versions_differ_by_check_and_hold_still() {
        assert_ne!(version(Check::Hidden), version(Check::Documents));
        assert_eq!(version(Check::Suspects(Kind::Repo)), version(Check::Suspects(Kind::Installed)));
        assert_eq!(version(Check::Mptcp), version(Check::Mptcp));
    }
}
