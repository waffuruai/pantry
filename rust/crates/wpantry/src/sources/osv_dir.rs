//! Advisories on this machine: a source of the user's own with
//! `kind = "advisories"`, `format = "osv-dir"` and a `path` to a folder of
//! OSV records, one per `*.json` file (`specs/design/sources-file.md`,
//! "Sources on this machine").
//!
//! ```toml
//! [[source]]
//! id = "team-advisories"
//! kind = "advisories"
//! format = "osv-dir"
//! path = "~/advisories"
//! ```
//!
//! The folder is read with the rules of a rules folder
//! ([`crate::sources::local`]): regular files only, no symlinks followed,
//! nothing outside it, plus one level of real subfolders
//! (`<ecosystem>/<id>.json`). It is read again only when its fingerprint
//! changes (each file's relative path, size and modification time, with the
//! path, pin and cap), and then its records replace the source's last set
//! as a whole in `local_vulns`, keyed by source and id. Nothing here is
//! governed by OSV's query TTL or its change lists.
//!
//! [`matching`] gives [`crate::sources::osv::lookup`] the records of the
//! sources in use that affect an item, judged here with
//! [`crate::sources::osv_changes::affects`]; a record only a service could
//! judge (a range of git commits, an ecosystem without a known order) is
//! left out and named as a gap.

use crate::db::Cache;
use crate::error::Result;
use crate::sources::fetch;
use crate::sources::file::{self, Source};
use crate::sources::local::{self, Found, Walk};
use crate::sources::osv::{self, Item};
use crate::utils::json::{arr_at, str_at};
use rusqlite::{OptionalExtension, params};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS local_vulns (
  source TEXT, id TEXT, file TEXT, aliases TEXT, url TEXT, record TEXT,
  PRIMARY KEY (source, id));
CREATE TABLE IF NOT EXISTS local_vuln_names (source TEXT, id TEXT, name TEXT);
CREATE INDEX IF NOT EXISTS local_vuln_names_name ON local_vuln_names (name);
";

/// The most `*.json` files one source may have.
pub const MAX_FILES: usize = 100_000;
/// The most bytes one source's files may hold together: 1 GiB.
pub const MAX_TOTAL_BYTES: u64 = 1 << 30;

/// How much one source may hold: files, and bytes together.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub files: usize,
    pub bytes: u64,
}

/// The limits every source is read under.
pub(crate) const LIMITS: Limits = Limits { files: MAX_FILES, bytes: MAX_TOTAL_BYTES };

/// The key a record matched from a source on this machine carries in
/// memory (never in the cache): the source's id. A record from anywhere
/// else has it removed ([`strip`]).
pub const SOURCE_KEY: &str = "wpantry_local_source";

#[cfg(test)]
thread_local! {
    /// How many times this thread read a folder's files.
    pub(crate) static READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Whether `s` is a folder of OSV records on this machine.
pub fn is_osv_dir(s: &Source) -> bool {
    s.format == file::OSV_DIR && s.transport == file::Transport::Local
}

/// Load each of `sources` (the user's osv-dir sources in use this run) when
/// its folder changed, and drop the records of every osv-dir source not
/// among `declared` (one turned off, or kept for `--deep`, keeps its
/// records). Returns the sources that have no good load to use, with why.
pub fn load(cache: &Cache, sources: &[Source], declared: &[Source]) -> Result<Vec<(String, String)>> {
    load_with(cache, sources, declared, LIMITS)
}

/// [`load`] under `limits`.
pub(crate) fn load_with(
    cache: &Cache,
    sources: &[Source],
    declared: &[Source],
    limits: Limits,
) -> Result<Vec<(String, String)>> {
    let keep: BTreeSet<&str> = declared.iter().filter(|s| is_osv_dir(s)).map(|s| s.id.as_str()).collect();
    for gone in loaded(cache)?.iter().filter(|h| !keep.contains(h.as_str())) {
        forget(cache, gone)?;
    }
    let mut failed = Vec::new();
    for s in sources.iter().filter(|s| is_osv_dir(s)) {
        if let Err(why) = load_one(cache, s, limits)? {
            fetch::record(&s.id, Err(why.clone()));
            if cache.get(&fp_key(&s.id))?.is_none() {
                failed.push((s.id.clone(), why));
            }
        }
    }
    cache.commit()?;
    Ok(failed)
}

fn fp_key(id: &str) -> String {
    format!("user:{id}_fp")
}

fn counts_key(id: &str) -> String {
    format!("user:{id}_osv")
}

/// The ids of every source with anything left here: those with a record,
/// and those with a counts key, which every successful load writes, a load
/// of no valid records included (and a database an older build wrote may
/// hold either without the other). The fingerprint key is not listed: rules
/// folders write the same suffix.
fn loaded(cache: &Cache) -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    let mut stmt = cache.conn.prepare("SELECT DISTINCT source FROM local_vulns")?;
    for id in stmt.query_map([], |r| r.get::<_, String>(0))? {
        ids.insert(id?);
    }
    let mut stmt = cache.conn.prepare("SELECT key FROM meta WHERE key LIKE 'user:%\\_osv' ESCAPE '\\'")?;
    for key in stmt.query_map([], |r| r.get::<_, String>(0))? {
        if let Some(id) = key?.strip_prefix("user:").and_then(|k| k.strip_suffix("_osv")) {
            ids.insert(id.to_string());
        }
    }
    Ok(ids)
}

/// A source's records, its fingerprint and its counts, gone.
fn forget(cache: &Cache, id: &str) -> Result<()> {
    cache.conn.execute("DELETE FROM local_vulns WHERE source = ?", [id])?;
    cache.conn.execute("DELETE FROM local_vuln_names WHERE source = ?", [id])?;
    cache.unset(&fp_key(id))?;
    cache.unset(&counts_key(id))
}

/// How many records the source's last good load holds, and how many of its
/// files were skipped; None before its first.
pub fn counts(cache: &Cache, id: &str) -> Result<Option<(u64, u64)>> {
    Ok(cache.get(&counts_key(id))?.and_then(|v| {
        let (r, s) = v.split_once(' ')?;
        Some((r.parse().ok()?, s.parse().ok()?))
    }))
}

/// Read `s` when its folder changed. `Ok(Err(why))` leaves the last good
/// load in place; only a cache failure is an error.
fn load_one(cache: &Cache, s: &Source, limits: Limits) -> Result<std::result::Result<(), String>> {
    let found = match list(s, limits) {
        Ok(f) => f,
        Err(why) => return Ok(Err(why)),
    };
    let fp = local::fingerprint(s, &found);
    if let Some(kept) = cache.get(&fp_key(&s.id))?
        && let Some((was, bytes)) = kept.split_once(' ')
        && was == fp
    {
        fetch::record(&s.id, Ok(bytes.parse().unwrap_or(0)));
        return Ok(Ok(()));
    }
    #[cfg(test)]
    READS.with(|r| r.set(r.get() + 1));
    // The new set replaces the old one inside a savepoint, a record at a
    // time (a 1 GiB folder is never held in memory whole): a read that
    // fails part way, or a pin that fails at the end, rolls back to the
    // last good set.
    cache.conn.execute_batch("SAVEPOINT osv_dir")?;
    match replace(cache, s, &found, limits) {
        Ok(Ok((records, skipped, total))) => {
            cache.set(&fp_key(&s.id), &format!("{fp} {total}"))?;
            cache.set(&counts_key(&s.id), &format!("{records} {skipped}"))?;
            cache.conn.execute_batch("RELEASE osv_dir")?;
            fetch::record(&s.id, Ok(total));
            Ok(Ok(()))
        }
        other => {
            cache.conn.execute_batch("ROLLBACK TO osv_dir; RELEASE osv_dir")?;
            other.map(|r| r.map(|_| ()))
        }
    }
}

/// Replace `s`'s records with the folder's, reading each file once: its
/// bytes go into the pin ([`pin`]) and its record, when it is one
/// ([`record`]), into `local_vulns` (the later file in byte-wise path order
/// wins a duplicate id). A file over the source's `max_bytes`, the files
/// together over `limits.bytes`, a file that can't be read and a failed pin
/// refuse the whole read. Returns (records, files skipped, bytes read).
fn replace(
    cache: &Cache,
    s: &Source,
    found: &Found,
    limits: Limits,
) -> Result<std::result::Result<(u64, u64, u64), String>> {
    let Found::Folder(dir, files) = found else { return Ok(Err("not a folder".into())) };
    forget(cache, &s.id)?;
    let mut pin = crate::utils::sha256::Sha256::new();
    let (mut total, mut skipped) = (0u64, 0u64);
    for f in files {
        let body = match local::read_entry(&f.path, s.max_bytes) {
            Ok(b) => b,
            Err(e) => {
                return Ok(Err(format!(
                    "{}: {e} (each .json file is read up to {} bytes)",
                    dir.display(),
                    s.max_bytes
                )));
            }
        };
        total += body.len() as u64;
        if total > limits.bytes {
            return Ok(Err(format!("{}: its .json files are over {} bytes together", dir.display(), limits.bytes)));
        }
        pin_part(&mut pin, &f.rel, &body);
        let Some(rec) = record(&body) else {
            skipped += 1;
            continue;
        };
        drop(body);
        let id = str_at(&rec, "id");
        cache.conn.execute("DELETE FROM local_vuln_names WHERE source = ? AND id = ?", params![s.id, id])?;
        cache.conn.execute(
            "INSERT OR REPLACE INTO local_vulns VALUES (?, ?, ?, ?, ?, ?)",
            params![
                s.id,
                id,
                String::from_utf8_lossy(&f.rel),
                crate::utils::json::strs_at(&rec, "aliases").join(" "),
                link(&rec).unwrap_or_default(),
                rec.to_string()
            ],
        )?;
        for name in names(&rec) {
            cache.conn.execute("INSERT INTO local_vuln_names VALUES (?, ?, ?)", params![s.id, id, name])?;
        }
    }
    if !s.sha256.is_empty() && pin.hex() != s.sha256 {
        return Ok(Err(format!("rejected: {} doesn't match its sha256 pin", s.url)));
    }
    let records: i64 =
        cache.conn.query_row("SELECT COUNT(*) FROM local_vulns WHERE source = ?", [&s.id], |r| r.get(0))?;
    Ok(Ok((records as u64, skipped, total)))
}

/// The folder `s` names (resolved once) and its record files, refused when
/// it isn't a folder or holds more than the limits allow.
fn list(s: &Source, limits: Limits) -> std::result::Result<Found, String> {
    let p = file::local_path(s).map_err(|e| e.to_string())?;
    let (real, folder) = local::resolve(&p)?;
    if !folder {
        return Err(format!("{} is not a folder: an osv-dir source is a folder of OSV records", p.display()));
    }
    let walk = Walk { ext: "json", depth: 1, max_files: limits.files };
    let files = local::folder_files(&real, walk).map_err(|e| format!("{}: {e}", p.display()))?;
    let listed: u64 = files.iter().filter_map(|f| std::fs::symlink_metadata(&f.path).ok()).map(|m| m.len()).sum();
    if listed > limits.bytes {
        return Err(format!("{}: its .json files are over {} bytes together", p.display(), limits.bytes));
    }
    Ok(Found::Folder(real, files))
}

/// One file's part of a folder's pin: its relative path, a newline, its
/// size in decimal, a newline, then its bytes.
fn pin_part(h: &mut crate::utils::sha256::Sha256, rel: &[u8], body: &[u8]) {
    h.update(rel);
    h.update(format!("\n{}\n", body.len()).as_bytes());
    h.update(body);
}

/// The SHA-256 a folder's `sha256` pin is: over each file, in byte-wise
/// order of its relative path (`/` between parts), [`pin_part`].
///
/// ```ignore
/// // a.json = "{}", npm/b.json = "[]":
/// // sha256("a.json\n2\n{}" + "npm/b.json\n2\n[]")
/// ```
pub fn pin(files: &[(&[u8], &[u8])]) -> String {
    let mut h = crate::utils::sha256::Sha256::new();
    let mut sorted = files.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (rel, body) in sorted {
        pin_part(&mut h, rel, body);
    }
    h.hex()
}

/// The OSV record in a file's bytes, None when it isn't one: JSON, an
/// object, an `id` (no spaces or control characters), and at least one
/// `affected` entry that names a package (ecosystem and name) or a git
/// repository's range.
pub fn record(body: &[u8]) -> Option<Value> {
    let rec = crate::utils::json::parse(body, crate::utils::json::MAX_DOCUMENT).ok()?;
    let id = rec.get("id")?.as_str()?;
    if id.is_empty() || id.len() > 256 || id.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let usable = |a: &Value| {
        let p = a.get("package").unwrap_or(&Value::Null);
        let named = !str_at(p, "ecosystem").is_empty() && !str_at(p, "name").is_empty();
        named || arr_at(a, "ranges").iter().any(|r| str_at(r, "type") == "GIT" && !str_at(r, "repo").is_empty())
    };
    arr_at(&rec, "affected").iter().any(usable).then_some(rec)
}

/// The names a record is found by: each affected package's name in lower
/// case, and git repositories (a package name, a range's `repo`) the way
/// [`osv::norm_repo`] writes them.
fn names(rec: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for a in arr_at(rec, "affected") {
        let name = a.get("package").map(|p| str_at(p, "name")).unwrap_or("");
        if !name.is_empty() {
            out.insert(name.to_lowercase());
            out.insert(osv::norm_repo(name));
        }
        for r in arr_at(a, "ranges") {
            let repo = str_at(r, "repo");
            if !repo.is_empty() {
                out.insert(osv::norm_repo(repo));
            }
        }
    }
    out
}

/// A local record's link: the first of its `references` whose type is
/// `ADVISORY` or `WEB`, when that one's `url` is an https URL; else none.
/// Never one the record doesn't give.
pub fn link(rec: &Value) -> Option<String> {
    let first = arr_at(rec, "references").iter().find(|r| matches!(str_at(r, "type"), "ADVISORY" | "WEB"))?;
    let url = str_at(first, "url");
    let clean = url.len() <= 2048 && !url.chars().any(|c| c.is_whitespace() || c.is_control());
    (clean && crate::utils::net::host_of(url).is_some()).then(|| url.to_string())
}

/// Takes [`SOURCE_KEY`] off a record that didn't come from here.
pub fn strip(rec: &mut Value) {
    if let Some(o) = rec.as_object_mut() {
        o.remove(SOURCE_KEY);
    }
}

/// The records of the osv-dir sources in use that affect each of `items`,
/// and the ids, by source, only a service could judge.
#[derive(Debug, Default)]
pub struct Matched {
    pub found: HashMap<Item, Vec<Value>>,
    pub undecided: BTreeMap<String, BTreeSet<String>>,
}

/// The ids of the osv-dir sources in use this run, in the sources files'
/// order.
pub fn in_use() -> Vec<String> {
    #[cfg(test)]
    if let Some(ids) = TEST_IN_USE.with(|t| t.borrow().clone()) {
        return ids;
    }
    file::effective().sources.iter().filter(|s| is_osv_dir(s) && file::active(&s.id)).map(|s| s.id.clone()).collect()
}

#[cfg(test)]
thread_local! {
    static TEST_IN_USE: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

/// Use the osv-dir sources `ids` on this test's thread only (the sources in
/// effect are the process's); None goes back to them.
#[cfg(test)]
pub(crate) fn set_test_in_use(ids: Option<&[&str]>) {
    TEST_IN_USE.with(|t| *t.borrow_mut() = ids.map(|i| i.iter().map(|s| s.to_string()).collect()));
}

/// The records of the osv-dir sources `order` (ids, in the sources files'
/// order; [`in_use`]) that affect each of `items`, as [`osv::lookup`] gives
/// OSV's: each with only the `affected` entries for the item, and
/// [`SOURCE_KEY`] set.
pub fn matching<'a>(cache: &Cache, items: impl IntoIterator<Item = &'a Item>, order: &[String]) -> Result<Matched> {
    let mut out = Matched::default();
    if order.is_empty() {
        return Ok(out);
    }
    let mut stmt = cache.conn.prepare(
        "SELECT DISTINCT v.source, v.id, v.record FROM local_vuln_names n \
         JOIN local_vulns v ON v.source = n.source AND v.id = n.id WHERE n.name = ? ORDER BY v.id",
    )?;
    for it in items {
        let key = if it.0 == "GIT" { osv::norm_repo(&it.1) } else { it.1.to_lowercase() };
        let rows: Vec<(String, String, String)> =
            stmt.query_map([key], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?;
        let mut rows: Vec<(usize, String, String, String)> = rows
            .into_iter()
            .filter_map(|(s, id, rec)| order.iter().position(|o| *o == s).map(|i| (i, s, id, rec)))
            .collect();
        rows.sort_by(|a, b| (a.0, &a.2).cmp(&(b.0, &b.2)));
        for (_, source, id, text) in rows {
            // A row another writer left unreadable is as good as missing.
            let Ok(mut rec) = serde_json::from_str::<Value>(&text) else { continue };
            if !rec.is_object() {
                continue;
            }
            match crate::sources::osv_changes::affects(&rec, &it.0, &it.1, &it.2) {
                Some(true) => {
                    if let Some(affected) = rec.get_mut("affected").and_then(Value::as_array_mut) {
                        affected.retain(|a| osv::matches(a, &it.0, &it.1));
                    }
                    if let Some(o) = rec.as_object_mut() {
                        o.insert(SOURCE_KEY.to_string(), Value::String(source));
                    }
                    out.found.entry(it.clone()).or_default().push(rec);
                }
                Some(false) => {}
                None => {
                    out.undecided.entry(source).or_default().insert(id);
                }
            }
        }
    }
    Ok(out)
}

/// A local record by its id or, failing that, an alias, with its link
/// ("" for none): what a report shows for a finding no cached OSV record
/// has the id of.
pub fn by_id(cache: &Cache, id: &str, alias: bool) -> Result<Option<(Value, String)>> {
    let sql = if alias {
        "SELECT record, url FROM local_vulns WHERE (' ' || aliases || ' ') LIKE ('% ' || ? || ' %') ORDER BY source LIMIT 1"
    } else {
        "SELECT record, url FROM local_vulns WHERE id = ? ORDER BY source LIMIT 1"
    };
    let row: Option<(String, Option<String>)> =
        cache.conn.query_row(sql, [id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    Ok(row.and_then(|(t, u)| serde_json::from_str(&t).ok().map(|v| (v, u.unwrap_or_default()))))
}

#[cfg(test)]
#[path = "osv_dir_tests.rs"]
mod tests;
