//! Sources on this machine (`path = "..."` in a sources file of the user's
//! own; `specs/design/sources-file.md`): a file, or for YARA rules a folder
//! of `*.yar` files, read into the same copy a fetched source makes
//! ([`crate::sources::user`]), with the same guards as a download: the
//! source's `max_bytes`, its `sha256` pin, and a copy that can't be read or
//! fails its pin keeping the last good one, the reason kept for
//! `wpantry sources` ([`fetch::record`]).
//!
//! A local source is read again when what it is made of changed (each
//! file's name, size and modification time, [`fingerprint`]), never on a
//! `refresh` period, and it is read with `--offline` too: it contacts
//! nobody.
//!
//! A folder of rules is read flat: only the regular files directly in it,
//! no subfolders, and no symlinks followed, so nothing outside the folder
//! is read. A folder of OSV records ([`crate::sources::osv_dir`]) is read
//! with the same rules and one level of real subfolders. The path itself
//! may be a symlink: it is resolved once, and what it names must be a
//! regular file or a folder.
//!
//! ```toml
//! [[source]]
//! id = "team-rules"
//! kind = "yara"
//! format = "yara"
//! path = "~/src/team-rules/yara"
//! ```

use crate::db::Cache;
use crate::error::Result;
use crate::sources::fetch;
use crate::sources::file::{self, Source};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// What a local source's path names, resolved.
#[derive(Debug, PartialEq)]
pub(crate) enum Found {
    File(PathBuf),
    /// A folder and the files read from it ([`folder_files`]), in byte-wise
    /// order of their paths relative to the folder.
    Folder(PathBuf, Vec<Entry>),
}

/// One file of a folder source: where it is, and its path relative to the
/// folder with `/` between parts (`npm/TEAM-1.json`), the name it is
/// ordered and pinned by.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Entry {
    pub path: PathBuf,
    pub rel: Vec<u8>,
}

/// Which files of a folder a source reads.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Walk {
    /// The extension a file has to have (`yar`, `json`).
    pub ext: &'static str,
    /// How many levels of subfolders below the folder are read: 0 reads it
    /// flat.
    pub depth: usize,
    /// The most files listed; more is an error, not a cut.
    pub max_files: usize,
}

/// A YARA rules folder: its `*.yar` files, flat.
const RULES: Walk = Walk { ext: "yar", depth: 0, max_files: usize::MAX };

#[cfg(test)]
thread_local! {
    /// How many times this thread read a local source's contents.
    pub(crate) static READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Source `s`'s new copy when what it reads changed since the last good
/// read (`key` names its fingerprint in the cache), None when unchanged or
/// when it can't be used now (the last copy stays, and why is recorded).
pub(crate) fn copy(cache: &Cache, s: &Source, key: &str) -> Result<Option<Vec<u8>>> {
    let fp_key = format!("{key}_fp");
    let found = match locate(s) {
        Ok(f) => f,
        Err(why) => {
            fetch::record(&s.id, Err(why));
            return Ok(None);
        }
    };
    let fp = fingerprint(s, &found);
    if let Some(kept) = cache.get(&fp_key)?
        && let Some((was, bytes)) = kept.split_once(' ')
        && was == fp
    {
        fetch::record(&s.id, Ok(bytes.parse().unwrap_or(0)));
        return Ok(None);
    }
    #[cfg(test)]
    READS.with(|r| r.set(r.get() + 1));
    let body = match read(s, &found) {
        Ok(b) => b,
        Err(why) => {
            fetch::record(&s.id, Err(why));
            return Ok(None);
        }
    };
    if !s.sha256.is_empty() && crate::utils::sha256::hex(&body) != s.sha256 {
        fetch::record(&s.id, Err(format!("rejected: {} doesn't match its sha256 pin", s.url)));
        return Ok(None);
    }
    fetch::record(&s.id, Ok(body.len() as u64));
    cache.set(&fp_key, &format!("{fp} {}", body.len()))?;
    Ok(Some(body))
}

/// Where `s` reads: its path resolved once (a symlink to the file or folder
/// is followed here, and only here), refused unless it names a regular file
/// or, for YARA rules, a folder with `*.yar` files in it.
fn locate(s: &Source) -> std::result::Result<Found, String> {
    let p = file::local_path(s).map_err(|e| e.to_string())?;
    let real = resolve(&p)?;
    if !real.1 {
        return Ok(Found::File(real.0));
    }
    if s.kind != "yara" {
        return Err(format!(
            "{} is a folder: a folder is a source only of YARA rules (kind yara) or of OSV records (format osv-dir)",
            p.display()
        ));
    }
    let rules = folder_files(&real.0, RULES).map_err(|e| format!("{}: {e}", p.display()))?;
    if rules.is_empty() {
        return Err(format!("{} has no .yar files", p.display()));
    }
    Ok(Found::Folder(real.0, rules))
}

/// `p` resolved once (a symlink to the file or folder is followed here, and
/// only here), and whether it is a folder; refused unless it names a
/// regular file or a folder.
pub(crate) fn resolve(p: &Path) -> std::result::Result<(PathBuf, bool), String> {
    let real = std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let meta = std::fs::symlink_metadata(&real).map_err(|e| format!("{}: {e}", p.display()))?;
    if meta.is_file() {
        return Ok((real, false));
    }
    if !meta.is_dir() {
        return Err(format!("{} is not a regular file or a folder", p.display()));
    }
    Ok((real, true))
}

/// The regular files with `walk.ext` in `dir` and, `walk.depth` levels
/// down, in its real subfolders, in byte-wise order of their relative
/// paths: a symlink (to a file or a folder) is passed over, never followed,
/// and a subfolder deeper than `walk.depth` is not read. More than
/// `walk.max_files` such files is an error.
///
/// ```ignore
/// // dir/a.json, dir/npm/b.json, dir/npm/deep/c.json, dir/link.json -> x
/// // depth 1: a.json, npm/b.json
/// ```
pub(crate) fn folder_files(dir: &Path, walk: Walk) -> std::io::Result<Vec<Entry>> {
    let mut out: Vec<Entry> = Vec::new();
    // (folder, its relative path with a trailing `/`, its level)
    let mut todo: Vec<(PathBuf, Vec<u8>, usize)> = vec![(dir.to_path_buf(), Vec::new(), 0)];
    while let Some((at, prefix, level)) = todo.pop() {
        for e in std::fs::read_dir(&at)?.flatten() {
            // The entry's own type: a symlink is a symlink here, not its target.
            let Ok(kind) = e.file_type() else { continue };
            let mut rel = prefix.clone();
            rel.extend_from_slice(e.file_name().as_encoded_bytes());
            if kind.is_dir() && level < walk.depth {
                rel.push(b'/');
                todo.push((e.path(), rel, level + 1));
                continue;
            }
            let p = e.path();
            if kind.is_file() && p.extension().is_some_and(|x| x == walk.ext) {
                if out.len() >= walk.max_files {
                    return Err(std::io::Error::other(format!("more than {} .{} files", walk.max_files, walk.ext)));
                }
                out.push(Entry { path: p, rel });
            }
        }
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

/// What a read depends on: where it reads, the pin and the cap, and each
/// file's name, size and modification time. A changed one is read again.
pub(crate) fn fingerprint(s: &Source, found: &Found) -> String {
    let mut h = crate::utils::sha256::Sha256::new();
    h.update(format!("{}\n{}\n{}\n", s.url, s.sha256, s.max_bytes).as_bytes());
    let files: Vec<&PathBuf> = match found {
        Found::File(f) => vec![f],
        Found::Folder(dir, entries) => {
            h.update(format!("folder {}\n", dir.display()).as_bytes());
            entries.iter().map(|e| &e.path).collect()
        }
    };
    for f in files {
        let meta = std::fs::symlink_metadata(f).ok();
        let when = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos());
        h.update(format!("{}\t{:?}\t{:?}\n", f.display(), meta.map(|m| m.len()), when).as_bytes());
    }
    h.hex()
}

/// The bytes `s` reads, at most its `max_bytes`: a file whole, a folder's
/// rule files joined in name order, each followed by a newline (as
/// Elastic's rules are joined, [`crate::checks::malware::yara`]).
fn read(s: &Source, found: &Found) -> std::result::Result<Vec<u8>, String> {
    match found {
        Found::File(f) => {
            let body = crate::utils::files::read_capped_bytes(f, s.max_bytes).map_err(|e| e.to_string())?;
            if s.kind == "yara" { rules_text(f, body) } else { Ok(body) }
        }
        Found::Folder(dir, rules) => {
            let mut out = Vec::new();
            for f in rules {
                // Each file costs its bytes plus its separator newline, so a
                // file needs room for at least that one byte, even an empty
                // one: the joined copy never passes `max_bytes`. With no byte
                // left the file is over the cap (an empty file is refused
                // there rather than skipped, so the copy keeps the same shape
                // wherever the cap falls). The subtraction is checked: a
                // saturating one gave such a file a zero budget it then met,
                // and the newline pushed the copy one byte over.
                let over =
                    |e: String| format!("{}: {e} (the .yar files are read up to {} bytes)", dir.display(), s.max_bytes);
                let Some(room) = s.max_bytes.checked_sub(out.len() as u64 + 1) else {
                    return Err(over(format!("{} is over the cap with the newline after it", f.path.display())));
                };
                let body = read_entry(&f.path, room).map_err(over)?;
                let body = rules_text(&f.path, body).map_err(|e| format!("{}: {e}", dir.display()))?;
                out.extend_from_slice(&body);
                out.push(b'\n');
            }
            Ok(out)
        }
    }
}

/// A YARA rules file's bytes as the rules loader reads them, which is as
/// UTF-8 text: a file that isn't (Latin-1, UTF-16) makes the whole joined
/// copy unreadable, so its source would add no rules and say nothing. It is
/// refused here, by name, so the source fails and is reported `unchecked`.
/// A leading UTF-8 byte order mark (what some Windows editors write) is
/// valid UTF-8 but is not YARA: the joined copy would carry it mid-file, so
/// it is dropped.
fn rules_text(f: &Path, body: Vec<u8>) -> std::result::Result<Vec<u8>, String> {
    if let Err(e) = std::str::from_utf8(&body) {
        return Err(format!(
            "{} is not UTF-8 text (invalid byte at offset {}): YARA rules are read as UTF-8, so re-save it as UTF-8",
            f.display(),
            e.valid_up_to()
        ));
    }
    Ok(body.strip_prefix(b"\xEF\xBB\xBF").map(<[u8]>::to_vec).unwrap_or(body))
}

/// One file of a folder, at most `max` bytes, refused when it is no longer
/// the regular file listed (swapped for a symlink since).
pub(crate) fn read_entry(f: &Path, max: u64) -> std::result::Result<Vec<u8>, String> {
    let listed = std::fs::symlink_metadata(f).map_err(|e| e.to_string())?;
    if !listed.file_type().is_file() {
        return Err(format!("{} is not a regular file", f.display()));
    }
    use std::io::Read;
    let mut file = std::fs::File::open(f).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    // The file opened is the one listed (same device and inode), not what a
    // symlink put in its place since points at.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (opened.dev(), opened.ino()) != (listed.dev(), listed.ino()) {
            return Err(format!("{} changed while it was read", f.display()));
        }
    }
    // TODO: compare the volume serial and file index on Windows too.
    if !opened.is_file() {
        return Err(format!("{} is not a regular file", f.display()));
    }
    let mut body = Vec::new();
    (&mut file).take(max + 1).read_to_end(&mut body).map_err(|e| e.to_string())?;
    if body.len() as u64 > max {
        return Err(format!("{} is over {max} bytes", f.display()));
    }
    Ok(body)
}

#[cfg(test)]
#[path = "local_tests.rs"]
mod tests;
