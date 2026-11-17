//! Compile a rules file and report what didn't compile; optionally scan files
//! with it and print `rule path` per match, the way `yara -r` does, so the
//! output can be compared with the reference implementation.
//!
//! ```text
//! cargo run --release --example yara_check -- RULES.yar [--strict] [--unanchored] [--categories] [PATH...]
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;
use wpantry_yara::{Compiler, ScanOptions, Syntax};

fn walk(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        let Ok(entries) = std::fs::read_dir(path) else { return };
        let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        entries.sort();
        for e in entries {
            walk(&e, out);
        }
    } else if path.is_file() {
        out.push(path.to_path_buf());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(rules_path) = args.first() else {
        eprintln!("usage: yara_check RULES.yar [--strict] [PATH...]");
        std::process::exit(2);
    };
    let syntax = if args.iter().any(|a| a == "--strict") { Syntax::Strict } else { Syntax::Relaxed };
    let src = std::fs::read_to_string(rules_path).expect("read rules");
    let t = Instant::now();
    let mut c = Compiler::new();
    let added = c.add_source("default", &src, syntax);
    let rules = c.build();
    eprintln!("compiled {added} rules, rejected {} in {:?}: {:?}", rules.rejected.len(), t.elapsed(), rules.stats());
    if args.iter().any(|a| a == "--unanchored") {
        for (rule, string) in rules.unanchored() {
            eprintln!("unanchored: {rule} ${string}");
        }
    }
    if args.iter().any(|a| a == "--categories") {
        let mut by: BTreeMap<(String, &str), usize> = BTreeMap::new();
        for r in rules.rules() {
            *by.entry((r.os.name().to_string(), r.category)).or_default() += 1;
        }
        for ((os, cat), n) in by {
            eprintln!("{n:6}  {os:8} {cat}");
        }
    }
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    for r in &rules.rejected {
        let msg = r.error.to_string();
        let msg = msg.split_once(": ").map_or(msg.clone(), |(_, m)| m.to_string());
        *reasons.entry(msg).or_default() += 1;
    }
    let mut reasons: Vec<_> = reasons.into_iter().collect();
    reasons.sort_by_key(|r| std::cmp::Reverse(r.1));
    for (msg, n) in reasons.iter().take(40) {
        eprintln!("{n:6}  {msg}");
    }
    let mut files = Vec::new();
    for p in args.iter().skip(1).filter(|a| !a.starts_with("--")) {
        walk(Path::new(p), &mut files);
    }
    let t = Instant::now();
    let mut bytes = 0;
    for f in &files {
        let Ok(data) = std::fs::read(f) else { continue };
        bytes += data.len();
        let name = f.file_name().map(|n| n.to_string_lossy().into_owned());
        let ext = f.extension().map(|e| format!(".{}", e.to_string_lossy()));
        let opts = ScanOptions {
            filename: name,
            filepath: Some(f.display().to_string()),
            extension: ext,
            ..Default::default()
        };
        for hit in rules.scan(&data, &opts).matches {
            println!("{} {}", hit.rule, f.display());
        }
    }
    if !files.is_empty() {
        eprintln!("scanned {} files, {} bytes in {:?}", files.len(), bytes, t.elapsed());
    }
}
