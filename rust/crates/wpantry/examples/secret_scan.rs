//! Scan files with the bundled secret rules and print each finding as
//! `path<TAB>rule<TAB>line<TAB>start col<TAB>end col<TAB>tags`, with the time
//! per file on stderr: for comparing with betterleaks' report on the same
//! files (`betterleaks dir … --report-format json`).
//!
//! ```text
//! cargo run --release -p wpantry --example secret_scan -- [--betterleaks-only] FILE...
//! ```
//!
//! `--betterleaks-only` leaves out Pantry's own filters, to compare like with like.

use std::time::Instant;
use wpantry::checks::secrets::{Scanner, rules::RuleSet};

fn main() {
    let t = Instant::now();
    let only = std::env::args().any(|a| a == "--betterleaks-only");
    let mut rules = RuleSet::load(&[]).expect("bundled rules compile");
    if only {
        rules.filters.retain(|f| !f.name.starts_with("Any_Secret_PantryFilter"));
    }
    let scanner = Scanner::new(rules);
    eprintln!("rules ready in {:?}", t.elapsed());
    for path in std::env::args().skip(1).filter(|a| !a.starts_with("--")) {
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("{path}: can't read");
            continue;
        };
        let t = Instant::now();
        let found = scanner.scan(&data, &path, None);
        let secs = t.elapsed().as_secs_f64();
        eprintln!("{path}: {} findings, {:.2} s, {:.1} MB/s", found.len(), secs, data.len() as f64 / 1e6 / secs);
        for f in found {
            println!("{path}\t{}\t{}\t{}\t{}\t{}", f.rule, f.start_line, f.start_col, f.end_col, f.tags.join(","));
        }
    }
}
