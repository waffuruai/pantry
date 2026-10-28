//! The Rust catalog (src/catalog.rs) says what python/wscanner/catalog.py
//! says, while python/ exists. Skipped without python/ or python3.

use std::path::Path;
use std::process::Command;
use wpantry::catalog::{Cycle, TOOLS};

const DUMP: &str = r#"
import json, sys
sys.path.insert(0, sys.argv[1])
from wscanner import catalog as c
print(json.dumps([[t.name, t.kind, list(t.bins), list(t.args), t.pattern, list(t.osv) or None,
                   [t.eol[0], t.eol[1].__name__] if t.eol else None, t.always, list(t.paths), t.fix] for t in c.TOOLS]))
"#;

#[test]
fn catalog_matches_python() {
    let python = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../python");
    if !python.is_dir() {
        return;
    }
    let Ok(out) = Command::new("python3").args(["-I", "-c", DUMP]).arg(&python).output() else { return };
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let want: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let got: Vec<serde_json::Value> = TOOLS
        .iter()
        .map(|t| {
            serde_json::json!([
                t.name,
                t.kind,
                t.bins,
                t.args,
                t.pattern,
                t.osv.map(|(e, p, f)| vec![e, p, f]),
                t.eol.map(|(p, c)| vec![
                    p,
                    match c {
                        Cycle::Major => "major",
                        Cycle::Minor => "minor",
                        Cycle::Java => "java",
                    }
                ]),
                t.always,
                t.paths,
                t.fix
            ])
        })
        .collect();
    assert_eq!(serde_json::Value::Array(got), want, "regenerate src/catalog.rs from python/wscanner/catalog.py");
}
