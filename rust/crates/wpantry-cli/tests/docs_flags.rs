//! The user docs name only real wpantry commands and flags: every `wpantry`
//! command and `--flag` in docs/public/*.md and desktop/README.md is checked
//! against the built binary's own `--help` (tests/docs/mod.rs has the
//! rules). A renamed or removed flag fails here as long as the docs still
//! name it. The other tests run the same checker against fixed help text,
//! including a known-bad case.
//!
//!     cargo test -p wpantry-cli --test docs_flags

mod common;
mod docs;

use common::BIN;
use docs::{Cli, check, mentions};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// docs/public/*.md in name order, then desktop/README.md, as (repo-relative
/// name, text).
fn user_docs() -> Vec<(String, String)> {
    let root = root();
    let mut names: Vec<String> = std::fs::read_dir(root.join("docs/public"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".md"))
        .collect();
    names.sort();
    let mut docs: Vec<String> = names.into_iter().map(|n| format!("docs/public/{n}")).collect();
    docs.push("desktop/README.md".to_string());
    docs.into_iter()
        .map(|name| {
            let text = std::fs::read_to_string(root.join(&name)).unwrap_or_else(|e| panic!("{name}: {e}"));
            (name, text)
        })
        .collect()
}

/// `wpantry <path> --help` from the built binary: its stdout, or None when
/// it exits non-zero.
fn real_help(path: &[String]) -> Option<String> {
    let out = Command::new(BIN)
        .args(path)
        .arg("--help")
        .env("WPANTRY_NO_UPDATE_CHECK", "1")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn user_docs_name_only_real_commands_and_flags() {
    let docs = user_docs();
    assert!(docs.len() > 5, "found the docs");
    let mut cli = Cli::new(real_help);
    let problems = check(&mut cli, &docs);
    assert!(
        problems.is_empty(),
        "{} doc mention(s) do not match `wpantry --help`:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// A stand-in scanner's help, by subcommand path.
fn fake_help() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        (
            "",
            "Usage: wpantry [options] [command]\n\nOptions:\n  -h, --help  print this help\n\n\
             Commands:\n  scan [options]  Scan\n  schedule <command>  Schedule\n",
        ),
        ("scan", "Usage: wpantry scan [options]\n\nOptions:\n  --json  JSON\n  --no-personal-files  skip\n"),
        ("schedule", "Usage: wpantry schedule <command>\n\nCommands:\n  status [options]  Status\n  run  Run\n"),
        ("schedule status", "Usage: wpantry schedule status [options]\n\nOptions:\n  --json  JSON\n"),
        ("schedule run", "Usage: wpantry schedule run\n"),
    ])
}

fn fake_check(text: &str) -> Vec<String> {
    let help = fake_help();
    let mut cli = Cli::new(move |path: &[String]| help.get(path.join(" ").as_str()).map(|t| t.to_string()));
    check(&mut cli, &[("doc.md".to_string(), text.to_string())])
}

#[test]
fn real_commands_and_flags_pass() {
    let doc = "Run `wpantry scan --json` or `wpantry schedule status --json`.\n\n\
               ```bash\nwpantry schedule run\nwpantry scan ~/code --no-personal-files\n```\n\
               With `wpantry scan`, `--no-personal-files` skips folders.\n\
               Pantry Setup takes `--install-only`; `cargo install --locked` is cargo's.\n";
    assert_eq!(fake_check(doc), Vec::<String>::new());
}

#[test]
fn known_bad_flags_and_commands_fail() {
    // Known bad: a flag scan never had, a flag from another subcommand, a
    // command that does not exist, and a bare flag nobody has.
    let doc = "`wpantry scan --fix`\n\
               `wpantry schedule run --json`\n\
               `wpantry frobnicate`\n\
               With `wpantry scan`, `--made-up` does things.\n";
    let problems = fake_check(doc);
    assert_eq!(problems.len(), 4, "{problems:?}");
    assert!(problems[0].contains("`wpantry scan` has no --fix"), "{problems:?}");
    assert!(problems[1].contains("`wpantry schedule run` has no --json"), "{problems:?}");
    assert!(problems[2].contains("`wpantry frobnicate` is not a command"), "{problems:?}");
    assert!(problems[3].contains("--made-up is not"), "{problems:?}");
    assert!(problems[0].starts_with("doc.md:1: "), "{problems:?}");
}

#[test]
fn arguments_are_not_taken_for_commands() {
    let commands: BTreeSet<String> = ["scan", "schedule"].iter().map(|s| s.to_string()).collect();
    let found = mentions("`wpantry scan ~/code --json`", "x.md", &commands);
    assert_eq!(found[0].path, ["scan"]);
    assert_eq!(found[0].flags, ["--json"]);
}

#[test]
fn a_help_without_commands_is_a_problem() {
    let mut cli = Cli::new(|_: &[String]| Some("Usage: wpantry\n".to_string()));
    assert_eq!(check(&mut cli, &[]), ["wpantry --help listed no commands"]);
}
