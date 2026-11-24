//! Sources on this machine (`path = "..."`) and `--add-sources FILE`
//! (specs/design/sources-file.md, specs/cli-contract.md), from the outside:
//! the built binary with a temp HOME and cache, `--offline --no-input`, so
//! nothing is fetched and nothing can be asked. The oracle is the scan's
//! JSON (a finding on the file a list or rule names) and its exit code.
//!
//!     cargo test -p wpantry-cli --test local_sources

mod common;

use common::*;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// A script a repo scan reads for malware (its `#!` line makes it a
/// program), and the text the team's rule looks for.
const MARKED: &str = "#!/bin/sh\necho team-marker-7f3a\n";
/// A script whose SHA-256 the team's list names.
const LISTED: &str = "#!/bin/sh\necho listed-by-hash\n";
const RULE: &str = "rule Team_Marker { strings: $a = \"team-marker-7f3a\" condition: $a }\n";

/// A temp HOME with a repo holding both scripts, a hash list naming one and
/// a rules folder matching the other, all outside the repo.
struct Setup {
    t: Ctx,
    repo: PathBuf,
    list: PathBuf,
    rules: PathBuf,
}

fn setup() -> Setup {
    let t = Ctx::new();
    let repo = git_repo(&t.home.join("work/repo"), false);
    write(&repo.join("marked.sh"), MARKED);
    write(&repo.join("listed.sh"), LISTED);
    let list = t.home.join("lists/bad-hashes.txt");
    mkdir(list.parent().unwrap());
    write(&list, format!("# the team's list\n{}\n", wpantry::utils::sha256::hex(LISTED.as_bytes())));
    let rules = t.home.join("team-rules");
    mkdir(&rules);
    write(&rules.join("marker.yar"), RULE);
    Setup { t, repo, list, rules }
}

/// One local source entry, its path a TOML literal string.
fn entry(id: &str, kind: &str, format: &str, path: &Path, extra: &str) -> String {
    format!(
        "[[source]]\nid = \"{id}\"\nkind = \"{kind}\"\nformat = \"{format}\"\npath = '{}'\n{extra}\n",
        path.display()
    )
}

fn scan(x: &Setup, extra: &[&str]) -> Out {
    let mut argv = vec!["scan", "--json", "--no-input", "--offline", "--no-machine", "--path", s(&x.repo)];
    argv.extend_from_slice(extra);
    x.t.run(&argv)
}

/// The (vuln_id, file name) of each malware finding.
fn hits(env: &Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = of_kind(env, "malware")
        .iter()
        .map(|f| {
            let file = str_(&f["component"]).rsplit(['/', '\\']).next().unwrap().to_string();
            (str_(&f["vuln_id"]).to_string(), file)
        })
        .collect();
    out.sort();
    out
}

fn unchecked(env: &Value) -> Vec<String> {
    of_kind(env, "unchecked").iter().map(|f| format!("{}: {}", str_(&f["component"]), str_(&f["note"]))).collect()
}

/// Whether a hash-list hit on `file` is among `hits`.
fn listed(hits: &[(String, String)], file: &str) -> bool {
    hits.iter().any(|(id, f)| id.starts_with("Hash_IOC_User_") && f == file)
}

fn marked(hits: &[(String, String)]) -> bool {
    hits.iter().any(|(id, f)| id == "Team_Marker" && f == "marked.sh")
}

/// Risk: a source on this machine is skipped where it matters most (an
/// offline machine, a program running wpantry with `--no-input`), or read
/// but never reaches the checks. Oracle: a finding on the script whose
/// SHA-256 the local list names and one on the script the local rules
/// folder's rule matches, from the person's own sources file, with no
/// question asked and nothing reported unchecked about either source.
#[test]
fn a_local_list_and_rules_folder_flag_files_offline_and_without_asking() {
    let x = setup();
    let config = x.t.home.join(".config/wpantry");
    mkdir(&config);
    write(
        &config.join("sources.toml"),
        entry("team-hashes", "hashes", "lines", &x.list, "")
            + &entry("team-rules", "yara", "yara", &x.rules, "")
            + "[[source]]\nid = \"team-home\"\nkind = \"hosts\"\nformat = \"lines\"\npath = \"~/lists/hosts.txt\"\n",
    );
    write(&x.t.home.join("lists/hosts.txt"), "bad-c2.example\n");
    let r = scan(&x, &[]);
    assert_eq!(r.code, 1, "{}", r.err);
    let env = r.json();
    let got = hits(&env);
    assert!(listed(&got, "listed.sh"), "the local hash list: {got:?}");
    assert!(marked(&got), "the local rules folder: {got:?}");
    let missed = unchecked(&env);
    assert!(!missed.iter().any(|m| m.contains("team-")), "{missed:?}");
}

/// Risk: `--add-sources` replaces the person's own file instead of adding
/// to it, or is ignored. Oracle: the person's file (`--sources`) holds the
/// hash list and the added file the rules folder; both findings appear.
/// The same id in both files, and an added file that isn't there, are
/// usage errors (exit 2) naming the id and both files, or the file.
#[test]
fn add_sources_adds_to_the_persons_file_and_an_id_is_defined_once() {
    let x = setup();
    let mine = x.t.home.join("mine.toml");
    write(&mine, entry("team-hashes", "hashes", "lines", &x.list, ""));
    let added = x.t.home.join("added.toml");
    write(
        &added,
        entry("team-rules", "yara", "yara", &x.rules, "") + "[[source]]\nid = \"cisa-kev\"\ntier = \"off\"\n",
    );
    let r = scan(&x, &["--sources", s(&mine), "--add-sources", s(&added)]);
    assert_eq!(r.code, 1, "{}", r.err);
    let got = hits(&r.json());
    assert!(listed(&got, "listed.sh") && marked(&got), "both files' sources: {got:?}");
    // `sources` lists both, the added file's tier for a bundled source too.
    let r = x.t.run(&["sources", "--json", "--sources", s(&mine), "--add-sources", s(&added)]);
    assert_eq!(r.code, 0, "{}", r.err);
    let listed_ids: Vec<(String, String)> = arr(&r.json()["sources"])
        .iter()
        .map(|s| (str_(&s["id"]).to_string(), str_(&s["tier"]).to_string()))
        .filter(|(id, _)| id.starts_with("team-") || id == "cisa-kev")
        .collect();
    assert_eq!(listed_ids.len(), 3, "{listed_ids:?}");
    assert!(listed_ids.contains(&("cisa-kev".into(), "off".into())), "{listed_ids:?}");
    // The same id twice.
    let again = x.t.home.join("again.toml");
    write(&again, entry("team-hashes", "hashes", "lines", &x.list, ""));
    for argv in
        [vec!["scan", "--json", "--no-input", "--offline", "--no-machine", "--path", s(&x.repo)], vec!["sources"]]
    {
        let mut argv = argv;
        argv.extend(["--sources", s(&mine), "--add-sources", s(&again)]);
        let r = x.t.run(&argv);
        assert_eq!(r.code, 2, "{argv:?}: {}", r.out);
        assert!(r.err.contains("\"team-hashes\"") && r.err.contains("your sources file"), "{}", r.err);
        assert!(r.err.contains("again.toml"), "{}", r.err);
    }
    // An added file that isn't there.
    let missing = x.t.home.join("missing.toml");
    for argv in [vec!["scan", "--no-input", "--offline", "--no-machine", "--path", s(&x.repo)], vec!["sources"]] {
        let mut argv = argv;
        argv.extend(["--add-sources", s(&missing)]);
        let r = x.t.run(&argv);
        assert_eq!(r.code, 2, "{argv:?}: {}", r.out);
        assert!(r.err.contains("missing.toml"), "{}", r.err);
    }
    // An added file beside no file of the person's own: still added.
    let r = scan(&x, &["--add-sources", s(&added)]);
    assert_eq!(r.code, 1, "{}", r.err);
    let got = hits(&r.json());
    assert!(marked(&got) && !listed(&got, "listed.sh"), "{got:?}");
}

/// Risk: a local source the person turned off (`tier = "off"`), or kept for
/// `--deep`, is still used, since a local source needs no yes. Oracle: no
/// finding from it on a default scan; the deep one is used with `--deep`.
#[test]
fn a_local_source_turned_off_or_kept_for_deep_is_not_used() {
    let x = setup();
    let mine = x.t.home.join("mine.toml");
    write(
        &mine,
        entry("team-hashes", "hashes", "lines", &x.list, "tier = \"off\"")
            + &entry("team-rules", "yara", "yara", &x.rules, "tier = \"deep\""),
    );
    let r = scan(&x, &["--sources", s(&mine)]);
    let got = hits(&r.json());
    assert!(!listed(&got, "listed.sh") && !marked(&got), "{got:?}: {}", r.err);
    let r = scan(&x, &["--sources", s(&mine), "--deep"]);
    let got = hits(&r.json());
    assert!(marked(&got) && !listed(&got, "listed.sh"), "{got:?}: {}", r.err);
    // And a default scan after the deep one still leaves the kept copy out.
    let r = scan(&x, &["--sources", s(&mine)]);
    let got = hits(&r.json());
    assert!(!marked(&got), "{got:?}");
}

/// Risk: a relative path or one with `..` is read from wherever wpantry
/// runs. Oracle: a usage error naming the source, before anything is read.
#[test]
fn a_relative_path_is_a_usage_error_naming_the_source() {
    let x = setup();
    let mine = x.t.home.join("mine.toml");
    for path in ["lists/bad-hashes.txt", "/tmp/../etc/hosts", ""] {
        write(
            &mine,
            format!("[[source]]\nid = \"team-hashes\"\nkind = \"hashes\"\nformat = \"lines\"\npath = \"{path}\"\n"),
        );
        let r = x.t.run(&["sources", "--sources", s(&mine)]);
        assert_eq!(r.code, 2, "{path}: {}", r.out);
        assert!(r.err.contains("\"team-hashes\""), "{path}: {}", r.err);
    }
}
