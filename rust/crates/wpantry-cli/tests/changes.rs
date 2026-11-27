//! `scan project --changes`: only what a commit or pull request adds,
//! read from git and never kept (specs/cli-contract.md). Each test builds
//! a real repo with the git on PATH; the secrets are put together at run
//! time, so no secret-shaped string sits in this file.
//!
//!     cargo test -p wpantry-cli --test changes [--release]

mod common;

use common::*;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;

fn have_git() -> bool {
    Command::new("git").arg("--version").output().is_ok_and(|o| o.status.success())
}

macro_rules! need_git {
    () => {
        if !have_git() {
            eprintln!("skipped: no git");
            return;
        }
    };
}

/// An AWS key pair, the shape a high-confidence rule fails on.
fn aws_pair() -> String {
    let id = ["AK", "IA", "QWERTYUIOPASDFGH"].concat();
    let secret = ["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCY", "EXAMPLEKEY"].concat();
    format!("aws_access_key_id = {id}\naws_secret_access_key = {secret}\n")
}

/// A repo under the test's home, its git isolated from the machine's
/// config and hooks.
struct Repo {
    dir: PathBuf,
    home: PathBuf,
}

impl Repo {
    fn new(t: &Ctx, name: &str) -> Repo {
        let dir = t.home.join(name);
        mkdir(&dir);
        let r = Repo { dir, home: t.home.clone() };
        r.git(&["init", "-q", "-b", "main"]);
        r.git(&["commit", "-q", "--allow-empty", "-m", "init"]);
        r
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new("git");
        c.current_dir(&self.dir)
            .args(["-c", "core.hooksPath=/dev/null", "-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(["-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"])
            .args(args)
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null");
        for k in ["GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY"] {
            c.env_remove(k);
        }
        c
    }

    fn git(&self, args: &[&str]) -> String {
        let o = self.cmd(args).output().unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    fn put(&self, path: &str, text: impl AsRef<[u8]>) {
        let p = self.dir.join(path);
        if let Some(d) = p.parent() {
            mkdir(d);
        }
        write(&p, text);
    }

    fn commit(&self, paths: &[&str], msg: &str) {
        let mut add = vec!["add", "--"];
        add.extend(paths);
        self.git(&add);
        self.git(&["commit", "-q", "-m", msg]);
    }
}

/// `scan project --changes SPEC DIR` with more flags; offline unless `online`.
fn changes(t: &Ctx, dir: &Path, spec: &str, extra: &[&str], env: &[(&str, &str)]) -> Out {
    let mut argv = vec!["scan", "project", "--changes", spec, "--no-input"];
    argv.extend_from_slice(extra);
    argv.push(s(dir));
    t.run_env(&argv, env)
}

fn offline(t: &Ctx, dir: &Path, spec: &str) -> Out {
    changes(t, dir, spec, &["--offline", "--json"], &[])
}

fn secrets(env: &Value) -> Vec<String> {
    of_kind(env, "secret").iter().map(|f| str_(&f["component"]).rsplit('/').next().unwrap().to_string()).collect()
}

#[test]
fn a_staged_secret_fails_and_one_unstaged_or_untouched_does_not() {
    need_git!();
    let t = Ctx::new();
    let r = Repo::new(&t, "app");
    // Committed before: in a file the change doesn't touch.
    r.put("old.ini", aws_pair());
    r.put("notes.txt", "hello\n");
    r.commit(&["old.ini", "notes.txt"], "before");

    // Staged: a clean edit; the working tree has a secret on top of it.
    r.put("notes.txt", "hello again\n");
    r.git(&["add", "notes.txt"]);
    r.put("notes.txt", format!("hello again\n{}", aws_pair()));
    let out = offline(&t, &r.dir, "staged");
    assert_eq!(out.code, 0, "{}{}", out.out, out.err);
    let env = envelope(&out.out);
    assert!(secrets(&env).is_empty(), "{}", env["findings"]);
    assert_eq!(env["checked"]["staged files"], 1, "{}", env["checked"]);

    // Staged with the secret: it fails, at the repo's path and line.
    r.git(&["add", "notes.txt"]);
    let out = offline(&t, &r.dir, "staged");
    assert_eq!(out.code, 1, "{}{}", out.out, out.err);
    let env = envelope(&out.out);
    assert_eq!(secrets(&env), ["notes.txt"], "{}", env["findings"]);
    let f = of_kind(&env, "secret")[0];
    assert_eq!(f["status"], "fail");
    assert_eq!(f["location"], "line 2");
}

#[test]
fn the_scan_reads_the_index_git_index_file_names() {
    need_git!();
    let t = Ctx::new();
    let r = Repo::new(&t, "app");
    r.put("a.txt", "fine\n");
    r.commit(&["a.txt"], "a");
    // A temporary index with a secret staged, as `git commit <paths>` makes
    // one; the real index stays clean.
    r.put("key.ini", aws_pair());
    let blob = r.git(&["hash-object", "-w", "key.ini"]);
    std::fs::remove_file(r.dir.join("key.ini")).unwrap();
    let index = t.tmp.join("next-index");
    let index_s = s(&index).to_string();
    let with_index = |args: &[&str]| {
        let o = r.cmd(args).env("GIT_INDEX_FILE", &index).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    with_index(&["read-tree", "HEAD"]);
    with_index(&["update-index", "--add", "--cacheinfo", &format!("100644,{},key.ini", blob.trim())]);

    let clean = offline(&t, &r.dir, "staged");
    assert_eq!(clean.code, 0, "{}{}", clean.out, clean.err);
    let out = changes(&t, &r.dir, "staged", &["--offline", "--json"], &[("GIT_INDEX_FILE", &index_s)]);
    assert_eq!(out.code, 1, "{}{}", out.out, out.err);
    assert_eq!(secrets(&envelope(&out.out)), ["key.ini"]);
}

#[test]
fn neither_the_index_nor_the_working_tree_is_written() {
    need_git!();
    let t = Ctx::new();
    let r = Repo::new(&t, "app");
    r.put("a.txt", "one\n");
    r.commit(&["a.txt"], "a");
    r.put("a.txt", "two\n");
    r.git(&["add", "a.txt"]);
    r.put("a.txt", "three\n");
    r.put("new.txt", "untracked\n");
    // `git status` refreshes the index itself: first, then the snapshot.
    let status = r.git(&["status", "--porcelain"]);
    let index = r.dir.join(".git/index");
    let before = (std::fs::read(&index).unwrap(), std::fs::metadata(&index).unwrap().modified().unwrap());
    let out = offline(&t, &r.dir, "staged");
    assert_eq!(out.code, 0, "{}", out.err);
    let after = (std::fs::read(&index).unwrap(), std::fs::metadata(&index).unwrap().modified().unwrap());
    assert!(before == after, "the index changed");
    assert_eq!(r.git(&["status", "--porcelain"]), status);
    assert_eq!(read(&r.dir.join("a.txt")), "three\n");
}

/// A cache holding OSV's answer for minimist 1.2.5 (fixed in 1.2.6).
fn seed(t: &Ctx) {
    let conn = Cache::new(t);
    let rec = json!({"id": "GHSA-m", "aliases": ["CVE-2026-7"], "summary": "minimist flaw",
                     "database_specific": {"severity": "MODERATE"},
                     "affected": [{"package": {"ecosystem": "npm", "name": "minimist"},
                                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.6"}]}]}]});
    insert_vuln(
        &conn.0,
        "INSERT",
        ["GHSA-m", "CVE-2026-7", "minimist flaw", "", "MODERATE", "", "", "", &rec.to_string()],
    );
    insert_query(&conn.0, "INSERT", "npm", "minimist", "1.2.5", now(), "GHSA-m");
}

/// The test's cache, its schema made by a run that reads nothing.
struct Cache(rusqlite::Connection);

impl Cache {
    fn new(t: &Ctx) -> Cache {
        let r = t.run(&["runs", "--json"]);
        assert_eq!(r.code, 0, "{}", r.err);
        Cache(t.conn())
    }
}

fn lockfile(version: &str) -> String {
    format!(
        r#"{{"lockfileVersion": 3, "packages": {{"": {{}}, "node_modules/minimist": {{"version": "{version}"}}}}}}"#
    )
}

#[test]
fn a_changed_lockfile_with_a_fixable_advisory_fails_and_an_unchanged_one_does_not() {
    need_git!();
    let t = Ctx::new();
    seed(&t);
    let r = Repo::new(&t, "app");
    r.put("README.md", "app\n");
    r.commit(&["README.md"], "base");
    r.git(&["checkout", "-q", "-b", "feature"]);
    r.put("web/package-lock.json", lockfile("1.2.5"));
    r.commit(&["web/package-lock.json"], "add a vulnerable lockfile");

    // The pull request adds it: a range, and a base alone.
    for spec in ["main...feature", "main...", "main"] {
        let out = offline(&t, &r.dir, spec);
        assert_eq!(out.code, 1, "{spec}: {}{}", out.out, out.err);
        let env = envelope(&out.out);
        let found = of_kind(&env, "project");
        assert_eq!(found.len(), 1, "{}", env["findings"]);
        assert_eq!(found[0]["component"], "minimist");
        assert_eq!(found[0]["fixed"], "1.2.6");
        // At the repo's path, not the temporary copy's.
        let at = str_(&found[0]["location"]);
        assert!(at.ends_with("/app/web/package-lock.json"), "{at}");
        assert!(str_(&found[0]["fix_cmd"]).contains("/app/web"), "{}", found[0]["fix_cmd"]);
    }

    // The next change leaves the lockfile alone: nothing to report.
    r.put("README.md", "app, documented\n");
    r.commit(&["README.md"], "docs");
    let out = offline(&t, &r.dir, "feature~1...feature");
    assert_eq!(out.code, 0, "{}{}", out.out, out.err);
    assert!(of_kind(&envelope(&out.out), "project").is_empty());
    r.put("README.md", "app, documented again\n");
    r.git(&["add", "README.md"]);
    assert_eq!(offline(&t, &r.dir, "staged").code, 0);

    // Staged, the fixed version clears it; the vulnerable one fails.
    r.put("web/package-lock.json", lockfile("1.2.6"));
    r.git(&["add", "web/package-lock.json"]);
    let out = offline(&t, &r.dir, "staged");
    assert_eq!(out.code, 0, "{}{}", out.out, out.err);
}

#[test]
fn nothing_is_kept_no_run_and_no_report_file() {
    need_git!();
    let t = Ctx::new();
    seed(&t);
    let r = Repo::new(&t, "app");
    r.put("package-lock.json", lockfile("1.2.5"));
    r.put("key.ini", aws_pair());
    r.git(&["add", "package-lock.json", "key.ini"]);
    let scans = |t: &Ctx| -> i64 { t.conn().query_row("SELECT count(*) FROM scans", [], |r| r.get(0)).unwrap() };
    let findings = |t: &Ctx| -> i64 { t.conn().query_row("SELECT count(*) FROM findings", [], |r| r.get(0)).unwrap() };
    let before = (scans(&t), findings(&t));
    for format in ["--txt", "--json", "--jsonl", "--csv", "--md", "--html"] {
        let mut argv = vec!["scan", "project", "--changes", "staged", "--offline", "--no-input", format];
        argv.push(".");
        let out = t.run_in(&r.dir, &argv);
        assert_eq!(out.code, 1, "{format}: {}{}", out.out, out.err);
        assert!(out.out.contains("minimist"), "{format}: {}", out.out);
    }
    assert_eq!((scans(&t), findings(&t)), before);
    let runs = t.run(&["runs", "--json"]);
    assert_eq!(runs.code, 0);
    assert!(arr(&runs.json()["runs"]).is_empty(), "{}", runs.out);
    let report = t.run(&["report", "--json"]);
    assert_eq!(report.code, 1, "no scan to report: {}", report.out);
    let written: Vec<String> = names(&r.dir).into_iter().filter(|n| n.starts_with("pantry_report")).collect();
    assert!(written.is_empty(), "{written:?}");
    // A report file is refused, not written.
    let out = changes(&t, &r.dir, "staged", &["--offline", "-o", s(&t.tmp.join("r.txt"))], &[]);
    assert_eq!(out.code, 2, "{}", out.err);
    assert!(!t.tmp.join("r.txt").exists());
}

#[test]
fn without_the_network_a_dependency_is_not_checked_and_a_secret_still_fails() {
    need_git!();
    let t = Ctx::new();
    let r = Repo::new(&t, "app");
    r.put("package-lock.json", lockfile("1.2.5"));
    r.git(&["add", "package-lock.json"]);
    // Online, every source refused (a proxy that isn't there), nothing cached.
    let dead = [("HTTPS_PROXY", "http://127.0.0.1:9"), ("ALL_PROXY", "http://127.0.0.1:9"), ("NO_PROXY", "")];
    for (extra, env) in [(vec!["--txt"], &dead[..]), (vec!["--txt", "--offline"], &[][..])] {
        let out = changes(&t, &r.dir, "staged", &extra, env);
        assert_eq!(out.code, 0, "{extra:?}: {}{}", out.out, out.err);
        assert!(out.out.contains("Not checked"), "{}", out.out);
        assert!(out.out.contains("repo dependencies against OSV"), "{}", out.out);
    }
    r.put("key.ini", aws_pair());
    r.git(&["add", "key.ini"]);
    let out = changes(&t, &r.dir, "staged", &["--txt"], &dead);
    assert_eq!(out.code, 1, "{}{}", out.out, out.err);
    assert!(out.out.contains("Not checked"), "{}", out.out);
}

#[test]
fn a_cache_that_cant_be_opened_is_said_and_the_scan_goes_on() {
    need_git!();
    let t = Ctx::new();
    let r = Repo::new(&t, "app");
    r.put("package-lock.json", lockfile("1.2.5"));
    r.put("key.ini", aws_pair());
    r.git(&["add", "package-lock.json", "key.ini"]);
    // The cache's folder is a file.
    write(&t.tmp.join("blocked"), "");
    let db = t.tmp.join("blocked/w.db");
    let out = changes(&t, &r.dir, "staged", &["--offline", "--json"], &[("WPANTRY_DB", s(&db))]);
    assert_eq!(out.code, 1, "{}{}", out.out, out.err);
    assert!(out.err.contains("can't be opened"), "{}", out.err);
    assert_eq!(secrets(&envelope(&out.out)), ["key.ini"]);
}

#[test]
fn the_ignore_file_applies_at_the_changes_version() {
    need_git!();
    let t = Ctx::new();
    let r = Repo::new(&t, "app");
    r.put("fixtures/key.ini", aws_pair());
    r.git(&["add", "fixtures/key.ini"]);
    // Only in the working tree: not what the commit records.
    r.put(".pantryignore", "[secret]\nfixtures/\n");
    assert_eq!(offline(&t, &r.dir, "staged").code, 1);
    r.git(&["add", ".pantryignore"]);
    let out = offline(&t, &r.dir, "staged");
    assert_eq!(out.code, 0, "{}{}", out.out, out.err);
    assert_eq!(envelope(&out.out)["checked"]["findings skipped by a repo's .pantryignore"], 1);
}

#[test]
fn deletions_add_nothing_and_renames_are_read() {
    need_git!();
    let t = Ctx::new();
    let r = Repo::new(&t, "app");
    r.put("key.ini", aws_pair());
    r.commit(&["key.ini"], "a secret");
    r.git(&["rm", "-q", "key.ini"]);
    assert_eq!(offline(&t, &r.dir, "staged").code, 0, "a deletion");
    r.git(&["reset", "-q", "--hard"]);
    r.git(&["mv", "key.ini", "moved.ini"]);
    let out = offline(&t, &r.dir, "staged");
    assert_eq!(out.code, 1, "a rename");
    assert_eq!(secrets(&envelope(&out.out)), ["moved.ini"]);
}

#[test]
fn a_folder_inside_the_repo_scans_only_its_changes() {
    need_git!();
    let t = Ctx::new();
    let r = Repo::new(&t, "app");
    r.put("web/a.txt", "fine\n");
    r.put("api/key.ini", aws_pair());
    r.git(&["add", "web", "api"]);
    assert_eq!(offline(&t, &r.dir.join("web"), "staged").code, 0);
    assert_eq!(offline(&t, &r.dir.join("api"), "staged").code, 1);
}

#[test]
fn the_first_commit_scans_everything_staged() {
    need_git!();
    let t = Ctx::new();
    let dir = t.home.join("fresh");
    mkdir(&dir);
    let r = Repo { dir, home: t.home.clone() };
    r.git(&["init", "-q", "-b", "main"]);
    r.put("key.ini", aws_pair());
    r.git(&["add", "key.ini"]);
    assert_eq!(offline(&t, &r.dir, "staged").code, 1);
}

/// `git ARGS` with `input` on stdin; its stdout, trimmed.
fn git_in(r: &Repo, args: &[&str], input: &str) -> String {
    use std::io::Write;
    let mut c = r.cmd(args);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(o.status.success(), "git {args:?}");
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

#[test]
fn a_path_out_of_the_repo_or_into_git_is_refused_and_never_written() {
    need_git!();
    let t = Ctx::new();
    let r = Repo::new(&t, "app");
    // A crafted tree, as a fork's pull request can carry: `..` and `.git`
    // entries, which git stores without fsck, each holding a lockfile.
    let blob = git_in(&r, &["hash-object", "-w", "--stdin"], &lockfile("1.2.5"));
    let sub = git_in(&r, &["mktree"], &format!("100644 blob {blob}\tpackage-lock.json\n"));
    let fine = git_in(&r, &["hash-object", "-w", "--stdin"], "fine\n");
    let top = git_in(
        &r,
        &["mktree"],
        &format!("040000 tree {sub}\t..\n040000 tree {sub}\t.git\n100644 blob {fine}\tok.txt\n"),
    );
    let head = git_in(&r, &["commit-tree", &top, "-p", "HEAD", "-m", "crafted"], "");
    let tmp = t.tmp.join("tmpdir");
    mkdir(&tmp);
    let out = changes(&t, &r.dir, &format!("HEAD...{head}"), &["--offline", "--json"], &[("TMPDIR", s(&tmp))]);
    assert_eq!(out.code, 1, "{}{}", out.out, out.err);
    let env = envelope(&out.out);
    let refused: Vec<&str> =
        arr(&env["findings"]).iter().filter(|f| f["vuln_id"] == "UNSAFE-PATH").map(|f| str_(&f["component"])).collect();
    assert_eq!(refused, ["\"../package-lock.json\"", "\".git/package-lock.json\""], "{}", env["findings"]);
    let gap = of_kind(&env, "unchecked");
    assert!(gap.iter().any(|f| f["component"] == "2 changed files with unsafe paths"), "{}", env["findings"]);
    assert!(of_kind(&env, "project").is_empty(), "nothing of the refused lockfiles was read");
    // Nothing was written outside the scan's own folder, which is gone.
    assert!(names(&tmp).is_empty(), "{:?}", names(&tmp));
    assert!(!r.dir.join(".git/package-lock.json").exists());
    assert!(!t.home.join("package-lock.json").exists());
}

#[test]
fn what_cant_be_read_is_a_usage_error() {
    need_git!();
    let t = Ctx::new();
    let r = Repo::new(&t, "app");
    let not_repo = t.tmp.join("plain");
    mkdir(&not_repo);
    let cases: Vec<(Out, &str)> = vec![
        (offline(&t, &not_repo, "staged"), "git repo"),
        (offline(&t, &r.dir, "no-such-branch"), "no commit 'no-such-branch'"),
        (offline(&t, &r.dir, "main..HEAD"), "three dots"),
        (changes(&t, &r.dir, "staged", &["--deep"], &[]), "--deep"),
        (changes(&t, &r.dir, "staged", &["--no-malware"], &[]), "--no-malware"),
    ];
    for (out, says) in cases {
        assert_eq!(out.code, 2, "{says}: {}{}", out.out, out.err);
        assert!(out.err.contains(says), "{says}: {}", out.err);
    }
}

/// Acceptance timings, on the release binary (`cargo test --release -p
/// wpantry-cli --test changes -- --ignored`): a small staged change in
/// under 1 s with the advisories cached, under 200 ms with no dependency
/// file in it.
#[test]
#[ignore]
fn timings() {
    need_git!();
    let t = Ctx::new();
    seed(&t);
    let r = Repo::new(&t, "app");
    r.put("src/main.rs", "fn main() {}\n");
    r.git(&["add", "src/main.rs"]);
    let best = |argv: &[&str]| {
        (0..5)
            .map(|_| {
                let start = std::time::Instant::now();
                let out = t.run(argv);
                assert!([0, 1].contains(&out.code), "{}", out.err);
                start.elapsed()
            })
            .min()
            .unwrap()
    };
    let argv = ["scan", "project", "--changes", "staged", "--offline", "--no-input", "--txt", s(&r.dir)];
    let plain = best(&argv);
    r.put("package-lock.json", lockfile("1.2.5"));
    r.git(&["add", "package-lock.json"]);
    let deps = best(&argv);
    eprintln!("no dependency file: {plain:?}; a lockfile, cached: {deps:?}");
    assert!(plain.as_millis() < 200, "{plain:?}");
    assert!(deps.as_millis() < 1000, "{deps:?}");
}
