use super::*;
use crate::checks::Options;
use crate::checks::supply_chain::testing;
use crate::utils::net::Fake;
use crate::utils::temp::TempDir;
use std::process::Command;

/// Patterns every check shares, and the paths to try them on: the same
/// answers as `git check-ignore` gives for a .gitignore holding them.
const PATTERNS: &str = "\
*.log
!keep.log
build/
/root-only.txt
docs/**/*.md
a/**/b
vendor/**
!vendor/keep.txt
[bc]in/
\\#hash
foo?.txt
nested/dir/
**/deep/x
tmp/*
!tmp/keep/
trailing.txt
";

const PATHS: &[&str] = &[
    "app.log",
    "keep.log",
    "sub/app.log",
    "sub/keep.log",
    "build/out.o",
    "src/build/x.o",
    "root-only.txt",
    "sub/root-only.txt",
    "docs/a.md",
    "docs/x/y/z.md",
    "docs/a.txt",
    "a/x/y/b",
    "a/b/c",
    "vendor/lib.c",
    "vendor/keep.txt",
    "vendor/sub/keep.txt",
    "bin/tool",
    "cin/tool",
    "din/tool",
    "#hash",
    "foo1.txt",
    "foo12.txt",
    "nested/dir/f",
    "x/nested/dir/f",
    "p/deep/x",
    "deep/x",
    "tmp/x.txt",
    "tmp/keep/a.txt",
    "trailing.txt",
    "ok.txt",
];

fn git(dir: &Path, args: &[&str]) -> Option<std::process::Output> {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "core.ignorecase=false"])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir)
        .output()
        .ok()
}

#[test]
fn patterns_match_as_git_check_ignore_does() {
    let d = TempDir::new("ignore-git").unwrap();
    let root = d.path();
    if !git(root, &["init", "-q"]).is_some_and(|o| o.status.success()) {
        eprintln!("skipped: no git");
        return;
    }
    std::fs::write(root.join(".gitignore"), PATTERNS).unwrap();
    for p in PATHS {
        testing::write(root, p, "x");
    }
    let mut args = vec!["check-ignore", "--no-index", "--"];
    args.extend(PATHS);
    let out = git(root, &args).unwrap();
    let by_git: Vec<&str> = std::str::from_utf8(&out.stdout).unwrap().lines().collect();
    let ig = Ignore::parse(PATTERNS);
    assert!(ig.problems.is_empty(), "{:?}", ig.problems);
    for p in PATHS {
        assert_eq!(ig.skips("project", "X", p), by_git.contains(p), "{p}: git says {by_git:?}");
    }
    // A sanity check that git ignored some and kept some.
    assert!(by_git.len() > 10 && by_git.len() < PATHS.len() - 5, "{by_git:?}");
}

#[test]
fn sections_pick_the_check_and_the_rule() {
    let ig = Ignore::parse(
        "vendor/\n[secret]\ntests/fixtures/\n[secret github-pat]\nconfig/legacy.py\n\
         [project GHSA-aaaa-bbbb-cccc]\nexamples/package-lock.json\n[*]\ndist/\n",
    );
    assert!(ig.problems.is_empty(), "{:?}", ig.problems);
    assert!(ig.skips("project", "CVE-1", "vendor/x/package-lock.json"), "before any section: every check");
    assert!(ig.skips("secret", "jwt", "tests/fixtures/a.env"));
    assert!(!ig.skips("project", "CVE-1", "tests/fixtures/package-lock.json"), "[secret] is the secret check's");
    assert!(ig.skips("secret", "github-pat", "config/legacy.py"));
    assert!(!ig.skips("secret", "jwt", "config/legacy.py"), "one rule only");
    assert!(ig.skips("project", "ghsa-AAAA-bbbb-cccc", "examples/package-lock.json"), "ids ignore case");
    assert!(!ig.skips("project", "CVE-2", "examples/package-lock.json"));
    assert!(ig.skips("license", "GPL-3.0-only", "dist/a/b"), "[*] is every check again");
    assert!(ig.skips_kind("secret", "tests/fixtures/a.env"));
    assert!(!ig.skips_kind("secret", "config/legacy.py"), "other rules may still hit it");
    assert!(!ig.skips("secret", "jwt", ""), "no path, nothing to match");
}

#[test]
fn lines_it_cant_use_are_problems_and_change_nothing() {
    let ig = Ignore::parse("[secrets]\nall.env\n[secret a b]\nx\n[unchecked]\n!\n[Bb]uild/\n/\n# a comment\n\n");
    let lines: Vec<usize> = ig.problems.iter().map(|(n, _)| *n).collect();
    assert_eq!(lines, [1, 3, 5, 6, 8], "{:?}", ig.problems);
    assert!(ig.problems[0].1.contains("did you mean `secret`?"), "{}", ig.problems[0].1);
    assert!(!ig.skips("secret", "jwt", "all.env"), "patterns under a bad header apply to nothing");
    assert!(!ig.skips("secret", "jwt", "x"));
    // `[Bb]uild/` is a pattern, not a header; it sits under the bad `[unchecked]`.
    let ig = Ignore::parse("[Bb]uild/\n");
    assert!(ig.problems.is_empty() && ig.skips("project", "X", "Build/a") && ig.skips("project", "X", "build/a"));
}

#[test]
fn your_file_takes_absolute_and_home_paths() {
    let home = Path::new("/home/me");
    let ig = Ignore::parse_user("~/research/samples/\n[malware]\n/srv/quarantine/\n!~/research/samples/keep\n", home);
    assert!(ig.problems.is_empty(), "{:?}", ig.problems);
    assert!(ig.skips("secret", "jwt", "home/me/research/samples/a"));
    assert!(ig.skips("malware", "EICAR", "srv/quarantine/x.bin"));
    assert!(!ig.skips("secret", "jwt", "srv/quarantine/x.bin"));
    assert!(!ig.skips("malware", "EICAR", "home/other/research/samples/a"));
}

#[test]
fn a_scan_leaves_out_what_the_files_skip() {
    let d = TempDir::new("ignore-apply").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d, Options::default());
    let (name, root) = testing::repo(&d, "app");
    let (inner, inner_root) = testing::repo(&d, "app/nested");
    testing::write(&root, FILE, "vendor/\n[malware]\nevil.js\n[secret]\ncfg.env\n[secrets]\nx\n");
    s.repos = vec![(name.clone(), root.clone()), (inner.clone(), inner_root.clone())];
    let at = |kind: &str, component: String, location: String| Finding {
        kind: kind.into(),
        component,
        location,
        vuln_id: "ID".into(),
        status: "fail".into(),
        ..Default::default()
    };
    let lock = root.join("vendor/package-lock.json").to_string_lossy().into_owned();
    s.findings = vec![
        at("secret", format!("{name}/cfg.env"), "line 2, commit 0123456789ab".into()),
        at("project", "left-pad".into(), lock),
        at("malware", short(&root.join("evil.js").to_string_lossy()), String::new()),
        at("suspect-code", format!("{name}/vendor/x.js"), "line 1".into()),
        at("secret", format!("{inner}/cfg.env"), "line 1, commit 0123456789ab".into()),
        at("unchecked", format!("{name}/vendor/a"), String::new()),
    ];
    let user = d.path().join("user-ignore");
    apply_with(&mut s, &user);
    let kept: Vec<(&str, &str)> = s.findings.iter().map(|f| (f.kind.as_str(), f.component.as_str())).collect();
    let file = format!("{name}/{FILE}");
    assert_eq!(
        kept,
        [
            ("malware", short(&root.join("evil.js").to_string_lossy()).as_str()),
            ("suspect-code", format!("{name}/vendor/x.js").as_str()),
            ("secret", format!("{inner}/cfg.env").as_str()),
            ("unchecked", format!("{name}/vendor/a").as_str()),
            ("config", file.as_str()),
            ("config", file.as_str()),
        ],
        "the repo's file can't skip malware or suspect code; a nested repo's file isn't its parent's"
    );
    let ids: Vec<(&str, &str)> = s.findings[4..].iter().map(|f| (f.vuln_id.as_str(), f.location.as_str())).collect();
    assert_eq!(ids, [("IGNORE-FILE", "line 6"), ("IGNORE-PROTECTED", "line 2")]);
    assert!(s.counts.contains(&("findings skipped by a repo's .pantryignore".to_string(), 2)), "{:?}", s.counts);
    // Your own file can skip malware.
    std::fs::write(&user, format!("[malware]\n{}\n", root.join("evil.js").to_string_lossy().replace('\\', "/")))
        .unwrap();
    s.findings.retain(|f| f.kind != "config");
    apply_with(&mut s, &user);
    assert!(s.findings.iter().all(|f| f.kind != "malware"), "{:?}", s.findings);
    assert!(s.counts.contains(&("findings skipped by your ignore file".to_string(), 1)), "{:?}", s.counts);
}

#[test]
fn no_files_leave_the_findings_alone() {
    let d = TempDir::new("ignore-none").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d, Options::default());
    s.repos = vec![testing::repo(&d, "app")];
    s.findings = vec![Finding { kind: "secret".into(), component: "app/cfg.env".into(), ..Default::default() }];
    apply_with(&mut s, &d.path().join("none"));
    assert_eq!(s.findings.len(), 1);
    assert!(s.counts.iter().all(|(k, _)| !k.contains("skipped")), "{:?}", s.counts);
}

#[test]
fn globs_and_classes() {
    assert!(glob("a*c", "abbbc") && glob("a*c", "ac") && !glob("a*c", "ab"));
    assert!(glob("f?o", "foo") && !glob("f?o", "fo"));
    assert!(glob("[a-c]x", "bx") && !glob("[!a-c]x", "bx") && glob("[^a-c]x", "dx"));
    assert!(glob("[]]x", "]x"), "a leading ] is a character");
    assert!(glob("[x", "[x"), "an unclosed [ is a character");
    assert!(glob("\\*", "*") && !glob("\\*", "a"));
    assert!(glob("***", "anything"));
}

#[test]
fn a_repo_cant_hide_what_threatens_you_whatever_its_check() {
    let d = TempDir::new("ignore-protected").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d, Options::default());
    let (name, root) = testing::repo(&d, "app");
    // Everything, for every check, and each protected check by name.
    testing::write(&root, FILE, "*\n[document]\n*\n[mcp]\n*\n[install-script]\n*\n");
    s.repos = vec![(name.clone(), root.clone())];
    let lock = format!("{name}/package-lock.json");
    let f = |kind: &str, id: &str, severity: &str, kev: bool| Finding {
        kind: kind.into(),
        component: lock.clone(),
        vuln_id: id.into(),
        severity: severity.into(),
        kev,
        status: "fail".into(),
        ..Default::default()
    };
    s.findings = vec![
        f("project", "MAL-2026-1", "MALICIOUS", false),
        f("project", "GHSA-x", "HIGH", true),
        f("document", "MALWARE", "", false),
        f("mcp", "UNPINNED", "", false),
        f("install-script", "CURL-BASH", "", false),
        f("secret", "REPO-POLICY", "", false),
        f("project", "GHSA-ordinary", "LOW", false),
    ];
    apply_with(&mut s, &d.path().join("no-user-file"));
    let kept: Vec<&str> = s.findings.iter().filter(|f| f.kind != "config").map(|f| f.vuln_id.as_str()).collect();
    assert_eq!(
        kept,
        ["MAL-2026-1", "GHSA-x", "MALWARE", "UNPINNED", "CURL-BASH", "REPO-POLICY"],
        "only the ordinary one goes"
    );
    let protected: Vec<&str> =
        s.findings.iter().filter(|f| f.vuln_id == "IGNORE-PROTECTED").map(|f| f.location.as_str()).collect();
    assert_eq!(protected, ["line 2", "line 4", "line 6"]);
}

#[test]
fn hostile_patterns_match_in_bounded_time() {
    let start = std::time::Instant::now();
    let name = "a".repeat(60);
    assert!(!glob(&format!("{}b", "*a".repeat(40)), &name));
    let deep: Vec<String> = (0..40).map(|i| format!("d{i}")).collect();
    let deep: Vec<&str> = deep.iter().map(String::as_str).collect();
    let stars: Vec<String> = std::iter::repeat_n("**".to_string(), 40).chain(["nope".to_string()]).collect();
    assert!(!matches(&stars, &deep));
    assert!(start.elapsed() < std::time::Duration::from_secs(1), "took {:?}", start.elapsed());
}

#[cfg(unix)]
#[test]
fn a_repos_file_is_read_only_when_its_a_regular_file() {
    let d = TempDir::new("ignore-link").unwrap();
    std::fs::write(d.path().join("elsewhere"), "*\n").unwrap();
    let link = d.path().join(FILE);
    std::os::unix::fs::symlink(d.path().join("elsewhere"), &link).unwrap();
    assert!(matches!(Ignore::load(&link), Some(Err(_))), "a link isn't followed");
    assert!(Ignore::load(&d.path().join("missing")).is_none());
}
