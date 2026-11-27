use super::*;

#[test]
fn parses_staged_a_base_and_a_range() {
    assert_eq!(Changes::parse("staged"), Ok(Changes::Staged));
    assert_eq!(Changes::parse("main"), Ok(Changes::Range { base: "main".into(), head: "HEAD".into() }));
    assert_eq!(
        Changes::parse("origin/dev...feat/x"),
        Ok(Changes::Range { base: "origin/dev".into(), head: "feat/x".into() })
    );
    assert_eq!(Changes::parse("main..."), Ok(Changes::Range { base: "main".into(), head: "HEAD".into() }));
}

#[test]
fn refuses_two_dots_options_and_empty_refs() {
    assert!(Changes::parse("main..HEAD").unwrap_err().contains("three dots"));
    assert!(Changes::parse("--all").is_err());
    assert!(Changes::parse("").is_err());
    assert!(Changes::parse("...HEAD").is_err());
    assert!(Changes::parse("a...b...c").is_err());
}

#[test]
fn describes_what_it_scans() {
    assert_eq!(Changes::Staged.describe(), "staged files");
    assert_eq!(Changes::parse("main").unwrap().describe(), "files changed since main");
    assert_eq!(Changes::parse("a...b").unwrap().describe(), "files changed in a...b");
}

#[test]
fn raw_diffs_keep_the_regular_files_new_blobs() {
    let a = "a".repeat(40);
    let b = "b".repeat(40);
    let z = "0".repeat(40);
    let raw = format!(
        ":100644 100644 {a} {b} M\0src/main.rs\0:000000 100755 {z} {b} A\0run.sh\0:100644 120000 {a} {b} T\0link\0:000000 160000 {z} {b} A\0sub\0:100644 100644 {a} {z} M\0unmerged\0"
    );
    let got = parse_raw(raw.as_bytes());
    assert_eq!(
        got,
        vec![Change { path: "src/main.rs".into(), sha: b.clone() }, Change { path: "run.sh".into(), sha: b.clone() }]
    );
    assert!(parse_raw(b"").is_empty());
}

#[test]
fn index_listings_keep_stage_zero_regular_files() {
    let a = "a".repeat(40);
    let ls = format!("100644 {a} 0\tsrc/a.rs\0100644 {a} 2\tconflict\0120000 {a} 0\tlink\0");
    assert_eq!(parse_ls(ls.as_bytes()), vec![Change { path: "src/a.rs".into(), sha: a.clone() }]);
}

#[test]
fn the_ignore_file_is_read_at_the_changes_version() {
    let git = Git { top: PathBuf::from("/r"), prefix: String::new(), env: Vec::new() };
    assert_eq!(git.ignore_file(&Changes::Staged), ":.pantryignore");
    assert_eq!(git.ignore_file(&Changes::parse("main...topic").unwrap()), "topic:.pantryignore");
}

#[test]
fn dependency_files_are_lockfiles_outside_pruned_folders() {
    for p in ["Cargo.lock", "web/package-lock.json", "requirements-dev.txt", "app/build.gradle.kts", "go.mod"] {
        assert!(is_dependency(p), "{p}");
    }
    for p in ["README.md", "node_modules/x/package-lock.json", "vendor/Gemfile.lock", "src/lock.rs"] {
        assert!(!is_dependency(p), "{p}");
    }
    let c = |p: &str| Change { path: p.into(), sha: String::new() };
    assert!(touches_dependencies(&[c("a.rs"), c("Cargo.lock")]));
    assert!(!touches_dependencies(&[c("a.rs")]));
}

#[test]
fn findings_name_the_repo_not_the_temporary_copy() {
    let mut f = Finding {
        component: "/tmp/w-1/sub/Cargo.lock".into(),
        location: "/tmp/w-1/sub/Cargo.lock".into(),
        note: "in /private/tmp/w-1/sub".into(),
        fix_cmd: "cd /tmp/w-1/sub && cargo update -p zip --precise 9.0.5".into(),
        ..Default::default()
    };
    relocate(&mut f, &["/private/tmp/w-1", "/tmp/w-1"], "/code/my app");
    assert_eq!(f.component, "/code/my app/sub/Cargo.lock");
    assert_eq!(f.location, "/code/my app/sub/Cargo.lock");
    assert_eq!(f.note, "in /code/my app/sub");
    assert_eq!(f.fix_cmd, "cd '/code/my app/sub' && cargo update -p zip --precise 9.0.5");
}

#[test]
fn a_secret_says_how_to_take_it_out_of_the_change() {
    let staged = secret(Path::new("/r/.env"), "aws-key", "AWS key", 3, true, None, &Changes::Staged);
    assert_eq!((staged.kind.as_str(), staged.status.as_str(), staged.location.as_str()), ("secret", "fail", "line 3"));
    assert!(staged.fix_cmd.contains("before committing"), "{}", staged.fix_cmd);
    let range = Changes::parse("main").unwrap();
    let low = secret(Path::new("/r/a.txt"), "generic", "Generic", 1, false, Some("base64".into()), &range);
    assert_eq!(low.status, "warn");
    assert!(low.note.contains("(base64-encoded), in the files changed since main"), "{}", low.note);
}
