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
    assert!(got.refused.is_empty());
    assert_eq!(
        got.files,
        vec![Change { path: "src/main.rs".into(), sha: b.clone() }, Change { path: "run.sh".into(), sha: b.clone() }]
    );
    assert_eq!(parse_raw(b""), Listing::default());
}

#[test]
fn index_listings_keep_stage_zero_regular_files() {
    let a = "a".repeat(40);
    let ls = format!("100644 {a} 0\tsrc/a.rs\0100644 {a} 2\tconflict\0120000 {a} 0\tlink\0");
    assert_eq!(parse_ls(ls.as_bytes()).files, vec![Change { path: "src/a.rs".into(), sha: a.clone() }]);
}

#[test]
fn the_ignore_file_is_read_at_the_changes_version() {
    let git = Git { git: PathBuf::from("git"), top: PathBuf::from("/r"), prefix: String::new(), env: Vec::new() };
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
    let staged = secret("/r/.env", "aws-key", "AWS key", 3, true, None, &Changes::Staged);
    assert_eq!((staged.kind.as_str(), staged.status.as_str(), staged.location.as_str()), ("secret", "fail", "line 3"));
    assert!(staged.fix_cmd.contains("before committing"), "{}", staged.fix_cmd);
    let range = Changes::parse("main").unwrap();
    let low = secret("/r/a.txt", "generic", "Generic", 1, false, Some("base64".into()), &range);
    assert_eq!(low.status, "warn");
    assert!(low.note.contains("(base64-encoded), in the files changed since main"), "{}", low.note);
}

#[test]
fn only_paths_that_stay_under_a_folder_are_safe() {
    for p in ["a.txt", "web/package-lock.json", ".github/workflows/ci.yml", "a..b/c", ".gitignore", "x/.gitkeep"] {
        assert!(safe_path(p), "{p}");
    }
    for p in [
        "",
        "/etc/passwd",
        "../x",
        "a/../../x",
        "a/..",
        "./a",
        "a/./b",
        "a//b",
        "a/",
        ".git/config",
        "sub/.GIT/hooks/pre-commit",
        ".Git",
        "a\0b",
    ] {
        assert!(!safe_path(p), "{p:?}");
    }
}

#[test]
fn windows_names_refuse_separators_devices_and_trailing_dots() {
    for c in ["a.txt", "console.log", "COM", "LPT10", "nul-ish"] {
        assert!(windows_name(c), "{c}");
    }
    for c in [
        "..\\x", "a\\b", "C:", "a:stream", "CON", "nul.txt", "Aux", "com1", "LPT9.log", "dot.", "space ", ".git.",
        "a\u{1}",
    ] {
        assert!(!windows_name(c), "{c:?}");
    }
}

#[test]
fn a_refused_path_is_listed_never_kept_as_a_file() {
    let b = "b".repeat(40);
    let z = "0".repeat(40);
    let raw = format!(
        ":000000 100644 {z} {b} A\0../package-lock.json\0:000000 100644 {z} {b} A\0.git/hooks/post-checkout\0:000000 100644 {z} {b} A\0ok.txt\0"
    );
    let got = parse_raw(raw.as_bytes());
    assert_eq!(got.files, vec![Change { path: "ok.txt".into(), sha: b.clone() }]);
    assert_eq!(got.refused, ["\"../package-lock.json\"", "\".git/hooks/post-checkout\""]);
    let mut bad = b"100644 ".to_vec();
    bad.extend(format!("{b} 0\t").as_bytes());
    bad.extend([0xff, b'x']);
    let got = parse_ls(&bad);
    assert!(got.files.is_empty());
    assert_eq!(got.refused.len(), 1, "a name that isn't UTF-8 can't be named faithfully");
}

#[test]
fn a_label_is_the_repo_path_with_slashes_on_every_system() {
    assert_eq!(label(Path::new("/code/app"), "web/a.txt"), "/code/app/web/a.txt");
    assert_eq!(label(Path::new("/"), "a.txt"), "/a.txt");
    // A canonical Windows top: the verbatim prefix gone, `/` throughout,
    // as `relocate` names the dependency findings.
    assert_eq!(label(Path::new(r"\\?\C:\Users\r\app"), "web/a.txt"), "C:/Users/r/app/web/a.txt");
    assert_eq!(label(Path::new(r"C:\Users\r\app\"), "key.ini"), "C:/Users/r/app/key.ini");
    // A canonical Windows temp folder, in each spelling a finding carries.
    let mut f = Finding {
        location: "C:/T/w/web/package-lock.json".into(),
        note: r"read C:\T\w\web\package-lock.json".into(),
        fix_cmd: "cd C:/T/w/web && npm install minimist@1.2.6".into(),
        component: r"\\?\C:\T\w\web\package-lock.json".into(),
        ..Default::default()
    };
    relocate_from(&mut f, r"\\?\C:\T\w", r"\\?\C:\Users\r\app");
    assert_eq!(f.location, "C:/Users/r/app/web/package-lock.json");
    assert_eq!(f.note, r"read C:\Users\r\app\web\package-lock.json");
    assert_eq!(f.fix_cmd, "cd C:/Users/r/app/web && npm install minimist@1.2.6");
    assert_eq!(f.component, r"C:\Users\r\app\web\package-lock.json");
}
