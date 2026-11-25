//! The editing engine on handmade findings and temp folders. Risks and
//! oracles, per test: a rule that hides more than one finding (the real
//! filter, run over the other findings), a write that changes bytes it was
//! not asked to (the file's exact text before and after), a write through a
//! link that leaves the folder (what the target link points at), and a
//! repo hiding what protects its owner (the filter's own refusal).

use super::*;
use crate::utils::temp::TempDir;

fn env(d: &TempDir) -> Env {
    let home = d.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    Env { home: home.clone(), user_file: home.join(".config/wpantry/ignore") }
}

/// A folder with a `.git`.
fn repo(d: &TempDir, name: &str) -> PathBuf {
    let root = d.path().join(name);
    std::fs::create_dir_all(root.join(".git")).unwrap();
    root
}

fn found(kind: &str, component: &str, location: &str, id: &str) -> Finding {
    Finding {
        kind: kind.into(),
        component: component.into(),
        location: location.into(),
        vuln_id: id.into(),
        status: "fail".into(),
        ..Default::default()
    }
}

fn lock(root: &Path, rel: &str, pkg: &str, id: &str) -> Finding {
    found("project", pkg, &root.join(rel).to_string_lossy(), id)
}

fn req<'a>(f: &'a Finding, all: &'a [Finding], scope: Scope) -> Request<'a> {
    Request { finding: f, all, scope, all_places: false, reason: None, now: 1_800_000_000.0 }
}

fn wrote(a: Added) -> (Target, Vec<Written>, Vec<LeftOut>) {
    match a {
        Added::Wrote { target, rules, left_out } => (target, rules, left_out),
        Added::Already { .. } => panic!("expected a write, got already"),
    }
}

fn refused(r: Result<Added, Stop>) -> Refused {
    match r {
        Err(Stop::Refused(r)) => r,
        Err(Stop::Failed(e)) => panic!("failed: {e}"),
        Ok(a) => panic!("expected a refusal, got {a:?}"),
    }
}

fn text(t: &Target) -> String {
    std::fs::read_to_string(&t.file).unwrap()
}

#[test]
fn a_rule_is_appended_and_removed_leaving_every_other_byte_alone() {
    // Risk: the file changes anywhere but its end, or loses its line endings.
    // Oracle: the original text is a prefix after the add and equal after the remove.
    let d = TempDir::new("ie-bytes").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    let original = "# vendored code\r\nvendor/\r\n\r\n[secret]\r\n# fixtures\r\ntests/fixtures/\r\n";
    std::fs::write(root.join(FILE), original).unwrap();
    let f = found("secret", &root.join("cfg.env").to_string_lossy(), "line 2, commit 0123456789ab", "github-pat");
    let mut r = req(&f, std::slice::from_ref(&f), Scope::Repo);
    r.reason = Some("  revoked in 2025 ");
    let (t, rules, _) = wrote(add(&r, &e).unwrap());
    let now = std::fs::read_to_string(&t.file).unwrap();
    let block = format!(
        "\r\n[secret github-pat]\r\n/cfg.env\r\n# wpantry ignore: {} | 2027-01-15 08:00 UTC | revoked in 2025\r\n",
        f.id()
    );
    assert_eq!(now, format!("{original}{block}"), "appended in the file's own line ending, after a blank line");
    assert_eq!((rules[0].section.as_str(), rules[0].pattern.as_str()), ("secret github-pat", "/cfg.env"));
    let gone = remove(std::slice::from_ref(&t), Want::Finding(&f.id())).unwrap();
    assert_eq!(gone.len(), 1);
    assert_eq!(text(&t), original, "removing the block restores the file exactly");
}

#[test]
fn a_file_with_no_final_newline_gains_only_that_newline() {
    let d = TempDir::new("ie-nonl").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    std::fs::write(root.join(FILE), "vendor/").unwrap();
    let f = found("secret", &root.join("cfg.env").to_string_lossy(), "line 1", "jwt");
    let (t, ..) = wrote(add(&req(&f, std::slice::from_ref(&f), Scope::Repo), &e).unwrap());
    assert!(text(&t).starts_with("vendor/\n\n[secret jwt]\n/cfg.env\n# wpantry ignore: "), "{}", text(&t));
    remove(std::slice::from_ref(&t), Want::Finding(&f.id())).unwrap();
    assert_eq!(text(&t), "vendor/\n", "the one line ending the add had to supply stays");
}

#[test]
fn a_new_user_file_is_private_and_so_is_its_folder() {
    let d = TempDir::new("ie-private").unwrap();
    let e = env(&d);
    let quarantine = d.path().join("quarantine/x.bin");
    let f = found("malware", &quarantine.to_string_lossy(), "", "EICAR");
    let (t, ..) = wrote(add(&req(&f, std::slice::from_ref(&f), Scope::User), &e).unwrap());
    assert_eq!(t.file, e.user_file);
    assert!(
        text(&t).starts_with(&format!("[malware EICAR]\n{}\n# wpantry ignore: ", abs_pattern(&quarantine))),
        "{}",
        text(&t)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&t.file), 0o600, "your file is yours alone");
        assert_eq!(mode(t.file.parent().unwrap()), 0o700, "so is the folder made for it");
    }
    // The leftover temporary files are gone.
    let names: Vec<String> = std::fs::read_dir(t.file.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["ignore"]);
}

#[cfg(unix)]
#[test]
fn an_existing_files_permissions_are_kept() {
    use std::os::unix::fs::PermissionsExt;
    let d = TempDir::new("ie-mode").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    let file = root.join(FILE);
    std::fs::write(&file, "x/\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o664)).unwrap();
    let f = found("secret", &root.join("a.env").to_string_lossy(), "line 1", "jwt");
    wrote(add(&req(&f, std::slice::from_ref(&f), Scope::Repo), &e).unwrap());
    assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o664);
}

#[test]
fn adding_the_same_finding_twice_changes_nothing() {
    // Risk: a second add duplicates the block. Oracle: the file's bytes.
    let d = TempDir::new("ie-idem").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    let f = lock(&root, "package-lock.json", "lodash", "GHSA-lodash");
    let all = [f.clone()];
    let (t, ..) = wrote(add(&req(&f, &all, Scope::Repo), &e).unwrap());
    let once = text(&t);
    assert!(matches!(add(&req(&f, &all, Scope::Repo), &e).unwrap(), Added::Already { .. }));
    assert_eq!(text(&t), once);
    // A rule written by hand counts as already done.
    let g = lock(&root, "other/package-lock.json", "lodash", "GHSA-lodash");
    std::fs::write(root.join(FILE), "[project GHSA-lodash]\n/other/package-lock.json\n").unwrap();
    assert!(matches!(add(&req(&g, std::slice::from_ref(&g), Scope::Repo), &e).unwrap(), Added::Already { .. }));
    assert_eq!(std::fs::read_to_string(root.join(FILE)).unwrap(), "[project GHSA-lodash]\n/other/package-lock.json\n");
}

#[test]
fn the_rule_names_one_file_and_neighbours_stay_reported() {
    // Risk: a rule one level too broad (a whole directory, or every rule of
    // the file). Oracle: the real filter over the neighbours.
    let d = TempDir::new("ie-narrow").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    let a = lock(&root, "pkg/package-lock.json", "lodash", "GHSA-lodash");
    let same_rule_other_file = lock(&root, "pkg/yarn.lock", "lodash", "GHSA-lodash");
    let other_rule_same_file = lock(&root, "pkg/package-lock.json", "left-pad", "GHSA-left-pad");
    let all = [a.clone(), same_rule_other_file.clone(), other_rule_same_file.clone()];
    let (t, rules, _) = wrote(add(&req(&a, &all, Scope::Repo), &e).unwrap());
    assert_eq!(rules[0].pattern, "/pkg/package-lock.json");
    let ig = Ignore::parse(&text(&t));
    let skips = |f: &Finding| {
        let rel = ignore::joined(Path::new(&f.location).strip_prefix(&root).unwrap());
        ig.skips(&f.kind, &f.vuln_id, &rel)
    };
    assert!(skips(&a));
    assert!(!skips(&same_rule_other_file), "the same rule in another file");
    assert!(!skips(&other_rule_same_file), "another rule in the same file");
}

#[test]
fn a_rule_that_would_hide_another_finding_is_refused() {
    // Two packages with one advisory in one lockfile: the format can't tell them apart.
    let d = TempDir::new("ie-collateral").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    let a = lock(&root, "package-lock.json", "foo", "GHSA-shared");
    let b = lock(&root, "package-lock.json", "foo-core", "GHSA-shared");
    let all = [a.clone(), b.clone()];
    let r = refused(add(&req(&a, &all, Scope::Repo), &e));
    assert_eq!(r.code, "would-hide-others");
    assert!(r.message.contains(&b.id()), "{}", r.message);
    assert!(!root.join(FILE).exists(), "nothing was written");
}

#[test]
fn all_places_writes_one_rule_for_each_place_and_one_remove_takes_them_all() {
    let d = TempDir::new("ie-places").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    let other = repo(&d, "other");
    let a = lock(&root, "package-lock.json", "lodash", "GHSA-lodash");
    let b = lock(&root, "web/package-lock.json", "lodash", "GHSA-lodash");
    let elsewhere = lock(&other, "package-lock.json", "lodash", "GHSA-lodash");
    let neighbour = lock(&root, "package-lock.json", "left-pad", "GHSA-left-pad");
    let all = [a.clone(), b.clone(), elsewhere.clone(), neighbour.clone()];
    let mut r = req(&a, &all, Scope::Repo);
    r.all_places = true;
    let (t, rules, left_out) = wrote(add(&r, &e).unwrap());
    let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
    assert_eq!(patterns, ["/package-lock.json", "/web/package-lock.json"], "one rule per place, never a broad pattern");
    assert!(rules.iter().all(|r| r.finding_id == a.id()), "every rule carries the finding asked for");
    assert_eq!(left_out.len(), 1, "the other repo's place is not this file's");
    assert_eq!(left_out[0].finding_id, elsewhere.id());
    assert_eq!(remove(std::slice::from_ref(&t), Want::Finding(&a.id())).unwrap().len(), 2);
    assert_eq!(text(&t), "", "both blocks went, and their blank lines");
    // The user's file covers every place, in every repo.
    let (_, rules, left_out) = wrote(add(&r_user(&a, &all), &e).unwrap());
    assert_eq!(rules.len(), 3);
    assert!(left_out.is_empty());
}

fn r_user<'a>(f: &'a Finding, all: &'a [Finding]) -> Request<'a> {
    Request { all_places: true, ..req(f, all, Scope::User) }
}

#[test]
fn what_protects_you_from_a_repo_can_only_be_skipped_in_your_file() {
    // Risk: a repo hides its own malware. Oracle: refusal, nothing written;
    // and the user's file takes the same finding.
    let d = TempDir::new("ie-protected").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    let at = |kind: &str, id: &str| found(kind, &root.join("x.js").to_string_lossy(), "line 1", id);
    let mut kev = lock(&root, "package-lock.json", "lodash", "CVE-2026-1");
    kev.kev = true;
    let mut mal = lock(&root, "package-lock.json", "evil", "MAL-2026-1");
    mal.severity = "MALICIOUS".into();
    for f in [at("malware", "EICAR"), at("suspect-code", "SUSPECT-RAW-IP"), at("document", "MALWARE"), kev, mal] {
        let all = [f.clone()];
        let r = refused(add(&req(&f, &all, Scope::Repo), &e));
        assert_eq!(r.code, "repo-cannot-skip", "{} {}: {}", f.kind, f.vuln_id, r.message);
        assert!(!root.join(FILE).exists());
        wrote(add(&req(&f, &all, Scope::User), &e).unwrap());
    }
}

#[test]
fn repo_scope_needs_a_finding_inside_a_repo() {
    let d = TempDir::new("ie-norepo").unwrap();
    let e = env(&d);
    let plain = d.path().join("notes");
    std::fs::create_dir_all(&plain).unwrap();
    let f = found("secret", &plain.join("a.env").to_string_lossy(), "line 1", "jwt");
    let r = refused(add(&req(&f, std::slice::from_ref(&f), Scope::Repo), &e));
    assert_eq!(r.code, "not-in-repo");
    assert!(r.message.contains("--scope user"), "{}", r.message);
    wrote(add(&req(&f, std::slice::from_ref(&f), Scope::User), &e).unwrap());
    // A finding about the repo as a whole names no path inside it.
    let root = repo(&d, "app");
    let whole = found("persistence", &root.to_string_lossy(), "", "PERSISTENCE-NEW");
    assert_eq!(refused(add(&req(&whole, std::slice::from_ref(&whole), Scope::Repo), &e)).code, "names-the-repo");
}

#[test]
fn findings_with_no_path_cannot_be_ignored_and_say_where_to_go() {
    let d = TempDir::new("ie-nopath").unwrap();
    let e = env(&d);
    let posture = found("posture", "FileVault", "CIS 2.6.1", "POSTURE-FILEVAULT");
    let r = refused(add(&req(&posture, std::slice::from_ref(&posture), Scope::User), &e));
    assert_eq!(r.code, "no-path");
    assert!(r.message.contains("posture"), "{}", r.message);
    let gap = found("unchecked", "OSV.dev", "", "UNREACHABLE");
    assert_eq!(refused(add(&req(&gap, std::slice::from_ref(&gap), Scope::User), &e)).code, "not-ignorable");
    // A rule's hits in many test files are one finding with no single file.
    let root = repo(&d, "app");
    let tests = found("secret", &root.to_string_lossy(), leaks::TESTS, "generic-password");
    assert_eq!(refused(add(&req(&tests, std::slice::from_ref(&tests), Scope::User), &e)).code, "grouped");
    assert!(!e.user_file.exists(), "nothing was created for a refusal");
}

#[test]
fn a_path_full_of_glob_characters_is_escaped_and_still_matches_only_itself() {
    let d = TempDir::new("ie-glob").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    let odd = format!("{}/we ird[1]*?.env ", root.to_string_lossy());
    let f = found("secret", &odd, "line 1", "jwt");
    let near = found("secret", &format!("{}/we ird1xy.env", root.to_string_lossy()), "line 1", "jwt");
    let all = [f.clone(), near.clone()];
    let (t, rules, _) = wrote(add(&req(&f, &all, Scope::Repo), &e).unwrap());
    assert_eq!(rules[0].pattern, "/we ird\\[1]\\*\\?.env\\ ");
    assert!(Ignore::parse(&text(&t)).skips("secret", "jwt", "we ird[1]*?.env "));
    assert!(!Ignore::parse(&text(&t)).skips("secret", "jwt", "we ird1xy.env"));
    // A line break can't go in a one-line pattern.
    let broken = found("secret", &format!("{}/a\nb.env", root.to_string_lossy()), "line 1", "jwt");
    assert_eq!(refused(add(&req(&broken, std::slice::from_ref(&broken), Scope::Repo), &e)).code, "odd-path");
}

#[test]
fn your_file_names_paths_under_your_home_with_a_tilde() {
    let d = TempDir::new("ie-home").unwrap();
    let e = env(&d);
    let inside = found("secret", &e.home.join("code/app/.env").to_string_lossy(), "line 1", "jwt");
    let elsewhere = d.path().join("srv/app/.env");
    let outside = found("secret", &elsewhere.to_string_lossy(), "line 1", "jwt");
    let all = [inside.clone(), outside.clone()];
    let (t, rules, _) = wrote(add(&req(&inside, &all, Scope::User), &e).unwrap());
    assert_eq!(rules[0].pattern, "~/code/app/.env", "no home directory in the file");
    let (_, rules, _) = wrote(add(&req(&outside, &all, Scope::User), &e).unwrap());
    assert_eq!(rules[0].pattern, abs_pattern(&elsewhere));
    let ig = Ignore::parse_user(&text(&t), &e.home);
    assert!(ig.problems.is_empty(), "{:?}", ig.problems);
}

#[test]
fn reasons_are_one_plain_line() {
    let d = TempDir::new("ie-reason").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    let f = found("secret", &root.join("a.env").to_string_lossy(), "line 1", "jwt");
    for bad in ["two\nlines", "tab\there", &"x".repeat(REASON_MAX + 1)] {
        let mut r = req(&f, std::slice::from_ref(&f), Scope::Repo);
        r.reason = Some(bad);
        assert_eq!(refused(add(&r, &e)).code, "bad-reason", "{bad:?}");
    }
    assert!(!root.join(FILE).exists());
    assert_eq!(clean_reason("  ok  ").unwrap(), "ok");
}

#[cfg(unix)]
#[test]
fn a_link_that_leaves_the_folder_is_never_written_through() {
    // Risk: a symlinked ignore file lets the write land somewhere else.
    // Oracle: the target's bytes are unchanged.
    use std::os::unix::fs::symlink;
    let d = TempDir::new("ie-link").unwrap();
    let e = env(&d);
    let outside = d.path().join("elsewhere.txt");
    std::fs::write(&outside, "keep me\n").unwrap();
    std::fs::create_dir_all(e.user_file.parent().unwrap()).unwrap();
    symlink(&outside, &e.user_file).unwrap();
    let f = found("malware", &d.path().join("q/x.bin").to_string_lossy(), "", "EICAR");
    let r = refused(add(&req(&f, std::slice::from_ref(&f), Scope::User), &e));
    assert_eq!(r.code, "unsafe-file");
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep me\n");
    // A repo's link is never read by a scan, so it isn't written either.
    let root = repo(&d, "app");
    symlink(&outside, root.join(FILE)).unwrap();
    let g = found("secret", &root.join("a.env").to_string_lossy(), "line 1", "jwt");
    assert_eq!(refused(add(&req(&g, std::slice::from_ref(&g), Scope::Repo), &e)).code, "unsafe-file");
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep me\n");
    // A dangling link, and a link inside the folder (written through, the link kept).
    std::fs::remove_file(&e.user_file).unwrap();
    symlink(d.path().join("nowhere"), &e.user_file).unwrap();
    assert_eq!(refused(add(&req(&f, std::slice::from_ref(&f), Scope::User), &e)).code, "unsafe-file");
    std::fs::remove_file(&e.user_file).unwrap();
    let inside = e.user_file.parent().unwrap().join("real-ignore");
    std::fs::write(&inside, "# mine\n").unwrap();
    symlink(&inside, &e.user_file).unwrap();
    wrote(add(&req(&f, std::slice::from_ref(&f), Scope::User), &e).unwrap());
    assert!(std::fs::symlink_metadata(&e.user_file).unwrap().file_type().is_symlink(), "the link stays");
    assert!(std::fs::read_to_string(&inside).unwrap().starts_with("# mine\n\n[malware EICAR]\n"));
}

#[test]
fn a_file_the_reader_wont_take_is_left_alone() {
    let d = TempDir::new("ie-odd").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    let g = found("secret", &root.join("a.env").to_string_lossy(), "line 1", "jwt");
    let all = [g.clone()];
    std::fs::write(root.join(FILE), [0xffu8, 0xfe, b'\n']).unwrap();
    assert_eq!(refused(add(&req(&g, &all, Scope::Repo), &e)).code, "not-utf8");
    std::fs::write(root.join(FILE), vec![b'a'; MAX as usize + 1]).unwrap();
    assert_eq!(refused(add(&req(&g, &all, Scope::Repo), &e)).code, "too-big");
    std::fs::remove_file(root.join(FILE)).unwrap();
    std::fs::create_dir(root.join(FILE)).unwrap();
    assert_eq!(refused(add(&req(&g, &all, Scope::Repo), &e)).code, "unsafe-file");
}

#[test]
fn removing_takes_only_the_asked_rule_and_never_a_neighbouring_hand_written_line() {
    // Risk: remove deletes a line it wasn't asked to. Oracle: exact text.
    let d = TempDir::new("ie-neighbour").unwrap();
    let root = repo(&d, "app");
    let t = Target::repo(&root);
    let hand = "# mine\n[secret github-pat]\n/hand-a.env\n/hand-b.env\n# after\n[project GHSA-x]\n/c\n";
    std::fs::write(&t.file, hand).unwrap();
    let rules = read_rules(&t).unwrap().unwrap();
    assert_eq!(rules.iter().map(|r| r.line).collect::<Vec<_>>(), [3, 4, 7]);
    assert!(rules.iter().all(|r| r.mark.is_none() && r.active));
    let gone = remove(std::slice::from_ref(&t), Want::Rule(&rules[0].id)).unwrap();
    assert_eq!(gone[0].rule.pattern, "/hand-a.env");
    assert_eq!(text(&t), "# mine\n[secret github-pat]\n/hand-b.env\n# after\n[project GHSA-x]\n/c\n");
    // A line our block's comment doesn't follow takes no comment with it.
    let ids: Vec<String> = read_rules(&t).unwrap().unwrap().into_iter().map(|r| r.id).collect();
    remove(std::slice::from_ref(&t), Want::Rule(&ids[1])).unwrap();
    assert_eq!(text(&t), "# mine\n[secret github-pat]\n/hand-b.env\n# after\n[project GHSA-x]\n");
}

#[test]
fn a_header_with_hand_written_lines_under_it_stays_when_our_rule_goes() {
    let d = TempDir::new("ie-header").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    std::fs::write(root.join(FILE), "vendor/\n").unwrap();
    let f = found("secret", &root.join("a.env").to_string_lossy(), "line 1", "jwt");
    let (t, ..) = wrote(add(&req(&f, std::slice::from_ref(&f), Scope::Repo), &e).unwrap());
    // Someone adds a rule under the same header, after our comment.
    let mut now = text(&t);
    now.push_str("/b.env\n");
    std::fs::write(&t.file, &now).unwrap();
    remove(std::slice::from_ref(&t), Want::Finding(&f.id())).unwrap();
    assert_eq!(text(&t), "vendor/\n\n[secret jwt]\n/b.env\n", "the header they rely on is kept");
}

#[test]
fn rules_are_listed_with_stable_ids_and_marks_and_duplicates_are_told_apart() {
    let d = TempDir::new("ie-list").unwrap();
    let e = env(&d);
    let root = repo(&d, "app");
    std::fs::write(root.join(FILE), "vendor/\n[bogus]\n/x\n[secret jwt]\n/a\n/a\n\\#hash\n!keep\n[Bb]uild/\n").unwrap();
    let f = found("secret", &root.join("z.env").to_string_lossy(), "line 1", "jwt");
    let mut r = req(&f, std::slice::from_ref(&f), Scope::Repo);
    r.reason = Some("test key | not real");
    let (t, ..) = wrote(add(&r, &e).unwrap());
    let rules = read_rules(&t).unwrap().unwrap();
    let shown: Vec<(usize, &str, &str, bool, bool)> =
        rules.iter().map(|r| (r.line, r.section.as_str(), r.pattern.as_str(), r.active, r.mark.is_some())).collect();
    assert_eq!(
        shown,
        [
            (1, "", "vendor/", true, false),
            (3, "bogus", "/x", false, false),
            (5, "secret jwt", "/a", true, false),
            (6, "secret jwt", "/a", true, false),
            (7, "secret jwt", "\\#hash", true, false),
            (8, "secret jwt", "!keep", true, false),
            (9, "secret jwt", "[Bb]uild/", true, false),
            (12, "secret jwt", "/z.env", true, true),
        ]
    );
    assert_ne!(rules[2].id, rules[3].id, "two copies of one line get two ids");
    let mark = rules[7].mark.clone().unwrap();
    assert_eq!((mark.finding_id.as_str(), mark.reason.as_str()), (f.id().as_str(), "test key | not real"));
    // Ids move with the line, not with its number: insert a line above.
    let again = rules_of(&format!("# top\n{}", text(&t)), &t);
    assert_eq!(rules.iter().map(|r| &r.id).collect::<Vec<_>>(), again.iter().map(|r| &r.id).collect::<Vec<_>>());
    // A missing file has no rules; a link is an error for a repo.
    assert!(read_rules(&Target::repo(&d.path().join("nowhere"))).unwrap().is_none());
    #[cfg(unix)]
    {
        let link = d.path().join("lnk");
        std::fs::create_dir_all(&link).unwrap();
        std::os::unix::fs::symlink(root.join(FILE), link.join(FILE)).unwrap();
        assert!(read_rules(&Target::repo(&link)).is_err());
    }
}

#[test]
fn an_id_in_two_files_is_ambiguous_and_nothing_is_removed() {
    let d = TempDir::new("ie-ambiguous").unwrap();
    let a = Target::repo(&repo(&d, "a"));
    let b = Target::repo(&repo(&d, "b"));
    std::fs::write(&a.file, "[secret]\n/x\n").unwrap();
    std::fs::write(&b.file, "[secret]\n/x\n").unwrap();
    let ida = read_rules(&a).unwrap().unwrap()[0].id.clone();
    let idb = read_rules(&b).unwrap().unwrap()[0].id.clone();
    assert_ne!(ida, idb, "the same line in two repos is two rules");
    assert_eq!(
        remove(std::slice::from_ref(&a), Want::Rule(&idb)).unwrap().len(),
        0,
        "an id of another file matches nothing"
    );
    assert_eq!(remove(&[a, b.clone()], Want::Rule(&idb)).unwrap().len(), 1);
    assert_eq!(text(&b), "[secret]\n");
}

#[test]
fn repo_for_finds_the_repo_a_path_means() {
    let d = TempDir::new("ie-repofor").unwrap();
    let root = repo(&d, "app");
    let sub = root.join("a/b");
    std::fs::create_dir_all(&sub).unwrap();
    assert_eq!(repo_for(&sub), root);
    assert_eq!(repo_for(&root), root);
    std::fs::write(sub.join(FILE), "x\n").unwrap();
    assert_eq!(repo_for(&sub), sub, "a folder with its own file is the one meant");
    let plain = d.path().join("plain");
    std::fs::create_dir_all(&plain).unwrap();
    assert_eq!(repo_for(&plain), plain);
}

#[test]
fn scopes_and_marks_parse() {
    assert_eq!(Scope::parse("user"), Some(Scope::User));
    assert_eq!(Scope::parse("repo"), Some(Scope::Repo));
    assert_eq!(Scope::parse("both"), None);
    assert_eq!((Scope::User.name(), Scope::Repo.name()), ("user", "repo"));
    assert!(parse_mark("not-an-id | x").is_none());
    let m = parse_mark("F-3FA9C01B2E | 2026-11-25 14:03 UTC").unwrap();
    assert_eq!(
        (m.finding_id.as_str(), m.when.as_str(), m.reason.as_str()),
        ("F-3fa9c01b2e", "2026-11-25 14:03 UTC", "")
    );
    assert_eq!(eol("a\r\nb\r\n"), "\r\n");
    assert_eq!(eol("a\nb"), "\n");
    assert_eq!(eol(""), "\n");
}

/// A path outside your home as your file spells it: from the root, with `/`.
fn abs_pattern(p: &Path) -> String {
    let j = ignore::joined(p);
    if cfg!(windows) { j } else { format!("/{j}") }
}
