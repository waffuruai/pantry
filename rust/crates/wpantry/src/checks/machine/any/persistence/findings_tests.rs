use super::*;
use crate::checks::machine::testing;
use crate::utils::net::Fake;
use crate::utils::temp;

#[test]
fn the_baseline_is_quiet_first_then_warns_on_new_items() {
    let d = temp::TempDir::new("persist").unwrap();
    let cache = Cache::open(Some(&d.path().join("w.db"))).unwrap();
    let item = |loc: &str, ident: &str| Item {
        source: Source::Launchd,
        location: loc.into(),
        ident: ident.into(),
        program: Some(PathBuf::from("/opt/x")),
        injects: Vec::new(),
        line: 0,
    };
    let mut inv = Inventory { items: vec![item("a.plist", "/opt/x")], read: vec![Source::Launchd], unread: Vec::new() };
    let (new, first) = diff(&cache, &inv, 1.0).unwrap();
    assert!(new.is_empty());
    assert_eq!(first, [Source::Launchd]);
    // A second scan with the same items: nothing new.
    assert_eq!(diff(&cache, &inv, 2.0).unwrap(), (vec![], vec![]));
    // A new plist, and the old one now runs something else.
    inv.items = vec![item("a.plist", "/opt/y"), item("b.plist", "/opt/x")];
    let (new, _) = diff(&cache, &inv, 3.0).unwrap();
    assert_eq!(new, [0, 1]);
    // Recorded: quiet again. A removed item that comes back is new again.
    assert!(diff(&cache, &inv, 4.0).unwrap().0.is_empty());
    inv.items.pop();
    diff(&cache, &inv, 5.0).unwrap();
    inv.items.push(item("b.plist", "/opt/x"));
    assert_eq!(diff(&cache, &inv, 6.0).unwrap().0, [1]);
    // An unread source keeps its baseline untouched.
    inv.read.clear();
    inv.items.clear();
    diff(&cache, &inv, 7.0).unwrap();
    inv.read.push(Source::Launchd);
    inv.items = vec![item("a.plist", "/opt/y"), item("b.plist", "/opt/x")];
    assert!(diff(&cache, &inv, 8.0).unwrap().0.is_empty());
}

#[test]
fn findings_for_new_items_injection_signatures_and_hidden_programs() {
    let shell = |line: usize, ident: &str| Item {
        source: Source::Shell,
        location: "~/.zshrc".into(),
        ident: ident.into(),
        program: None,
        injects: Vec::new(),
        line,
    };
    let agent = Item {
        source: Source::Launchd,
        location: "~/Library/LaunchAgents/x.plist".into(),
        ident: "/Users/u/.x/agent".into(),
        program: Some(PathBuf::from("/Users/u/.x/agent")),
        injects: vec!["DYLD_INSERT_LIBRARIES".into()],
        line: 0,
    };
    let inv = Inventory { items: vec![shell(3, "a"), shell(9, "b"), agent], read: vec![], unread: vec![] };
    let mut vetted = BTreeMap::new();
    vetted.insert(
        PathBuf::from("/Users/u/.x/agent"),
        Vetted { signature: Signature::Invalid("invalid signature".into()), quarantined: Some(false), hidden: true },
    );
    let show = |p: &Path| p.display().to_string();
    let got = findings(&inv, &[0, 1, 2], &vetted, &show);
    let ids: Vec<(&str, &str)> = got.iter().map(|f| (f.vuln_id.as_str(), f.component.as_str())).collect();
    assert_eq!(
        ids,
        [
            ("PERSISTENCE-NEW", "~/Library/LaunchAgents/x.plist"),
            ("PERSISTENCE-NEW", "~/.zshrc"),
            ("PERSISTENCE-INJECTION", "~/Library/LaunchAgents/x.plist"),
            ("PERSISTENCE-SIGNATURE", "~/Library/LaunchAgents/x.plist"),
            ("PERSISTENCE-HIDDEN", "~/Library/LaunchAgents/x.plist"),
        ]
    );
    assert!(got.iter().all(|f| f.kind == "persistence" && f.status == "warn" && !f.fix_auto));
    assert!(got[0].note.contains("runs /Users/u/.x/agent (its signature doesn't verify"), "{}", got[0].note);
    assert_eq!(got[1].note, "2 new lines since the last scan (lines 3, 9); every new shell runs them");
    // Nothing new: only what warns every scan.
    assert_eq!(findings(&inv, &[], &vetted, &show).len(), 3);
}

#[test]
fn persistence_baselines_first_then_warns_on_what_is_new() {
    use crate::checks::machine::any::persistence::{Inventory, Item, Source};
    let d = crate::utils::temp::TempDir::new("persistence").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    let item = |loc: &str| Item {
        source: Source::Launchd,
        location: loc.into(),
        ident: String::new(),
        program: None,
        injects: Vec::new(),
        line: 0,
    };
    let mut inv = Inventory {
        items: vec![item("a.plist")],
        read: vec![Source::Launchd],
        unread: vec![(Source::SystemExtension, "systemextensionsctl list gave no answer".into())],
    };
    persistence(&mut s, (inv.clone(), Default::default()));
    assert_eq!(
        testing::kinds(&s),
        [("persistence: system extensions".to_string(), "UNCHECKED".to_string(), "warn".to_string())],
        "the first scan records, and says what it couldn't read"
    );
    assert!(s.counts.iter().any(|(k, n)| k.starts_with("persistence items recorded") && *n == 1));
    let mut s2 = Scan::new(Default::default(), s.cache, &net, &|_| {}, &|_| {});
    inv.items.push(item("b.plist"));
    inv.unread.clear();
    persistence(&mut s2, (inv, Default::default()));
    assert_eq!(testing::kinds(&s2), [("b.plist".to_string(), "PERSISTENCE-NEW".to_string(), "warn".to_string())]);
    assert_eq!(s2.findings[0].kind, "persistence");
}

/// Risk: a launch agent whose program lies in a folder the scan leaves out
/// (`~/Downloads` under `--no-personal-files`) was dropped from the checks
/// and then skipped without a word, so the output read as if its signature,
/// quarantine flag and contents had been checked. Oracle: the findings and
/// the calls the checks make. The scan says it once, as an `unchecked`
/// finding that is a gap (not an area left out by choice) and names the item
/// and its program; the program is never opened, or handed to `codesign` or
/// `xattr`; the agent whose program is elsewhere is vetted as before.
/// Known bad: drop the finding, or let `vet_all` look at the program (the
/// recorded calls then name it).
#[test]
fn a_login_program_in_a_left_out_folder_is_named_as_not_checked_and_never_opened() {
    use crate::checks::machine::any::persistence::{Inventory, Item, Source, vet_all};
    let _home = crate::utils::files::test_home();
    let h = crate::utils::files::home();
    let d = temp::TempDir::new("left-out-agent").unwrap();
    let (shut, fine) = (h.join("Downloads/agent"), h.join("bin/tool"));
    testing::write(&shut, "x");
    testing::write(&fine, "x");
    let item = |loc: &str, program: &Path| Item {
        source: Source::Launchd,
        location: loc.into(),
        ident: program.display().to_string(),
        program: Some(program.to_path_buf()),
        injects: Vec::new(),
        line: 0,
    };
    let inv = Inventory {
        items: vec![item("~/Library/LaunchAgents/evil.plist", &shut), item("~/Library/LaunchAgents/ok.plist", &fine)],
        read: vec![Source::Launchd],
        unread: Vec::new(),
    };
    let _guard = crate::utils::privacy::leave_out(crate::utils::privacy::folders(&h, false), Vec::new());
    let calls = std::sync::Mutex::new(Vec::<String>::new());
    let runner = |argv: &[&str]| {
        calls.lock().unwrap().push(argv.join(" "));
        String::new()
    };
    let vetted = vet_all(&testing::roots(d.path(), true, &runner), &inv);
    let calls = calls.lock().unwrap().clone();
    assert!(!calls.iter().any(|c| c.contains("Downloads")), "the left-out program was handed to a tool: {calls:?}");
    assert!(calls.iter().any(|c| c.contains("tool")), "the witness: the other program is checked: {calls:?}");
    assert!(vetted.contains_key(&fine) && !vetted.contains_key(&shut));

    let net = Fake::offline();
    let mut s = testing::scan(&net, &d);
    persistence(&mut s, (inv, vetted));
    let gaps: Vec<&Finding> = s.findings.iter().filter(|f| f.kind == "unchecked").collect();
    assert_eq!(gaps.len(), 1, "{:?}", s.findings);
    let gap = gaps[0];
    assert!(gap.is_gap(), "the person should know: {gap:?}");
    assert!(gap.component.contains("evil.plist") && gap.component.contains("agent"), "{}", gap.component);
    assert!(!gap.component.contains("ok.plist") && gap.note.contains("--no-personal-files"), "{gap:?}");
    assert_eq!(
        (gap.vuln_id.as_str(), gap.status.as_str(), gap.fix_cmd.as_str()),
        ("UNCHECKED", "warn", "wpantry scan")
    );
}
