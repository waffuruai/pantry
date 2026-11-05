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
