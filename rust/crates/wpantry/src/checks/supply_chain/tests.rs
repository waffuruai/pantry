use super::*;
use crate::checks::supply_chain::testing;
use crate::checks::supply_chain::testing::CARGO_LOCK;
use crate::checks::{Options, REMOVE};
use crate::utils::temp::TempDir;
use serde_json::json;

/// The whole pass over one repo, with gitleaks scanning ahead of the
/// network: lockfile hits, the secret it found, the sweep against the
/// malicious index; and once more as a machine scan with nothing
/// installed under a private home.
#[cfg(unix)]
#[test]
fn run_scans_the_repos_with_gitleaks_ahead() {
    let _home = crate::utils::files::test_home();
    let d = TempDir::new("run").unwrap();
    testing::seed_index(&d, &[("npm", "evil", "MAL-0001")]);
    let net = testing::osv_net(&[("crates.io", "serde")]);
    let mut s = testing::scan(&net, &d, Options { jobs: Some(1), ..Default::default() });
    let (name, root) = testing::repo(&d, "app");
    testing::write(&root, ".git/HEAD", format!("{}\n", "a".repeat(40)));
    testing::write(&root, "Cargo.lock", CARGO_LOCK);
    s.repos = vec![(name, root.clone())];
    let report = json!([{"RuleID": "github-pat", "File": "x.env", "StartLine": 1, "Commit": "0123456789abcdef",
                        "Fingerprint": "fp1", "Description": "GitHub"}]);
    let exe = testing::script(
        d.path(),
        "gitleaks",
        &format!(
            "#!/bin/sh\nif [ \"$1\" = version ]; then echo 8.21.2; exit 0; fi\nprev=\"\"\nfor a in \"$@\"; do if [ \"$prev\" = --report-path ]; then printf '%s' '{report}' > \"$a\"; fi; prev=\"$a\"; done\n"
        ),
    );
    run_with(&mut s, &[], Some(exe), None).unwrap();
    assert_eq!(testing::by_id(&s, "GHSA-serde").len(), 1, "{:?}", s.findings);
    let pat = testing::by_id(&s, "github-pat");
    assert_eq!(pat.len(), 1, "{:?}", s.findings);
    assert_eq!((pat[0].component.as_str(), pat[0].status.as_str()), ("app/x.env", "fail"));
    for what in [
        "repos scanned for secrets",
        "repos checked for hooks",
        "repos checked for suspicious code",
        "repos checked for hidden text",
        "repos checked for documents and images",
    ] {
        assert!(s.counts.contains(&(what.to_string(), 1)), "{what}: {:?}", s.counts);
    }
    assert!(testing::unchecked(&s).is_empty(), "{:?}", s.findings);
    // A machine scan: the editor, bundle and breach steps run over an empty home.
    let net = testing::osv_net(&[]);
    let mut s = testing::scan(&net, &d, Options { machine: true, jobs: Some(1), ..Default::default() });
    s.repos = vec![];
    let mut npm = Component::new("manager", "npm", "10.0.0", "");
    npm.osv = Some(("npm".into(), "evil".into(), "1.0.0".into()));
    run_with(&mut s, &[npm], None, None).unwrap();
    let mal = testing::by_id(&s, "MAL-0001");
    assert_eq!(mal.len(), 1, "{:?}", s.findings);
    assert_eq!(
        (mal[0].status.as_str(), mal[0].severity.as_str(), mal[0].note.as_str()),
        ("fail", "MALICIOUS", "MAL-0001 is malicious")
    );
    assert_eq!(mal[0].fix_cmd, REMOVE.replace("{}", "evil"));
    assert!(mal[0].kev);
}
