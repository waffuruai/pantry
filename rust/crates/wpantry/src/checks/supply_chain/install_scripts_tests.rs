use super::*;
use crate::checks::Options;
use crate::checks::supply_chain::testing;
use crate::utils::net::Fake;
use crate::utils::temp::TempDir;
use serde_json::json;

fn allows(lines: &[&str]) -> Vec<Allow> {
    parse_entries(&lines.iter().map(|l| l.to_string()).collect::<Vec<_>>())
}

fn v(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| x.to_string()).collect()
}

#[test]
fn entries_split_on_the_last_at_sign_so_scopes_survive() {
    assert_eq!(parse_entry("esbuild"), Some(Allow { name: "esbuild".into(), range: None }));
    assert_eq!(parse_entry("@swc/core").unwrap().name, "@swc/core");
    let scoped = parse_entry("@swc/core@^1").unwrap();
    assert_eq!((scoped.name.as_str(), scoped.range.unwrap().shown.as_str()), ("@swc/core", "^1"));
    let exact = parse_entry("  sharp@0.35.5  ").unwrap();
    assert_eq!(exact.range.unwrap().shown, "0.35.5");
}

#[test]
fn garbage_entries_are_skipped_not_panics() {
    for bad in [
        "",
        "  ",
        "esbuild@",
        "esbuild@latest",
        "esbuild@^1.x",
        "esbuild@1.2.3.4",
        "esbuild@^",
        "a b@1",
        "@",
        "esbuild@>=1",
    ] {
        assert_eq!(parse_entry(bad), None, "{bad:?}");
    }
    assert_eq!(allows(&["esbuild@^0.28", "nonsense@^", "sharp"]).len(), 2);
}

#[test]
fn exact_versions_match_only_themselves() {
    let r = Range::parse("1.2.3").unwrap();
    assert!(r.contains("1.2.3") && r.contains("v1.2.3"));
    assert!(!r.contains("1.2.4") && !r.contains("1.2") && !r.contains("1.2.3-beta.1"));
    assert!(Range::parse("=1.2.3").unwrap().contains("1.2.3"));
    assert!(Range::parse("1.2").unwrap().contains("1.2.0"), "a short exact version is padded with zeros");
}

#[test]
fn caret_keeps_the_first_non_zero_part() {
    let one = Range::parse("^1.2.3").unwrap();
    assert!(one.contains("1.2.3") && one.contains("1.9.0") && !one.contains("1.2.2") && !one.contains("2.0.0"));
    let zero = Range::parse("^0.28").unwrap();
    assert!(zero.contains("0.28.0") && zero.contains("0.28.9") && !zero.contains("0.29.0") && !zero.contains("0.27.9"));
    let tiny = Range::parse("^0.0.3").unwrap();
    assert!(tiny.contains("0.0.3") && !tiny.contains("0.0.4"));
    let all_zero = Range::parse("^0.0").unwrap();
    assert!(all_zero.contains("0.0.9") && !all_zero.contains("0.1.0"));
    let major = Range::parse("^1").unwrap();
    assert!(major.contains("1.0.0") && major.contains("1.99.99") && !major.contains("2.0.0"));
    assert!(!major.contains("1.5.0-rc.1"), "a prerelease is never inside a range");
    assert!(!major.contains("not-a-version"));
}

#[test]
fn tilde_keeps_the_minor() {
    let r = Range::parse("~1.2.3").unwrap();
    assert!(r.contains("1.2.3") && r.contains("1.2.9") && !r.contains("1.3.0") && !r.contains("1.2.2"));
    let short = Range::parse("~1.2").unwrap();
    assert!(short.contains("1.2.0") && !short.contains("1.3.0"));
    let major = Range::parse("~1").unwrap();
    assert!(major.contains("1.9.9") && !major.contains("2.0.0"));
}

#[test]
fn verdicts() {
    let list = allows(&["esbuild@^0.25", "sharp", "@swc/core@^1", "workerd@1.20261019.1", "workerd@^2"]);
    assert_eq!(verdict(&list, "esbuild", &v(&["0.25.9"])), Verdict::Allowed);
    assert_eq!(
        verdict(&list, "esbuild", &v(&["0.28.1"])),
        Verdict::OutsideRange { allowed: "^0.25".into(), locked: v(&["0.28.1"]) }
    );
    assert_eq!(
        verdict(&list, "esbuild", &v(&["0.25.0", "0.28.1"])),
        Verdict::OutsideRange { allowed: "^0.25".into(), locked: v(&["0.28.1"]) },
        "only the versions outside are named"
    );
    assert_eq!(verdict(&list, "esbuild", &[]), Verdict::UnknownVersion { allowed: "^0.25".into() });
    assert_eq!(verdict(&list, "sharp", &v(&["0.1.0"])), Verdict::Allowed, "a bare name allows every version");
    assert_eq!(verdict(&list, "sharp", &[]), Verdict::Allowed, "and needs no version");
    assert_eq!(verdict(&list, "@swc/core", &v(&["1.16.21"])), Verdict::Allowed);
    assert_eq!(verdict(&list, "foo", &v(&["1.0.0"])), Verdict::NotListed);
    assert_eq!(
        verdict(&list, "workerd", &v(&["1.20261019.1", "2.0.0"])),
        Verdict::Allowed,
        "two entries read together"
    );
    assert_eq!(
        verdict(&list, "workerd", &v(&["1.20261031.1"])),
        Verdict::OutsideRange { allowed: "1.20261019.1, ^2".into(), locked: v(&["1.20261031.1"]) }
    );
}

#[test]
fn the_bundled_list_parses_whole_and_is_pinned() {
    let lines = crate::checks::listed(None, crate::defaults::INSTALL_SCRIPTS, "allow");
    let parsed = parse_entries(&lines);
    assert_eq!(parsed.len(), lines.len(), "every line of the default file is an entry");
    assert!(parsed.iter().all(|a| a.range.is_some()), "every default entry carries a version range");
    assert_eq!(verdict(&parsed, "esbuild", &v(&["0.28.2"])), Verdict::Allowed);
}

/// Install scripts outside the allowlist warn, each verdict with its own
/// advice; npm running scripts by default is a config warning.
#[cfg(unix)]
#[test]
fn install_scripts_outside_the_allowlist_warn() {
    let d = TempDir::new("install").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d, Options::default());
    let (name, root) = testing::repo(&d, "app");
    testing::write(
        &root,
        "package-lock.json",
        json!({"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app"},
        "node_modules/foo": {"version": "1.0.0", "hasInstallScript": true},
        "node_modules/esbuild": {"version": "0.27.0", "hasInstallScript": true},
        "node_modules/fsevents": {"version": "2.3.3", "hasInstallScript": true},
        "node_modules/sharp": {"hasInstallScript": true}}})
        .to_string(),
    );
    let npm = testing::script(d.path(), "npm", "#!/bin/sh\necho false\n");
    let found = [Component::new("manager", "npm", "10.0.0", &npm.to_string_lossy())];
    install_scripts(&mut s, &[(name, root.clone())], &found);
    let script_for = |n: &str| {
        testing::by_id(&s, "INSTALL-SCRIPT")
            .into_iter()
            .find(|f| f.component == n)
            .map(|f| (f.note.clone(), f.fix_cmd.clone()))
    };
    assert!(script_for("fsevents").is_none(), "allowed at that version");
    let (note, fix) = script_for("foo").unwrap();
    assert_eq!(note, "runs code when installed");
    assert!(fix.starts_with("Check what foo's install script does"), "{fix}");
    let (note, fix) = script_for("esbuild").unwrap();
    assert!(note.contains("allowed at ^0.28 but 0.27.0 is locked"), "{note}");
    assert!(fix.starts_with("Re-read esbuild's install script at 0.27.0"), "{fix}");
    let (note, fix) = script_for("sharp").unwrap();
    assert!(note.contains("the locked version couldn't be read"), "{note}");
    assert!(fix.starts_with("Check which sharp the lockfile pins"), "{fix}");
    let f = testing::by_id(&s, "INSTALL-SCRIPT")[0];
    assert_eq!(
        (f.kind.as_str(), f.status.as_str(), f.location.as_str()),
        ("install-script", "warn", root.join("package-lock.json").to_str().unwrap())
    );
    let cfg = testing::by_id(&s, "NPM-SCRIPTS");
    assert_eq!(cfg.len(), 1, "{:?}", s.findings);
    assert_eq!(
        (cfg[0].kind.as_str(), cfg[0].component.as_str(), cfg[0].location.as_str()),
        ("config", "npm ignore-scripts", npm.to_str().unwrap())
    );
    assert_eq!(
        cfg[0].fix_cmd,
        format!("{} config set ignore-scripts true  (then allow builds per project)", npm.display())
    );
    // npm that ignores scripts, or no npm: no config warning.
    let npm = testing::script(d.path(), "npm2", "#!/bin/sh\necho true\n");
    let before = s.findings.len();
    install_scripts(&mut s, &[], &[Component::new("manager", "npm", "10.0.0", &npm.to_string_lossy())]);
    install_scripts(&mut s, &[], &[Component::new("manager", "npm", "10.0.0", "")]);
    assert_eq!(s.findings.len(), before);
}
