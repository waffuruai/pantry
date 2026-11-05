use super::*;
use crate::checks::Options;
use crate::checks::supply_chain::testing;
use crate::checks::supply_chain::testing::CARGO_LOCK;
use crate::utils::files;
use crate::utils::net::{Fake, Response};
use crate::utils::temp::TempDir;
use serde_json::json;

/// A known malicious extension fails (and nothing else is said of it),
/// a vulnerable one fails, a deprecated one warns with its replacement,
/// one behind its marketplace warns with the update.
#[test]
fn extensions_against_the_lists_osv_and_the_marketplaces() {
    let d = TempDir::new("extensions").unwrap();
    let net = Fake::new(|r| {
        if r.url == crate::sources::file::url("vscode-extension-lists") {
            return Ok(Response::ok(json!({"malicious": ["Evil.One"], "deprecated": {"Old.Two": {"extension": {"id": "New.Two"}}, "Plain.X": true}}).to_string()));
        }
        if r.url == crate::sources::file::url("vscode-marketplace") {
            return Ok(Response::ok(json!({"results": [{"extensions": [
                {"publisher": {"publisherName": "Old"}, "extensionName": "Two", "versions": [{"version": "2.0.0"}]},
                {"publisher": {"publisherName": "Vuln"}, "extensionName": "Three", "versions": [{"version": "1.0.0"}]}]}]}).to_string()));
        }
        if r.url == "https://open-vsx.org/api/cur/four/latest" {
            return Ok(Response::ok(json!({"version": "1.0.0"}).to_string()));
        }
        testing::osv(r, &[("VSCode", "Vuln.Three")]).unwrap_or_else(|| panic!("unexpected request to {}", r.url))
    });
    let mut s = testing::scan(&net, &d, Options::default());
    let exts = vec![
        testing::extension("Evil.One", "1.0.0", "vscode", "/e/evil"),
        testing::extension("Old.Two", "1.0.0", "vscode", "/e/old"),
        testing::extension("Vuln.Three", "1.0.0", "vscode", "/e/vuln"),
        testing::extension("Cur.Four", "1.0.0", "openvsx", "/e/cur"),
    ];
    assert!(extensions_with(&mut s, Vec::new()).unwrap().is_empty());
    let out = extensions_with(&mut s, exts).unwrap();
    assert_eq!(out.len(), 4);
    assert_eq!(out[0].name, "Evil.One (VS Code)", "how the report names it");
    assert!(s.counts.contains(&("editor extensions".to_string(), 4)));
    let mal = testing::by_id(&s, "MALICIOUS");
    assert_eq!(mal.len(), 1, "{:?}", s.findings);
    assert_eq!(
        (
            mal[0].component.as_str(),
            mal[0].status.as_str(),
            mal[0].severity.as_str(),
            mal[0].fix_cmd.as_str(),
            mal[0].fix_auto
        ),
        ("Evil.One (VS Code)", "fail", "MALICIOUS", "code --uninstall-extension Evil.One", true)
    );
    assert!(!s.findings.iter().any(|f| f.component.starts_with("Evil.One") && f.vuln_id != "MALICIOUS"));
    let vuln = testing::by_id(&s, "GHSA-Vuln.Three");
    assert_eq!(vuln.len(), 1, "{:?}", s.findings);
    assert_eq!(
        (vuln[0].component.as_str(), vuln[0].status.as_str(), vuln[0].fix_cmd.as_str()),
        ("Vuln.Three (VS Code)", "fail", "code --uninstall-extension Vuln.Three")
    );
    assert!(
        !s.findings.iter().any(|f| f.component.starts_with("Vuln.Three") && f.vuln_id == "OUTDATED"),
        "a vulnerable one is removed, not updated"
    );
    let dep = testing::by_id(&s, "DEPRECATED");
    assert_eq!(dep.len(), 1, "{:?}", s.findings);
    assert_eq!(
        (dep[0].component.as_str(), dep[0].status.as_str(), dep[0].note.as_str()),
        ("Old.Two (VS Code)", "warn", "deprecated; use New.Two")
    );
    let old = testing::by_id(&s, "OUTDATED");
    assert_eq!(old.len(), 1, "{:?}", s.findings);
    assert_eq!(
        (
            old[0].component.as_str(),
            old[0].fixed.as_str(),
            old[0].note.as_str(),
            old[0].fix_cmd.as_str(),
            old[0].fix_auto
        ),
        ("Old.Two (VS Code)", "2.0.0", "latest release is 2.0.0", "code --install-extension Old.Two --force", true)
    );
    assert!(!s.findings.iter().any(|f| f.component.starts_with("Cur.Four")), "current on Open VSX: {:?}", s.findings);
    assert!(testing::unchecked(&s).is_empty(), "{:?}", s.findings);
}

#[test]
fn unreachable_extension_lists_are_unchecked_not_clean() {
    let d = TempDir::new("extensions-off").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d, Options::default());
    extensions_with(&mut s, vec![testing::extension("Old.Two", "1.0.0", "vscode", "/e/old")]).unwrap();
    let mut un = testing::unchecked(&s);
    un.sort_unstable();
    assert_eq!(
        un,
        ["VS Code's malicious-extension list", "editor extensions against OSV", "latest extension versions (vscode)"]
    );
    assert_eq!(s.findings.len(), 3, "{:?}", s.findings);
}

/// The npm packages bundled in extensions and plugins, and the lockfiles
/// shipped in those and in skills: a vulnerable one warns (its vendor
/// fixes it).
#[test]
fn bundles_read_node_modules_and_shipped_lockfiles() {
    let _home = crate::utils::files::test_home();
    let home = files::home();
    let d = TempDir::new("bundles").unwrap();
    let net = testing::osv_net(&[("npm", "lodash"), ("crates.io", "serde")]);
    let mut s = testing::scan(&net, &d, Options::default());
    let ext_dir = d.path().join("ext");
    testing::write(&ext_dir, "node_modules/lodash/package.json", r#"{"name": "lodash", "version": "4.17.20"}"#);
    let mut ext = testing::extension("Pub.Ext", "1.0.0", "vscode", ext_dir.to_str().unwrap());
    ext.name = "Pub.Ext (VS Code)".into();
    ext.fix = "code --install-extension Pub.Ext --force".into();
    testing::write(
        &home,
        ".claude/plugins/cache/mk/p1/node_modules/ms/package.json",
        r#"{"name": "ms", "version": "2.1.3"}"#,
    );
    testing::write(&home, ".claude/skills/s1/Cargo.lock", CARGO_LOCK);
    bundles(&mut s, &[ext]).unwrap();
    assert!(s.counts.contains(&("packages in extension, plugin and skill lockfiles".to_string(), 2)), "{:?}", s.counts);
    let lodash = testing::by_id(&s, "GHSA-lodash");
    assert_eq!(lodash.len(), 1, "{:?}", s.findings);
    assert_eq!(
        (lodash[0].kind.as_str(), lodash[0].component.as_str(), lodash[0].status.as_str(), lodash[0].fix_cmd.as_str()),
        ("bundled", "Pub.Ext (VS Code) › lodash", "warn", "code --install-extension Pub.Ext --force")
    );
    assert_eq!(lodash[0].location, ext_dir.to_string_lossy());
    let serde = testing::by_id(&s, "GHSA-serde");
    assert_eq!(serde.len(), 1, "{:?}", s.findings);
    assert_eq!((serde[0].component.as_str(), serde[0].status.as_str()), ("~/.claude/skills/s1 › serde", "warn"));
    assert_eq!(serde[0].fix_cmd, "Update or remove what ships ~/.claude/skills/s1/Cargo.lock");
    let asked: Vec<String> = net
        .requests()
        .iter()
        .filter(|r| r.url.ends_with("/v1/querybatch"))
        .map(|r| String::from_utf8_lossy(r.body.as_ref().unwrap()).into_owned())
        .collect();
    assert!(asked.iter().any(|b| b.contains("\"ms\"")), "the plugin's bundle is asked too: {asked:?}");
    assert!(!s.findings.iter().any(|f| f.component.contains("ms")), "{:?}", s.findings);
}
