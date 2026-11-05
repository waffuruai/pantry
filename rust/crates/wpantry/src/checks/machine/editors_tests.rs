use super::*;
use crate::utils::temp;

// The test vector the Python implementation had (`SupplyChain.test_bundled_npm`).
#[test]
fn bundled_npm_packages() {
    let d = temp::TempDir::new("bundled").unwrap();
    for (rel, name, ver) in [
        ("node_modules/a", "a", "1.0.0"),
        ("node_modules/@s/b", "@s/b", "2.0.0"),
        ("node_modules/a/node_modules/c", "c", "3.0.0"),
        ("src/not-a-dep", "d", "4"),
    ] {
        std::fs::create_dir_all(d.path().join(rel)).unwrap();
        std::fs::write(d.path().join(rel).join("package.json"), format!(r#"{{"name": "{name}", "version": "{ver}"}}"#))
            .unwrap();
    }
    let got = bundled_npm(d.path());
    let want: Vec<(String, String)> = [("@s/b", "2.0.0"), ("a", "1.0.0"), ("c", "3.0.0")]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    assert_eq!(got, want);
}

#[test]
fn node_modules_nested_too_deep_are_left_alone() {
    let d = temp::TempDir::new("deep").unwrap();
    let deep = "node_modules/a/".repeat(7) + "node_modules/z";
    std::fs::create_dir_all(d.path().join(&deep)).unwrap();
    std::fs::write(d.path().join(&deep).join("package.json"), r#"{"name": "z", "version": "1"}"#).unwrap();
    std::fs::write(d.path().join("node_modules/a/package.json"), r#"{"name": "a", "version": "1"}"#).unwrap();
    let got = bundled_npm(d.path());
    assert_eq!(got, [("a".to_string(), "1".to_string())], "z sits under eight node_modules: not read");
    assert_eq!(ecosystem("vscode"), "VSCode");
    assert_eq!(ecosystem("openvsx"), "VSCode:https://open-vsx.org");
    assert_eq!(text(&serde_json::Value::Null), "");
    assert_eq!(text(&serde_json::json!(1.5)), "1.5");
}

/// Extensions on disk count only for an installed editor, and the
/// `.obsolete` list (what the editor will remove) is skipped.
#[test]
fn extensions_of_installed_editors() {
    let home = files::test_home();
    let root = files::home().join(".vscode/extensions");
    let put = |dir: &str, json: &str| {
        std::fs::create_dir_all(root.join(dir)).unwrap();
        std::fs::write(root.join(dir).join("package.json"), json).unwrap();
    };
    put("ms-python.python-2026.1.0", r#"{"publisher": "ms-python", "name": "python", "version": "2026.1.0"}"#);
    put("gone.ext-1.0.0", r#"{"publisher": "gone", "name": "ext", "version": "1.0.0"}"#);
    put("broken-0.1", r#"{"publisher": null, "name": "broken", "version": 0.1}"#);
    put("nojson", "not json");
    std::fs::write(root.join(".obsolete"), r#"{"gone.ext-1.0.0": true}"#).unwrap();
    // Cursor's extensions exist, but Cursor itself is gone.
    let cursor = files::home().join(".cursor/extensions");
    std::fs::create_dir_all(cursor.join("x.y-1.0.0")).unwrap();
    std::fs::write(cursor.join("x.y-1.0.0/package.json"), r#"{"publisher": "x", "name": "y", "version": "1"}"#)
        .unwrap();
    let cli_of = |name: &str, _: &[&str], _: &str| if name == "code" { "/opt/code".to_string() } else { String::new() };
    let got = extensions_with(&cli_of);
    assert_eq!(got.len(), 1, "{got:?}");
    let c = &got[0];
    assert_eq!((c.kind.as_str(), c.name.as_str(), c.version.as_str()), ("extension", "ms-python.python", "2026.1.0"));
    assert_eq!(c.osv, Some(("VSCode".into(), "ms-python.python".into(), "2026.1.0".into())));
    assert_eq!(c.fix, "/opt/code --install-extension ms-python.python --force");
    assert!(c.auto);
    assert_eq!(c.extra["editor"], "VS Code");
    assert_eq!(c.extra["market"], "vscode");
    assert_eq!(c.extra["cli"], "/opt/code");
    assert_eq!(c.extra["dir"], root.join("ms-python.python-2026.1.0").display().to_string());
    // No extension directories at all in a fresh home: nothing, whatever is on PATH.
    std::fs::remove_dir_all(files::home().join(".vscode")).unwrap();
    std::fs::remove_dir_all(files::home().join(".cursor")).unwrap();
    assert!(extensions().is_empty());
    drop(home);
}
