//! Extensions of VS Code-family editors, and the npm packages they bundle.
//!
//! An editor counts only when it's installed: its leftover extensions on
//! disk never run, so they don't apply.

use crate::check_supply::quote;
use crate::system::{self, Component, app_cli, expand, read_json, which};
use std::collections::BTreeSet;
use std::path::Path;

/// (editor, extensions dir, marketplace, CLI name, app names, CLI path inside the app)
pub type Editor = (&'static str, &'static str, &'static str, &'static str, &'static [&'static str], &'static str);

pub const EDITORS: &[Editor] = &[
    ("VS Code", "~/.vscode/extensions", "vscode", "code", &["Visual Studio Code"], "bin/code"),
    (
        "VS Code Insiders",
        "~/.vscode-insiders/extensions",
        "vscode",
        "code-insiders",
        &["Visual Studio Code - Insiders"],
        "bin/code",
    ),
    ("Cursor", "~/.cursor/extensions", "openvsx", "cursor", &["Cursor"], "bin/cursor"),
    ("Windsurf", "~/.windsurf/extensions", "openvsx", "windsurf", &["Windsurf"], "bin/windsurf"),
    ("VSCodium", "~/.vscode-oss/extensions", "openvsx", "codium", &["VSCodium"], "bin/codium"),
    ("Antigravity", "~/.antigravity/extensions", "openvsx", "antigravity", &["Antigravity"], "bin/antigravity"),
    ("Kiro", "~/.kiro/extensions", "openvsx", "kiro", &["Kiro"], "bin/kiro"),
];

pub fn ecosystem(market: &str) -> &'static str {
    if market == "vscode" { "VSCode" } else { "VSCode:https://open-vsx.org" }
}

fn text(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        o => o.to_string(),
    }
}

/// Extension components, extra = {editor, market, cli, id (as published), dir}.
pub fn extensions() -> Vec<Component> {
    extensions_with(&|cli_name, apps, cli_rel| {
        which(cli_name).map(|p| p.display().to_string()).unwrap_or_else(|| app_cli(apps, cli_rel))
    })
}

/// `extensions`, with `cli_of(cli name, app names, CLI path in the app)`
/// finding an editor's CLI ("" when the editor isn't installed).
fn extensions_with(cli_of: &dyn Fn(&str, &[&str], &str) -> String) -> Vec<Component> {
    let home = system::home().display().to_string();
    let mut out = Vec::new();
    for (editor, root, market, cli_name, apps, cli_rel) in EDITORS {
        let root = root.replacen('~', &home, 1);
        let cli = cli_of(cli_name, apps, cli_rel);
        if !Path::new(&root).is_dir() || cli.is_empty() {
            continue;
        }
        let obsolete: BTreeSet<String> = read_json(&Path::new(&root).join(".obsolete"))
            .and_then(|o| o.as_object().map(|m| m.keys().cloned().collect()))
            .unwrap_or_default();
        for manifest in expand(&[format!("{root}/*/package.json")]) {
            let dir = Path::new(&manifest).parent().map(|p| p.display().to_string()).unwrap_or_default();
            let base = Path::new(&dir).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let pkg = read_json(Path::new(&manifest)).unwrap_or_default();
            let (publisher, name, version) = (text(&pkg["publisher"]), text(&pkg["name"]), text(&pkg["version"]));
            if obsolete.contains(&base) || publisher.is_empty() || name.is_empty() || version.is_empty() {
                continue;
            }
            let id = format!("{publisher}.{name}");
            let q = quote(&cli);
            let mut c = Component::new("extension", &id.to_lowercase(), &version, &dir);
            c.osv = Some((ecosystem(market).into(), id.clone(), version.clone()));
            c.fix = format!("{q} --install-extension {id} --force");
            c.auto = true;
            for (k, v) in
                [("editor", editor.to_string()), ("market", market.to_string()), ("cli", q), ("id", id), ("dir", dir)]
            {
                c.extra.insert(k.into(), v);
            }
            out.push(c);
        }
    }
    out
}

/// (name, version) of every npm package shipped in node_modules under root:
/// an editor extension, a harness plugin, a desktop extension.
pub fn bundled_npm(root: &Path) -> Vec<(String, String)> {
    fn visit(d: &Path, root: &Path, found: &mut BTreeSet<(String, String)>) {
        let rel = d.strip_prefix(root).map(|r| r.to_string_lossy().matches("node_modules").count()).unwrap_or(0);
        if rel > 6 {
            return;
        }
        let parent =
            d.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let grand = d
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if (parent == "node_modules" || (parent.starts_with('@') && grand == "node_modules"))
            && let Some(pkg) = read_json(&d.join("package.json"))
        {
            let (n, v) = (text(&pkg["name"]), text(&pkg["version"]));
            if !n.is_empty() && !v.is_empty() {
                found.insert((n, v));
            }
        }
        let Ok(rd) = std::fs::read_dir(d) else { return };
        let mut subs: Vec<_> =
            rd.filter_map(|e| e.ok()).filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.path()).collect();
        subs.sort();
        for s in subs {
            visit(&s, root, found);
        }
    }
    let mut found = BTreeSet::new();
    visit(root, root, &mut found);
    found.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The test vector the Python implementation had (`SupplyChain.test_bundled_npm`).
    #[test]
    fn bundled_npm_packages() {
        let d = system::TempDir::new("bundled").unwrap();
        for (rel, name, ver) in [
            ("node_modules/a", "a", "1.0.0"),
            ("node_modules/@s/b", "@s/b", "2.0.0"),
            ("node_modules/a/node_modules/c", "c", "3.0.0"),
            ("src/not-a-dep", "d", "4"),
        ] {
            std::fs::create_dir_all(d.path().join(rel)).unwrap();
            std::fs::write(
                d.path().join(rel).join("package.json"),
                format!(r#"{{"name": "{name}", "version": "{ver}"}}"#),
            )
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
        let d = system::TempDir::new("deep").unwrap();
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
    #[cfg(unix)]
    #[test]
    fn extensions_of_installed_editors() {
        let home = system::test_home();
        let root = system::home().join(".vscode/extensions");
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
        let cursor = system::home().join(".cursor/extensions");
        std::fs::create_dir_all(cursor.join("x.y-1.0.0")).unwrap();
        std::fs::write(cursor.join("x.y-1.0.0/package.json"), r#"{"publisher": "x", "name": "y", "version": "1"}"#)
            .unwrap();
        let cli_of =
            |name: &str, _: &[&str], _: &str| if name == "code" { "/opt/code".to_string() } else { String::new() };
        let got = extensions_with(&cli_of);
        assert_eq!(got.len(), 1, "{got:?}");
        let c = &got[0];
        assert_eq!(
            (c.kind.as_str(), c.name.as_str(), c.version.as_str()),
            ("extension", "ms-python.python", "2026.1.0")
        );
        assert_eq!(c.osv, Some(("VSCode".into(), "ms-python.python".into(), "2026.1.0".into())));
        assert_eq!(c.fix, "/opt/code --install-extension ms-python.python --force");
        assert!(c.auto);
        assert_eq!(c.extra["editor"], "VS Code");
        assert_eq!(c.extra["market"], "vscode");
        assert_eq!(c.extra["cli"], "/opt/code");
        assert_eq!(c.extra["dir"], root.join("ms-python.python-2026.1.0").display().to_string());
        // No extension directories at all in a fresh home: nothing, whatever is on PATH.
        std::fs::remove_dir_all(system::home().join(".vscode")).unwrap();
        std::fs::remove_dir_all(system::home().join(".cursor")).unwrap();
        assert!(extensions().is_empty());
        drop(home);
    }
}
