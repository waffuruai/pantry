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
    let home = system::home().display().to_string();
    let mut out = Vec::new();
    for (editor, root, market, cli_name, apps, cli_rel) in EDITORS {
        let root = root.replacen('~', &home, 1);
        let cli = which(cli_name).map(|p| p.display().to_string()).unwrap_or_else(|| app_cli(apps, cli_rel));
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

    // The Python test vector (python/test_wscanner.py `SupplyChain.test_bundled_npm`).
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
}
