use super::*;

#[test]
fn each_rule_is_listed_once_by_its_file() {
    for (i, r) in RULES.iter().enumerate() {
        assert!(RULES[..i].iter().all(|o| o.name != r.name), "{} twice", r.name);
        assert!(r.source.contains("pub(super) fn scan("), "{}'s source is its file", r.name);
    }
    assert_eq!(RULES.len(), 10);
}

#[test]
fn contexts() {
    assert_eq!(context("a/b/package.json"), Context::Manifest);
    assert_eq!(context("x.tsx"), Context::Web);
    assert_eq!(context("k.metal"), Context::Native);
    assert_eq!(context("s.scss"), Context::Style);
    assert_eq!(context("README.md"), Context::Prompt);
    assert_eq!(context("rules/.cursorrules"), Context::Prompt);
    assert_eq!(context("config/.env"), Context::Data);
    assert_eq!(context("data/events.log"), Context::Data);
    assert_eq!(context("conf/app.yaml"), Context::Data);
    assert_eq!(context("x.bin"), Context::Other);
    assert_eq!(context(".github/workflows/ci.yml"), Context::Shell);
    assert_eq!(context("Dockerfile"), Context::Shell);
    assert_eq!(context("docker/Dockerfile.ci"), Context::Shell);
    assert_eq!(context("site/index.html"), Context::Markup);
    assert_eq!(context("tool.py"), Context::Python);
    assert_eq!(context("Makefile"), Context::Manifest);
}

#[test]
fn paths_that_are_output_or_tests() {
    assert!(generated_path("dist/app.js"));
    assert!(generated_path("site/.next/static/a.js"));
    assert!(!generated_path("src/distribute.js"), "a name that merely contains `dist`");
    assert!(test_path("src/__tests__/a.js"));
    assert!(test_path("a/b.spec.ts"));
    assert!(!test_path("src/attestation.ts"), "a name that merely contains `test`");
}

#[test]
fn line_helpers() {
    assert_eq!(line_of("a\nb\nc", "c"), 3);
    assert_eq!(line_of("a\nb", "z"), 0, "absent is 0, not a panic");
    assert_eq!(line_at("a\nb\nc", 4), 3);
    assert_eq!(has_any("x eval( y", &["atob(", "eval("]), Some("eval("));
    assert_eq!(has_any("plain", &["atob("]), None);
}

#[test]
fn policy_parses_ids_and_paths() {
    let p =
        Policy::parse("# mine\nids = [\"SUSPECT-PRIV-ESCALATION\", \"  raw-ip \"]\npaths = [\" scripts/legacy/\"]\n");
    assert_eq!(p.ids, ["PRIV-ESCALATION", "RAW-IP"]);
    assert_eq!(p.paths, ["scripts/legacy/"]);
    let hit = Suspect { file: "x.js".into(), id: "SUSPECT-RAW-IP", line: 1, note: String::new(), hard: true };
    assert!(p.exempt(&hit));
    assert!(p.exempt(&Suspect { file: "scripts/legacy/a.js".into(), id: "SUSPECT-X", ..hit.clone() }));
    assert!(!p.exempt(&Suspect { id: "SUSPECT-WALLET-SIGNING", ..hit.clone() }));
    let mut v = vec![hit.clone(), Suspect { hard: false, ..hit }];
    apply_policy(&mut v, &p);
    assert!(v.iter().all(|s| !s.hard));
    assert!(v[0].note.contains("exempted") && !v[1].note.contains("exempted"), "only a downgrade says so");
}

#[test]
fn policy_downgrades_but_never_silences() {
    let p = Policy::parse("# mine\nids = [\"SUSPECT-PRIV-ESCALATION\"]\npaths = [\"scripts/legacy/\"]\n");
    let d = crate::utils::temp::TempDir::new("suspect").unwrap();
    std::fs::create_dir_all(d.path().join("scripts/legacy")).unwrap();
    std::fs::write(d.path().join("scripts/legacy/old.js"), "eval(atob('x'))").unwrap();
    std::fs::write(d.path().join("package.json"), "{\"scripts\": {\"postinstall\": \"chmod u+s x\"}}").unwrap();
    let got = scan_dir(d.path(), Kind::Repo, &p);
    assert_eq!(got.len(), 2, "{got:?}");
    assert!(got.iter().all(|s| !s.hard), "{got:?}");
    assert!(got.iter().all(|s| s.note.contains("exempted")));
    let strict = scan_dir(d.path(), Kind::Repo, &Policy::default());
    assert!(strict.iter().all(|s| s.hard), "{strict:?}");
}

#[test]
fn walk_skips_output_and_pairs_pages_with_signing() {
    let d = crate::utils::temp::TempDir::new("suspect-walk").unwrap();
    let root = d.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("out")).unwrap();
    std::fs::write(root.join("out/app.js"), "eval(atob('x'))").unwrap();
    std::fs::write(root.join("README.md"), "eval(atob('x')) and sudo rm -rf /").unwrap();
    std::fs::write(root.join("src/swap.ts"), "import { ethers } from 'ethers';\nsigner.signTypedData(d, t, v);\n")
        .unwrap();
    std::fs::write(root.join("index.html"), "<script src=\"https://cdn.example/t.js\"></script>").unwrap();
    let got = scan_dir(root, Kind::Repo, &Policy::default());
    assert_eq!(
        ids(&got),
        [("SUSPECT-THIRD-PARTY-SCRIPT", true), ("SUSPECT-WALLET-SIGNING", false)],
        "sorted by file; the page fails because the project signs: {got:?}"
    );
    assert_eq!((got[0].file.as_str(), got[1].file.as_str()), ("index.html", "src/swap.ts"));
    let installed = scan_dir(root, Kind::Installed, &Policy::default());
    assert!(installed.iter().any(|s| s.file == "out/app.js"), "installed code is read wherever it sits");
}
