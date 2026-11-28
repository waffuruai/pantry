use super::*;
use crate::checks::Options;
use crate::checks::models::testing::{Gguf, TRIGGERED_DOWNLOAD, fake_pe};
use crate::checks::models::{FileResult, Meta, What};
use crate::checks::supply_chain::testing;
use crate::utils::net::Fake;
use crate::utils::temp::TempDir;

fn model(repo: &str, sha: Option<&str>, issues: Vec<Issue>) -> Model {
    Model {
        path: "/m/blobs/x".into(),
        rel: "blobs/x".into(),
        meta: Meta { repo: repo.into(), name: "m.gguf".into(), sha256: sha.map(String::from), ..Meta::default() },
        result: FileResult { what: What::Gguf, issues, split: 0 },
    }
}

/// Known bad: a listed repo or hash fails naming the entry; the twin, an
/// unlisted one, finds nothing.
#[test]
fn listed_models_fail_naming_the_entry() {
    let l = List::bundled();
    let bad = model("Mir2k/Inkling-2-Mini-Uncensored-GGUF", None, vec![]);
    let got = listed(&l, None, &bad);
    assert_eq!(got.len(), 1);
    assert!(got[0].note.contains("mir2k/inkling-2-mini-uncensored-gguf"), "{}", got[0].note);
    let h = "a95f9e00a5062b2f55a7d089696833965643765f40b2eae3b962d5952492f221";
    assert_eq!(listed(&l, None, &model("", Some(h), vec![]))[0].id, ids::KNOWN_BAD);
    assert!(listed(&l, None, &model("org/fine", Some(&"0".repeat(64)), vec![])).is_empty());
}

#[test]
fn a_finding_names_the_file_and_never_calls_it_safe() {
    let m = model("org/r", None, vec![]);
    assert_eq!(component(Where::Hub, None, &m), "org/r/m.gguf");
    assert_eq!(component(Where::Ollama, None, &m), "ollama org/r");
    assert_eq!(component(Where::Tree, Some("app"), &m), "app/blobs/x");
    assert_eq!(component(Where::Tree, None, &m), "/m/blobs/x");
    assert_eq!(finding(Where::Hub, None, &m, vec![]), None, "nothing found: no finding");
    let issues =
        vec![Issue::new(ids::NOT_CHECKED, Level::Unchecked, "why"), Issue::new(ids::HEADER, Level::Warn, "odd")];
    let f = finding(Where::Hub, None, &m, issues).unwrap();
    assert_eq!((f.kind.as_str(), f.status.as_str(), f.vuln_id.as_str()), ("model", "warn", ids::NOT_CHECKED));
    assert_eq!(f.note, "not checked: why; odd");
    assert_eq!(f.location, "/m/blobs/x");
    for id in ids::ALL {
        assert!(!fix(id).to_lowercase().contains("safe"), "{id}");
    }
}

/// End to end in a repo: a model with an appended program (an inert
/// stand-in) fails, a poisoned template file fails, a Modelfile's benign
/// twin and a clean model are counted, not reported.
#[test]
fn a_repo_scan_reports_models_and_counts_the_rest() {
    let d = TempDir::new("models-scan").unwrap();
    let net = Fake::offline();
    let mut s = testing::scan(&net, &d, Options::default());
    let (name, root) = testing::repo(&d, "app");
    testing::write(&root, "models/bad.gguf", [Gguf::default().bytes(), fake_pe(8192)].concat());
    testing::write(&root, "models/good.gguf", Gguf::default().bytes());
    testing::write(&root, "models/renamed.bin", [Gguf::default().bytes(), fake_pe(64)].concat());
    testing::write(&root, "templates/chat_template.jinja", TRIGGERED_DOWNLOAD);
    testing::write(&root, "Modelfile", "FROM ./models/good.gguf\nSYSTEM You are helpful.\n");
    testing::write(&root, "README.md", "not a model at all, but long enough to be read");
    s.repos = vec![(name, root)];
    models(&mut s);
    let mine: Vec<_> = s.findings.iter().filter(|f| f.kind == "model").collect();
    let by = |c: &str| mine.iter().find(|f| f.component == c).unwrap_or_else(|| panic!("{c} in {mine:#?}"));
    assert_eq!(
        (by("app/models/bad.gguf").status.as_str(), by("app/models/bad.gguf").vuln_id.as_str()),
        ("fail", ids::APPENDED_PROGRAM)
    );
    assert_eq!(by("app/models/renamed.bin").vuln_id, ids::APPENDED_PROGRAM, "found by its magic, whatever its name");
    assert_eq!(by("app/templates/chat_template.jinja").status, "fail");
    assert_eq!(mine.len(), 3, "{mine:#?}");
    assert!(s.counts.contains(&(CHECKED.to_string(), 5)), "{:?}", s.counts);
    // The second scan reads nothing: every result comes from the cache.
    let mut again = testing::scan(&net, &d, Options::default());
    again.repos = s.repos.clone();
    let before = crate::checks::files::view::opens(&again.repos[0].1.join("models/bad.gguf"));
    models(&mut again);
    assert_eq!(crate::checks::files::view::opens(&again.repos[0].1.join("models/bad.gguf")), before);
    assert_eq!(again.findings.iter().filter(|f| f.kind == "model").count(), 3);
}
