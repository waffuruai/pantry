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
    let got = repo_issue(&l, "Mir2k/Inkling-2-Mini-Uncensored-GGUF").unwrap();
    assert_eq!(got.id, ids::KNOWN_BAD);
    assert!(got.note.contains("mir2k/inkling-2-mini-uncensored-gguf"), "{}", got.note);
    let bad = model("Mir2k/Inkling-2-Mini-Uncensored-GGUF", None, vec![]);
    assert!(listed(&l, None, Where::Hub, &bad).is_empty(), "a hub repo is judged once per repo, not per file");
    let h = "a95f9e00a5062b2f55a7d089696833965643765f40b2eae3b962d5952492f221";
    assert_eq!(listed(&l, None, Where::Tree, &model("", Some(h), vec![]))[0].id, ids::KNOWN_BAD);
    assert!(listed(&l, None, Where::Hub, &model("org/fine", Some(&"0".repeat(64)), vec![])).is_empty());
}

/// Each level gives its id and status: repo, hash and Ollama model fail;
/// a demonstration repo and another repo of a listed account warn; an
/// unlisted repo of an unlisted account, the twin, finds nothing.
#[test]
fn each_list_level_gives_its_id_and_status() {
    let l = List::parse(
        "source = \"the test list\"\nrepos = [\"Bad/one\"]\nsha256 = []\nollama = [\"evil/chat\"]\nowners = [\"Bad\"]\ndemos = [\"lab/poc\", \"Bad/one\"]\n",
    );
    let status = |at: Where, repo: &str| {
        let m = model(repo, None, vec![]);
        let issues = super::super::sorted(listed(&l, None, at, &m));
        finding(at, None, &m, issues).map(|f| (f.vuln_id, f.status, f.note))
    };
    let repo = |r: &str| repo_issue(&l, r).map(|i| (i.id, i.level, i.note));
    let (id, level, _) = repo("bad/one").unwrap();
    assert_eq!((id, level), (ids::KNOWN_BAD, Level::Fail), "malicious wins over demo");
    let (id, level, note) = repo("Bad/other").unwrap();
    assert_eq!((id, level), (ids::KNOWN_BAD_OWNER, Level::Warn));
    assert!(note.contains("bad") && note.contains("isn't on the list itself"), "{note}");
    let (id, level, note) = repo("lab/poc").unwrap();
    assert_eq!((id, level), (ids::RESEARCH_DEMO, Level::Warn));
    assert!(note.contains("public demonstration of an attack"), "{note}");
    assert_eq!(repo("lab/other"), None);
    assert_eq!(status(Where::Hub, "bad/one"), None, "per repo, not per file");
    let (id, st, _) = status(Where::Ollama, "evil/chat:latest").unwrap();
    assert_eq!((id.as_str(), st.as_str()), (ids::KNOWN_BAD, "fail"), "any tag");
    let (id, _, _) = status(Where::Ollama, "hf.co/Bad/one:Q4_K_M").unwrap();
    assert_eq!(id, ids::KNOWN_BAD, "an Ollama pull from the hub is the hub repo");
    assert_eq!(status(Where::Ollama, "hf.co/Bad/other:Q4").unwrap().0, ids::KNOWN_BAD_OWNER);
    assert_eq!(status(Where::Ollama, "evil/chatty:latest"), None);
    assert_eq!(status(Where::Tree, "bad/one"), None, "a repo file has no hub repo");
    // Severity: the warn row other model warnings use; known bad is Critical.
    for (id, st, want) in [
        (ids::KNOWN_BAD_OWNER, "warn", "LOW"),
        (ids::RESEARCH_DEMO, "warn", "LOW"),
        (ids::DATA_GAP, "warn", "LOW"),
        (ids::DATA_GAP, "fail", "HIGH"),
        (ids::KNOWN_BAD, "fail", "CRITICAL"),
    ] {
        let f = Finding { kind: "model".into(), vuln_id: id.into(), status: st.into(), ..Default::default() };
        assert_eq!(crate::checks::severity::own(&f), want, "{id} {st}");
    }
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

/// A hub cache with no GGUF in it: a safetensors-only repo's benign
/// template is read (and so counted) and says nothing, a poisoned one
/// fails, a listed repo holding only safetensors fails once (component the
/// repo id), and another repo of a listed account warns once. Read the way
/// `models` reads a hub job, without a machine scan's other passes.
#[cfg(unix)]
#[test]
fn a_hub_cache_without_ggufs_is_read() {
    use crate::checks::models::testing::CHATML;
    use std::os::unix::fs::symlink;
    let d = TempDir::new("models-hub").unwrap();
    let hub = d.path().join("hub");
    let repo = |id: &str, template: Option<&str>| {
        let dir = hub.join(format!("models--{}", id.replace('/', "--")));
        let snap = dir.join("snapshots/r1");
        std::fs::create_dir_all(&snap).unwrap();
        testing::write(&dir, "refs/main", "r1\n");
        // A stand-in for the weights: never parsed.
        testing::write(&dir, "blobs/weights", "not a real safetensors file, only a stand-in");
        symlink("../../blobs/weights", snap.join("model.safetensors")).unwrap();
        if let Some(t) = template {
            testing::write(&dir, "blobs/config", serde_json::json!({ "chat_template": t }).to_string());
            symlink("../../blobs/config", snap.join("tokenizer_config.json")).unwrap();
        }
    };
    repo("org/benign", Some(CHATML));
    repo("org/poisoned", Some(TRIGGERED_DOWNLOAD));
    repo("Mir2k/Inkling-2-Mini-Uncensored-GGUF", None);
    repo("Mir2k/some-new-upload", Some(CHATML));
    let list = List::bundled();
    let read = crate::checks::models::scan_dir(Where::Hub, &hub, crate::utils::walk::DEEPEST);
    assert_eq!(read.len(), 3, "the three templates are read and counted: {read:#?}");
    let files: Vec<Finding> = read
        .iter()
        .filter_map(|m| {
            let mut issues = m.result.issues.clone();
            issues.extend(listed(&list, None, Where::Hub, m));
            finding(Where::Hub, None, m, super::super::sorted(issues))
        })
        .collect();
    assert_eq!(files.len(), 1, "{files:#?}");
    assert_eq!((files[0].component.as_str(), files[0].status.as_str()), ("org/poisoned/tokenizer_config.json", "fail"));
    let repos = hub_repos(&list, &hub);
    assert_eq!(repos.len(), 2, "{repos:#?}");
    let by = |c: &str| repos.iter().find(|f| f.component == c).unwrap_or_else(|| panic!("{c}"));
    let listed_repo = by("Mir2k/Inkling-2-Mini-Uncensored-GGUF");
    assert_eq!((listed_repo.status.as_str(), listed_repo.vuln_id.as_str()), ("fail", ids::KNOWN_BAD));
    let owner = by("Mir2k/some-new-upload");
    assert_eq!((owner.status.as_str(), owner.vuln_id.as_str()), ("warn", ids::KNOWN_BAD_OWNER));
    assert!(hub_repos(&list, &d.path().join("absent")).is_empty());
}
