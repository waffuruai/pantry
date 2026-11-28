use super::*;
use crate::checks::models::testing::{Gguf, Val};

#[test]
fn template_and_modelfile_names() {
    for n in ["tokenizer_config.json", "Chat_Template.JSON", "chat_template.jinja", "x.jinja"] {
        assert!(is_template_file(n), "{n}");
    }
    assert!(!is_template_file("config.json"));
    for n in ["Modelfile", "modelfile.llama", "my.Modelfile"] {
        assert!(is_modelfile(n), "{n}");
    }
    assert!(!is_modelfile("model.gguf"));
}

/// A split model is judged only with all its parts beside it.
#[test]
fn split_shards_need_their_siblings() {
    let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let all = names(&["m-00001-of-00002.gguf", "m-00002-of-00002.gguf"]);
    assert_eq!(missing_siblings("m-00001-of-00002.gguf", 2, &all), None);
    let one = names(&["m-00001-of-00002.gguf"]);
    assert!(missing_siblings("m-00001-of-00002.gguf", 2, &one).unwrap().contains("1 of its parts"));
    assert!(missing_siblings("m.gguf", 2, &one).unwrap().contains("doesn't say"));
    assert!(missing_siblings("m-00001-of-00003.gguf", 2, &one).unwrap().contains("the name says 3"));

    let d = crate::utils::temp::TempDir::new("split").unwrap();
    let mut g = Gguf::default();
    g.kvs.push(("split.count".into(), Val::U16(2)));
    std::fs::write(d.path().join("m-00001-of-00002.gguf"), g.bytes()).unwrap();
    let found = scan_dir(Where::Tree, d.path(), DEPTH);
    assert_eq!(found[0].result.issues[0].id, ids::NOT_CHECKED);
    std::fs::write(d.path().join("m-00002-of-00002.gguf"), g.bytes()).unwrap();
    crate::utils::walk::forget_walks();
    let found = scan_dir(Where::Tree, d.path(), DEPTH);
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|m| m.result.issues.is_empty()), "{found:#?}");
}

/// What the cache keeps reads back as it was.
#[test]
fn results_round_trip_through_json() {
    let r = Some(FileResult {
        what: What::Gguf,
        issues: vec![Issue::new(ids::APPENDED_PROGRAM, Level::Fail, "n"), Issue::new(ids::HEADER, Level::Warn, "w")],
        split: 3,
    });
    assert_eq!(from_json(&to_json(&r)), Some(r));
    assert_eq!(from_json(&to_json(&None)), Some(None));
    let t = Some(FileResult { what: What::Template, issues: vec![], split: 0 });
    assert_eq!(from_json(&to_json(&t)), Some(t));
    assert_eq!(from_json(&serde_json::json!({"w": "gguf", "s": 0, "i": [["NOPE", "fail", "x"]]})), None);
    assert_eq!(from_json(&serde_json::json!("x")), None);
    for l in [Level::Fail, Level::Unchecked, Level::Warn] {
        assert_eq!(Level::of(l.word()), Some(l));
    }
}

/// Machine stores are jobs only on a machine scan; a store under a
/// left-out folder is not read.
#[test]
fn jobs_cover_repos_and_stores() {
    let _home = crate::utils::files::test_home();
    let home = crate::utils::files::home();
    std::fs::create_dir_all(home.join(".lmstudio/models")).unwrap();
    let repos = vec![home.join("code/app")];
    assert_eq!(jobs(&repos, false, &home).len(), 1);
    assert_eq!(jobs(&repos, true, &home).len(), 2);
    let _g = crate::utils::privacy::leave_out(vec![home.join(".lmstudio")], vec![]);
    assert_eq!(jobs(&repos, true, &home).len(), 1);
}
