use super::*;
use crate::checks::supply_chain::testing::CARGO_LOCK;
use crate::checks::supply_chain::{projects, testing};
use crate::checks::{Options, Policy};
use crate::utils::temp::TempDir;

fn pkg(eco: &str, name: &str) -> Package {
    Package::new(eco, name, "1.0.0")
}

fn near(eco: &str, name: &str) -> Option<String> {
    find(&[pkg(eco, name)]).pop().map(|s| s.near)
}

#[test]
fn edits() {
    assert_eq!(edit("lodahs", "lodash"), Some(Edit::Transposition));
    assert_eq!(edit("lodas", "lodash"), Some(Edit::Omission));
    assert_eq!(edit("lodashs", "lodash"), Some(Edit::Omission));
    assert_eq!(edit("lodaash", "lodash"), Some(Edit::Duplication));
    assert_eq!(edit("expres", "express"), Some(Edit::Duplication));
    assert_eq!(edit("lodesh", "lodash"), Some(Edit::Substitution));
    assert_eq!(edit("@babe1", "@babel"), Some(Edit::Confusable));
    assert_eq!(edit("lodash", "underscore"), None);
    assert_eq!(edit("preact", "react"), Some(Edit::Omission));
    assert_eq!(edit("xml-js", "xml2js"), None, "a separator for a letter is a different word");
    assert_eq!(edit("uuidv4", "uuidv7"), None, "a digit for a digit is a version");
    assert_eq!(edit("0penai", "openai"), Some(Edit::Confusable), "a digit for a letter can be a look-alike");
    assert_eq!(edit("nodefetch", "node-fetch"), None, "a dropped separator is the registry's business");
    assert_eq!(distance("lodash", "lodahs"), 1);
    assert!(!is_typo(Edit::Substitution, 4), "mime is not a typo of time");
    assert!(is_typo(Edit::Transposition, 4));
}

#[test]
fn canonical_names() {
    assert_eq!(canon("Python_DateUtil"), "python-dateutil");
    assert_eq!(canon("socket.io"), "socket-io");
    assert_eq!(canon("foo--bar"), "foo-bar");
    assert_eq!(fold("ansi-colors"), "ansicolors");
}

#[test]
fn squats_warn_and_a_typo_beside_the_real_one_is_both() {
    let s = find(&[pkg("npm", "lodahs"), pkg("npm", "react"), pkg("npm", "express")]);
    assert_eq!(s.len(), 1, "{s:?}");
    assert_eq!((s[0].name.as_str(), s[0].near.as_str(), s[0].both), ("lodahs", "lodash", false));
    let s = find(&[pkg("npm", "lodahs"), pkg("npm", "lodash")]);
    assert!(s[0].both);
    assert!(find(&[pkg("npm", "preact"), pkg("npm", "react")]).is_empty(), "both popular");
    assert!(find(&[pkg("npm", "colors"), pkg("npm", "color")]).is_empty(), "both popular");
    assert!(
        find(&[pkg("npm", "nodefetch"), pkg("npm", "ansicolors"), pkg("npm", "query-string")]).is_empty(),
        "npm refuses a name that differs from an existing one only by punctuation: a name that does is the older one"
    );
    assert!(find(&[pkg("npm", "ms"), pkg("npm", "qs")]).is_empty(), "short names are skipped");
    assert_eq!(near("npm", "@babe1/core").as_deref(), Some("@babel/core"));
    assert!(find(&[pkg("npm", "@babel/core"), pkg("npm", "@mycompany/react")]).is_empty());
    assert!(
        find(&[pkg("npm", "@next/env"), pkg("npm", "@clack/core")]).is_empty(),
        "a scope a letter apart is a scope"
    );
    assert_eq!(near("npm", "lodesh").as_deref(), Some("lodash"));
    assert!(
        find(&[pkg("crates.io", "libm"), pkg("crates.io", "libc"), pkg("crates.io", "mime"), pkg("crates.io", "time")])
            .is_empty(),
        "short names a letter apart are words of their own"
    );
    assert!(find(&[pkg("npm", "ntapi")]).is_empty(), "five letters, one extra: a word of its own");
}

#[test]
fn separators_are_the_same_package() {
    assert!(find(&[pkg("PyPI", "python_dateutil")]).is_empty(), "PEP 503: one package");
    assert!(find(&[pkg("PyPI", "Scikit-Learn")]).is_empty());
    assert_eq!(near("PyPI", "reqeusts").as_deref(), Some("requests"));
    assert!(
        near("PyPI", "sklearn").is_none(),
        "too far from scikit-learn; the squat is in the malicious index instead"
    );
    assert!(find(&[pkg("crates.io", "serde"), pkg("crates.io", "serde_json")]).is_empty());
    assert!(find(&[pkg("crates.io", "serde-json")]).is_empty(), "crates.io reads - and _ as one name");
    assert_eq!(near("crates.io", "serde_jsn").as_deref(), Some("serde_json"));
    assert_eq!(near("crates.io", "serde-jsn").as_deref(), Some("serde_json"), "the slip is the missing letter");
    assert!(find(&[pkg("Go", "github.com/x/y")]).is_empty(), "no list for the ecosystem");
}

/// The pairs a real scan of a developer machine flagged, every one two
/// established packages, beside the squats the check is for. Four of
/// that scan's pairs still warn, the typed name being below every
/// ranking's cut: `scrypt`/`bcrypt`, `sqlite`/`sqlite3`,
/// `tslint-config-airbnb`/`eslint-config-airbnb`, `valirator`/`validator`.
#[test]
fn established_packages_are_not_typos_of_each_other() {
    let pairs = [
        ("query-string", "querystring"),
        ("scrypt-js", "bcryptjs"),
        ("stylis", "stylus"),
        ("crypt", "bcrypt"),
        ("queue", "p-queue"),
        ("tslint", "eslint"),
        ("motion", "emotion"),
        ("rc-motion", "remotion"),
        ("xml-js", "xml2js"),
        ("colord", "colors"),
        ("ansicolors", "ansi-colors"),
        ("emoticon", "emotion"),
        ("sha-1", "sha1"),
        ("ansistyles", "ansi-styles"),
        ("scrypt.js", "bcryptjs"),
        ("buffers", "buffer"),
        ("mquery", "jquery"),
        ("tokenize-rt", "tokenizers"),
        ("uuidv4", "uuidv7"),
    ];
    let packages: Vec<Package> = pairs.iter().flat_map(|(a, b)| [pkg("npm", a), pkg("npm", b)]).collect();
    let flagged: Vec<(String, String)> = find(&packages).into_iter().map(|s| (s.name, s.near)).collect();
    assert!(flagged.is_empty(), "{flagged:?}");
    for (typed, meant) in [("lodahs", "lodash"), ("@babe1/core", "@babel/core"), ("lodesh", "lodash")] {
        assert_eq!(near("npm", typed).as_deref(), Some(meant));
    }
    let s = find(&[pkg("npm", "lodahs"), pkg("npm", "lodash")]);
    assert!(s[0].both, "the typo beside the name meant");
}

#[test]
fn a_typosquat_in_the_suspect_policy_warns_instead() {
    let d = TempDir::new("typosquat").unwrap();
    let net = testing::osv_net(&[]);
    let policy = d.path().join("suspect.txt");
    std::fs::write(&policy, "SUSPECT-TYPOSQUAT\n").unwrap();
    let opts = Options { policy: Policy { suspect: Some(policy), ..Default::default() }, ..Default::default() };
    let mut s = testing::scan(&net, &d, opts);
    let (name, root) = testing::repo(&d, "app");
    testing::write(&root, "Cargo.lock", CARGO_LOCK);
    projects::projects(&mut s, &[(name, root)]).unwrap();
    let squat = testing::by_id(&s, "SUSPECT-TYPOSQUAT");
    assert_eq!(squat.len(), 1);
    assert_eq!(squat[0].status, "warn");
    assert!(squat[0].note.ends_with("(exempted by the suspect policy: still a warning)"), "{}", squat[0].note);
    // Without the popular one beside it, a warning on its own.
    let (name, root) = testing::repo(&d, "solo");
    testing::write(
        &root,
        "Cargo.lock",
        CARGO_LOCK.split("\n[[package]]\nname = \"sedre\"").next().unwrap().replace("serde", "sedre"),
    );
    projects::projects(&mut s, &[(name, root)]).unwrap();
    let solo = testing::by_id(&s, "SUSPECT-TYPOSQUAT");
    assert_eq!(solo.len(), 2, "{:?}", s.findings);
    assert_eq!(solo[1].status, "warn");
    assert_eq!(solo[1].note, "`sedre` is one keystroke from the popular `serde`");
    // No lockfiles at all: nothing is asked.
    let (name, root) = testing::repo(&d, "empty");
    projects::projects(&mut s, &[(name, root)]).unwrap();
    assert!(net.requests().iter().all(|r| r.url.ends_with("/v1/querybatch")));
}
