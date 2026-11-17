use super::super::{Kind, ids, scan_text};
use super::*;

#[test]
fn a_known_weak_password_fails() {
    let got = scan_text("config/app.env", "DB_PASSWORD=letmein\n", Kind::Repo);
    assert_eq!(ids(&got), [("SUSPECT-WEAK-PASSWORD", true)], "{got:?}");
    assert!(got[0].note.contains("known default or weak"), "{}", got[0].note);
    assert_eq!(
        ids(&scan_text("conf/db.yaml", "password: changeme\n", Kind::Repo)),
        [("SUSPECT-WEAK-PASSWORD", true)],
        "an unquoted weak value in yaml fails"
    );
    assert_eq!(
        ids(&scan_text("src/db.py", "admin_password = \"123456\"\n", Kind::Repo)),
        [("SUSPECT-WEAK-PASSWORD", true)]
    );
}

#[test]
fn a_hardcoded_literal_warns_and_placeholders_are_skipped() {
    let got = scan_text("src/config.js", "const pwd = \"s3rvice-Acct!\";\n", Kind::Repo);
    assert_eq!(ids(&got), [("SUSPECT-WEAK-PASSWORD", false)], "a non-weak literal warns: {got:?}");
    assert!(got[0].note.contains("hardcoded password literal"), "{}", got[0].note);
    assert!(scan_text("src/a.py", "password = os.environ['PW']\n", Kind::Repo).is_empty(), "an env lookup");
    assert!(scan_text("app.yaml", "password: ${DB_PASS}\n", Kind::Repo).is_empty(), "a variable");
    assert!(scan_text("tpl.yaml", "password: \"<your password>\"\n", Kind::Repo).is_empty(), "a placeholder");
    assert!(scan_text("ci.yml", "password: ${{ secrets.DEPLOY }}\n", Kind::Repo).is_empty(), "a CI secret ref");
    assert!(
        scan_text("src/config.js", "const dbPassword = process.env.DB_PASS;\n", Kind::Repo).is_empty(),
        "an unquoted env read does not warn"
    );
}

#[test]
fn tests_native_and_comparisons_are_left_alone() {
    assert!(scan_text("tests/data/seed.env", "PASSWORD=letmein\n", Kind::Repo).is_empty(), "a test path is skipped");
    assert!(scan_text("src/main.rs", "let password = \"letmein\";\n", Kind::Repo).is_empty(), "native is not read");
    assert!(
        scan_text("src/check.py", "if password == user_input:\n", Kind::Repo).is_empty(),
        "a comparison is not an assignment"
    );
    assert_eq!(assignment("PASSWORD=hunter2").map(|(_, v, q)| (v, q)), Some(("hunter2".into(), false)));
    assert_eq!(assignment("  secret: \"abc\"").map(|(_, v, q)| (v, q)), Some(("abc".into(), true)));
    assert_eq!(assignment("keyboard = 3"), None, "the key must be a password word");
    assert!(placeholder("${X}") && placeholder("xxx") && !placeholder("hunter2"));
}

#[test]
fn dictionary_words_warn_and_defaults_fail() {
    // monkey/sunshine are common but not shipped defaults: warn, not fail.
    assert_eq!(
        ids(&scan_text("conf/app.yaml", "password: monkey\n", Kind::Repo)),
        [("SUSPECT-WEAK-PASSWORD", false)],
        "a common dictionary password warns, it does not fail"
    );
    let got = scan_text("conf/app.yaml", "password: sunshine\n", Kind::Repo);
    assert_eq!(ids(&got), [("SUSPECT-WEAK-PASSWORD", false)]);
    assert!(got[0].note.contains("common, easily-guessed"), "{}", got[0].note);
    // changeme stays a hard fail: a shipped default, not a real secret.
    assert_eq!(ids(&scan_text("conf/app.yaml", "password: changeme\n", Kind::Repo)), [("SUSPECT-WEAK-PASSWORD", true)]);
}

#[test]
fn normalization_catches_simple_mutations() {
    assert_eq!(
        ids(&scan_text("a.env", "ADMIN_PASSWORD=Admin1\n", Kind::Repo)),
        [("SUSPECT-WEAK-PASSWORD", true)],
        "a trailing digit does not hide a default"
    );
    assert_eq!(
        ids(&scan_text("a.env", "PASSWORD=p@ssw0rd\n", Kind::Repo)),
        [("SUSPECT-WEAK-PASSWORD", true)],
        "leet substitutions are undone"
    );
    assert_eq!(
        ids(&scan_text("a.yaml", "password: Monkey99!\n", Kind::Repo)),
        [("SUSPECT-WEAK-PASSWORD", false)],
        "a mutated dictionary word still warns"
    );
    assert_eq!(normalize("p@ssw0rd"), "password");
    assert_eq!(normalize("admin1"), "admin");
    assert_eq!(normalize("monkey99!"), "monkey");
    assert!(classify("Tr0ub4dour&3xplr").is_none(), "a strong password is not matched");
}
