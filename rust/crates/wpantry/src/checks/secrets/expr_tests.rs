use super::*;

fn env(secret: &str, path: &str) -> Env<'static> {
    Env {
        finding: vec![
            ("secret", Value::Str(secret.into())),
            ("match", Value::Str(format!("key = {secret}").into_bytes())),
            ("fragment_raw", Value::Str(format!("a\nkey = {secret}\nb").into_bytes())),
            ("match_start_idx", Value::Num(2.0)),
            ("match_end_idx", Value::Num(8.0 + secret.len() as f64)),
        ],
        attributes: vec![("path", Value::Str(path.into()))],
        confidence: Default::default(),
        _text: Default::default(),
    }
}

fn run(src: &str, secret: &str) -> Option<bool> {
    Program::compile(src).expect("compiles").skips(&env(secret, "src/app.rs"))
}

#[test]
fn checks_combine_with_or_and_not_and_ternaries() {
    assert_eq!(
        run(r#"entropy(finding["secret"]) <= 2.0 || containsAny(finding["secret"], ["TEST"])"#, "abc_test"),
        Some(true)
    );
    assert_eq!(run(r#"!filter.matchesAny(finding["secret"], [`[0-9]`])"#, "abc"), Some(true));
    assert_eq!(run(r#"len(finding["secret"]) > 3 ? false : true"#, "abcd"), Some(false));
    assert_eq!(run(r#"filter.matchesAny(attributes["path"], [`(?i)\.RS$`]) && true"#, "x"), Some(true));
}

#[test]
fn lets_slices_and_string_functions() {
    let src = r#"
        // the text before the match, clamped
        let before = finding["fragment_raw"][max(finding["match_start_idx"] - 50, 0):finding["match_start_idx"]];
        let lines = split(before, "\n");
        lines[len(lines) - 2] == "a" && lower("KEY") contains "ke" && join(["x", "y"], "-") == "x-y"
    "#;
    assert_eq!(run(src, "s3cr3t"), Some(true));
    let src = r#"(let p = filter.findMatch(finding["match"], `^[\w ]+`); p == "key ")"#;
    assert_eq!(run(src, "v"), Some(true));
}

#[test]
fn set_confidence_is_recorded() {
    let e = env("x", "");
    let p = Program::compile(r#"let _ = filter.setConfidence("medium"); false"#).unwrap();
    assert_eq!(p.skips(&e), Some(false));
    assert_eq!(e.confidence.borrow().as_deref(), Some("medium"));
}

#[test]
fn a_failing_program_has_no_verdict_and_bad_syntax_is_an_error() {
    assert_eq!(run(r#"nosuch(finding["secret"])"#, "x"), None);
    assert_eq!(run(r#"finding["secret"] - 1"#, "x"), None);
    assert!(Program::compile("a ||").is_err());
    assert!(Program::compile("`open").is_err());
}
