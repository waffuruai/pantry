use super::*;

#[test]
fn scope_and_directness_from_the_root_and_the_flags() {
    let text = r#"{"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"debug": "2.6.8", "my-ms": "npm:ms@2.1.3"}, "devDependencies": {"minimist": "1.2.5"},
                 "optionalDependencies": {"fsevents": "2.3.3"}},
            "node_modules/debug": {"version": "2.6.8"},
            "node_modules/ms": {"version": "2.0.0"},
            "node_modules/debug/node_modules/ms": {"version": "2.1.3"},
            "node_modules/my-ms": {"name": "ms", "version": "2.1.3"},
            "node_modules/minimist": {"version": "1.2.5", "dev": true},
            "node_modules/fsevents": {"version": "2.3.3", "optional": true},
            "node_modules/semver": {"version": "7.5.4", "devOptional": true}}}"#;
    let got = parse(text).unwrap();
    let find = |name: &str, version: &str| got.iter().find(|p| p.name == name && p.version == version).unwrap();
    assert_eq!((find("debug", "2.6.8").scope, find("debug", "2.6.8").direct), (Scope::Runtime, Some(true)));
    assert_eq!(find("ms", "2.0.0").direct, Some(false), "hoisted, not the root's");
    assert_eq!(find("ms", "2.1.3").direct, Some(false), "nested under debug");
    assert!(
        got.iter().any(|p| p.name == "ms" && p.version == "2.1.3" && p.direct == Some(true)),
        "the alias my-ms is the root's"
    );
    assert_eq!((find("minimist", "1.2.5").scope, find("minimist", "1.2.5").direct), (Scope::Dev, Some(true)));
    assert_eq!(find("fsevents", "2.3.3").scope, Scope::Optional);
    assert_eq!((find("semver", "7.5.4").scope, find("semver", "7.5.4").direct), (Scope::Optional, Some(false)));
    let v1 = r#"{"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "dev": true}, "b": {"version": "2.0.0"}}}"#;
    let got = parse(v1).unwrap();
    assert_eq!((got[0].scope, got[0].direct), (Scope::Dev, None), "v1 says nothing about directness");
    assert_eq!(got[1].scope, Scope::Runtime);
}

/// A file with npm's key but not npm's shape is an error, never a
/// lockfile with no packages; the shapes npm writes for none still read
/// as empty.
#[test]
fn a_shape_npm_doesnt_write_is_an_error_not_empty() {
    for text in [
        r#"{"lockfileVersion": 3, "packages": []}"#,
        r#"{"lockfileVersion": 3, "packages": null}"#,
        r#"{"lockfileVersion": 3}"#,
        r#"{"lockfileVersion": 2, "dependencies": {}}"#,
        r#"{"lockfileVersion": 1, "dependencies": []}"#,
        r#"{"lockfileVersion": "3", "packages": {"": {}}}"#,
        r#"{"lockfileVersion": 4, "packages": {"": {}}}"#,
        r#"{"packages": {"": {}}}"#,
    ] {
        assert!(matches!(parse(text), Err(crate::error::Error::Invalid(_))), "{text}");
    }
    for text in [
        r#"{"lockfileVersion": 3, "packages": {"": {"name": "x"}}}"#,
        r#"{"lockfileVersion": 1, "dependencies": {}}"#,
        r#"{"name": "x", "version": "1.0.0", "lockfileVersion": 1}"#,
    ] {
        assert_eq!(parse(text).unwrap(), [], "{text}");
    }
}
