use super::*;

#[test]
fn keys_across_versions() {
    assert_eq!(split_key("'@babel/core@7.22.0'", false), ("@babel/core".into(), "7.22.0".into()));
    assert_eq!(split_key("/react-dom@18.2.0(react@18.2.0)", false), ("react-dom".into(), "18.2.0".into()));
    assert_eq!(split_key("/@types/node/20.1.0", true), ("@types/node".into(), "20.1.0".into()));
    assert_eq!(split_key("/foo/1.0.0_react@18.2.0", true), ("foo".into(), "1.0.0".into()));
    assert_eq!(
        split_key("foo@https://codeload.github.com/x/y/tar.gz/abc", false).1,
        "https://codeload.github.com/x/y/tar.gz/abc"
    );
}

#[test]
fn importers_say_what_is_direct_and_in_which_scope() {
    let text = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      debug:\n        specifier: 2.6.8\n        version: 2.6.8\n      my-ms:\n        specifier: npm:ms@2.1.3\n        version: ms@2.1.3\n      react-dom:\n        specifier: ^18\n        version: 18.2.0(react@18.2.0)\n    devDependencies:\n      minimist:\n        specifier: 1.2.5\n        version: 1.2.5\n\npackages:\n\n  debug@2.6.8:\n    resolution: {integrity: sha512-x}\n\n  minimist@1.2.5:\n    resolution: {integrity: sha512-x}\n\n  ms@2.0.0:\n    resolution: {integrity: sha512-x}\n\n  ms@2.1.3:\n    resolution: {integrity: sha512-x}\n\n  react-dom@18.2.0:\n    resolution: {integrity: sha512-x}\n";
    let got = parse(text).unwrap();
    let find = |n: &str, v: &str| got.iter().find(|p| p.name == n && p.version == v).unwrap();
    assert_eq!((find("debug", "2.6.8").scope, find("debug", "2.6.8").direct), (Scope::Runtime, Some(true)));
    assert_eq!((find("minimist", "1.2.5").scope, find("minimist", "1.2.5").direct), (Scope::Dev, Some(true)));
    assert_eq!((find("ms", "2.0.0").scope, find("ms", "2.0.0").direct), (Scope::Unknown, Some(false)));
    assert_eq!(find("ms", "2.1.3").direct, Some(true), "the alias resolves to the real package");
    assert_eq!(find("react-dom", "18.2.0").direct, Some(true), "the peer suffix is dropped");
    let v6 = "lockfileVersion: '6.0'\n\npackages:\n\n  /a@1.0.0:\n    resolution: {integrity: sha512-x}\n    dev: true\n\n  /b@2.0.0:\n    resolution: {integrity: sha512-x}\n    dev: false\n";
    let got = parse(v6).unwrap();
    assert_eq!((got[0].scope, got[0].direct), (Scope::Dev, None), "no importers: directness unknown");
    assert_eq!(got[1].scope, Scope::Runtime);
}

/// A file with pnpm's keys but not pnpm's shape is an error, never a
/// lockfile with no packages; one reindented by hand still reads.
#[test]
fn a_shape_pnpm_doesnt_write_is_an_error_and_indentation_is_followed() {
    for text in [
        "lockfileVersion: [\n",
        "lockfileVersion: '9.0'\n\npackages: {\n",
        "lockfileVersion: '9.0'\n\nimporters: [\n",
        "lockfileVersion: '9.0'\n\npackages:\n  a@1.0.0:\n   resolution: {integrity: sha512-x}\n",
    ] {
        assert!(matches!(parse(text), Err(crate::error::Error::Invalid(_))), "{text:?}");
    }
    assert_eq!(parse("lockfileVersion: '9.0'\n\npackages: {}\n").unwrap(), []);
    let two = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      debug:\n        specifier: 2.6.8\n        version: 2.6.8\n\npackages:\n\n  debug@2.6.8:\n    resolution: {integrity: sha512-x}\n\n  ms@2.0.0:\n    resolution: {integrity: sha512-x}\n";
    let four = "lockfileVersion: '9.0'\n\nimporters:\n\n    .:\n        dependencies:\n            debug:\n                specifier: 2.6.8\n                version: 2.6.8\n\npackages:\n\n    debug@2.6.8:\n        resolution: {integrity: sha512-x}\n\n    ms@2.0.0:\n        resolution: {integrity: sha512-x}\n";
    let got = parse(four).unwrap();
    assert_eq!(got, parse(two).unwrap());
    assert_eq!(got.len(), 2);
    assert_eq!((got[0].name.as_str(), got[0].direct), ("debug", Some(true)));
}
