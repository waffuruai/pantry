use super::*;

#[test]
fn versions_and_keys() {
    let v4 = r#"{"version": "4", "specifiers": {"jsr:@std/path@1": "1.0.8"},
            "jsr": {"@std/path@1.0.8": {"integrity": "x"}},
            "npm": {"@types/node@20.11.0": {}, "react-dom@18.2.0_react@18.2.0": {}, "string_decoder@1.3.0": {}}}"#;
    let got: Vec<String> = parse(v4).unwrap().iter().map(|p| format!("{} {}", p.name, p.version)).collect();
    assert_eq!(got, ["@types/node 20.11.0", "react-dom 18.2.0", "string_decoder 1.3.0"]);
    let v3 = r#"{"version": "3", "packages": {"specifiers": {}, "npm": {"ms@2.1.3": {}}}, "remote": {}}"#;
    assert_eq!(parse(v3).unwrap(), [Package::new("npm", "ms", "2.1.3")]);
    assert!(parse(r#"{"version": "2", "npm": {}}"#).is_err());
}
