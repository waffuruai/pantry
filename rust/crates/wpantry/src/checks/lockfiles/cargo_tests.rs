use super::*;

#[test]
fn workspace_members_name_the_direct_dependencies() {
    let text = "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde\",\n \"syn 2.0.1\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\ndependencies = [\n \"serde_derive\",\n]\n\n[[package]]\nname = \"serde_derive\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"syn\"\nversion = \"1.0.109\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"syn\"\nversion = \"2.0.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    let got = parse(text).unwrap();
    let direct: Vec<(&str, &str, Option<bool>)> =
        got.iter().map(|p| (p.name.as_str(), p.version.as_str(), p.direct)).collect();
    assert_eq!(
        direct,
        [
            ("serde", "1.0.200", Some(true)),
            ("serde_derive", "1.0.200", Some(false)),
            ("syn", "1.0.109", Some(false)),
            ("syn", "2.0.1", Some(true)),
        ]
    );
    assert_eq!(
        dependency_list("[\n \"a\",\n \"b 1.2.3\",\n \"c 0.1.0 (registry+https://x)\",\n]"),
        [("a".into(), "".into()), ("b".into(), "1.2.3".into()), ("c".into(), "0.1.0".into())]
    );
}
