use super::*;

#[test]
fn tables_strings_and_spanning_values() {
    let doc = "version = 4\n\n[[package]]\nname = \"a\\u00e9\"\nversion = '1.0.0'\nsource = { registry = \"https://pypi.org/simple\" }\ndependencies = [\n  { name = \"b\" },\n]\n# c\n[package.metadata]\nrequires-dist = [{ name = \"x\", specifier = \">=1\" }]\n";
    let t = parse(doc).unwrap();
    assert_eq!(t.len(), 3);
    assert_eq!(
        (t[1].name.as_str(), t[1].array, t[1].str("name"), t[1].str("version")),
        ("package", true, "aé", "1.0.0")
    );
    assert_eq!(
        inline(match t[1].get("source").unwrap() {
            Val::Raw(r) => r,
            _ => panic!(),
        }),
        [("registry".to_string(), Val::Str("https://pypi.org/simple".into()))]
    );
    assert_eq!((t[2].name.as_str(), t[2].array), ("package.metadata", false));
    assert!(parse("[a]\nx = [\n").is_err());
    assert!(parse("not toml").is_err());
}

#[test]
fn inline_tables() {
    let got = inline("{ git = \"https://x/y.git?rev=1\", editable = \".\", n = 1, a = [1, {b = 2}], s = 'q,}' }");
    let keys: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, ["git", "editable", "n", "a", "s"]);
    assert_eq!(got[4].1, Val::Str("q,}".into()));
    // A string inside a raw value is skipped whole, and the table may end
    // after a raw value.
    let got = inline("{ a = [\"x, }\", 'y]'], b = 1 }");
    assert_eq!(got, [("a".to_string(), Val::Raw("[\"x, }\", 'y]']".into())), ("b".to_string(), Val::Raw("1".into()))]);
    assert_eq!(inline("{ n = 1 }"), [("n".to_string(), Val::Raw("1".into()))]);
    assert_eq!(inline("{ a = [\"open] }"), [("a".to_string(), Val::Raw("[\"open]".into()))]);
    assert_eq!(inline("{ = 1 }"), []);
    assert_eq!(inline("{ a 1 }"), []);
    assert_eq!(inline("{ a = \"open }"), []);
    assert_eq!(inline("x"), []);
}

#[test]
fn string_escapes_and_quoted_keys() {
    assert_eq!(
        string(r#""a\nb\tc\rd\be\ff\"g\\h\u00e9\U0001F600" rest"#),
        Some(("a\nb\tc\rd\u{8}e\u{c}f\"g\\h\u{e9}\u{1f600}".to_string(), " rest"))
    );
    assert_eq!(string(r#""\q""#), None, "an unknown escape");
    assert_eq!(string(r#""\u12""#), None, "a short unicode escape");
    assert_eq!(string(r#""open"#), None);
    assert_eq!(string("'open"), None);
    assert_eq!(string("x"), None);
    assert_eq!(string(""), None);
    let t =
        parse("\"quoted key\" = 'v'\n'k2' = \"w\"\nml = \"\"\"x\"\"\"\na = [ 1, # ] a comment with a bracket\n  2 ]\n")
            .unwrap();
    assert_eq!(t[0].str("quoted key"), "v");
    assert_eq!(t[0].str("k2"), "w");
    assert_eq!(t[0].get("ml"), Some(&Val::Raw("\"\"\"x\"\"\"".into())), "multi-line strings are kept raw");
    assert_eq!(t[0].get("a"), Some(&Val::Raw("[ 1, # ] a comment with a bracket\n  2 ]".into())));
    assert!(parse("x = \"unterminated\n").is_err());
    assert!(parse("x = \"a\n").is_err());
    assert!(parse("= 1\n").is_err());
}
