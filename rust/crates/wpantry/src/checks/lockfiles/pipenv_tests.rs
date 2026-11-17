use super::*;

#[test]
fn sections_and_pins() {
    let text = r#"{"_meta": {"hash": {"sha256": "x"}},
            "default": {"Jinja2": {"version": "==3.1.2"}, "local": {"editable": true, "path": "."},
                        "g": {"git": "https://github.com/x/g.git", "ref": "abc"}, "star": {"version": "*"}},
            "develop": {"pytest": {"version": "==7.4.0", "markers": "python_version >= '3.7'"}}}"#;
    assert_eq!(
        parse(text).unwrap(),
        [
            Package::new("PyPI", "jinja2", "3.1.2").scoped(Scope::Runtime),
            Package::new("PyPI", "pytest", "7.4.0").scoped(Scope::Dev)
        ]
    );
}
