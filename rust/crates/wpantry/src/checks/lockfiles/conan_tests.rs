use super::*;

#[test]
fn references() {
    assert_eq!(reference("zlib/1.3.1#42bc0fa9eabcade24e42a0ddecfb8830%1793094518.3745675"), Some(("zlib", "1.3.1")));
    assert_eq!(reference("zlib/1.2.11:5ab84d6acfe1f23c4fae0ab88f26e3a396351ac9#prev"), Some(("zlib", "1.2.11")));
    assert_eq!(reference("mylib/1.0.0@acme/stable#810f"), None);
    assert_eq!(reference("conanfile"), None);
    let v04 = r#"{"version": "0.4", "graph_lock": {"nodes": {
            "0": {"path": "conanfile.txt", "requires": ["1"]},
            "1": {"ref": "openssl/3.2.0#rev", "requires": ["2"]},
            "2": {"pref": "zlib/1.3.1#rev:pkgid#prev", "ref": "ignored/0.0.1"}}}}"#;
    let got: Vec<String> = parse(v04).unwrap().iter().map(|p| format!("{} {}", p.name, p.version)).collect();
    assert_eq!(got, ["openssl 3.2.0", "zlib 1.3.1"]);
    let v05 = r#"{"version": "0.5", "requires": ["zlib/1.3.1#r%1"], "build_requires": ["cmake/3.28.1#r%1"], "python_requires": ["pyreq/1.0.0#r%1"], "config_requires": ["cfg/1.0#r"]}"#;
    let got: Vec<String> = parse(v05).unwrap().iter().map(|p| format!("{} {}", p.name, p.version)).collect();
    assert_eq!(got, ["zlib 1.3.1", "cmake 3.28.1", "pyreq 1.0.0"]);
}
