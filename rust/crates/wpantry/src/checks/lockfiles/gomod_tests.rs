use super::*;

#[test]
fn indirect_marks_transitive_requires() {
    let text = "module m\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.0.0\n\tgolang.org/x/net v0.17.0 // indirect\n)\n";
    let got = parse(text).unwrap();
    let direct = |n: &str| got.iter().find(|p| p.name == n).unwrap().direct;
    assert_eq!(direct("github.com/a/b"), Some(true));
    assert_eq!(direct("golang.org/x/net"), Some(false));
    assert_eq!(direct("stdlib"), None);
}

#[test]
fn requires_replaces_and_stdlib() {
    let text = "module example.com/m\n\ngo 1.22.1\n\ntoolchain go1.23.4\n\nrequire golang.org/x/net v0.17.0 // indirect\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgithub.com/c/d v2.0.0+incompatible\n\tgithub.com/e/f v1.0.0\n\tgithub.com/g/h v0.0.0-20230101000000-abcdefabcdef\n)\n\nreplace github.com/a/b => github.com/a/b2 v1.2.4\n\nreplace (\n\tgithub.com/e/f v1.0.0 => ../local/f\n\tgithub.com/c/d v9.9.9 => github.com/x/y v1.0.0\n)\n";
    let got = parse(text).unwrap();
    let want = [
        ("github.com/a/b2", "1.2.4"),
        ("github.com/c/d", "2.0.0+incompatible"),
        ("../local/f", ""),
        ("github.com/g/h", "0.0.0-20230101000000-abcdefabcdef"),
        ("golang.org/x/net", "0.17.0"),
        ("stdlib", "1.23.4"),
    ];
    let got: Vec<(&str, &str)> = got.iter().map(|p| (p.name.as_str(), p.version.as_str())).collect();
    assert_eq!(got, want);
    let go_only = parse("module m\ngo 1.21\n").unwrap();
    assert_eq!(go_only, [Package::new("Go", "stdlib", "1.21")]);
}
