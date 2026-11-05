use super::*;

#[test]
fn sources() {
    let text = "[[package]]\nname = \"a\"\nversion = \"1.0\"\n\n[package.dependencies]\nb = {version = \"*\", markers = \"sys_platform == \\\"win32\\\"\"}\n\n[[package]]\nname = \"local\"\nversion = \"0.1.0\"\n\n[package.source]\ntype = \"directory\"\nurl = \"local\"\n\n[[package]]\nname = \"private\"\nversion = \"2.0\"\n\n[package.source]\ntype = \"legacy\"\nurl = \"https://pypi.example.com/simple\"\nreference = \"private\"\n\n[[package]]\nname = \"g\"\nversion = \"3.0\"\n\n[package.source]\ntype = \"git\"\nurl = \"https://github.com/x/g.git\"\n\n[metadata]\nlock-version = \"2.1\"\n";
    assert_eq!(parse(text).unwrap(), [Package::new("PyPI", "a", "1.0"), Package::new("PyPI", "private", "2.0")]);
}
