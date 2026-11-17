use super::*;

#[test]
fn hex_tuples() {
    let text = r#"%{
  "alias": {:hex, :plug, "1.15.3", "abc", [:mix], [{:mime, "~> 1.0 or ~> 2.0", [hex: :mime, repo: "hexpm", optional: false]}], "hexpm", "def"},
  "old": {:hex, :poison, "3.1.0", "abc", [:mix], []},
  "private": {:hex, :secret, "0.3.0", "abc", [:mix], [], "hexpm:acme", "def"},
  "g": {:git, "https://github.com/x/g.git", "abc", [branch: "main"]},
}
"#;
    assert_eq!(parse(text).unwrap(), [Package::new("Hex", "plug", "1.15.3"), Package::new("Hex", "poison", "3.1.0")]);
}
