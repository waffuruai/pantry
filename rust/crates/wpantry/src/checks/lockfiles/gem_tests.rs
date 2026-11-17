use super::*;

#[test]
fn gem_sections_only() {
    let text = "GIT\n  remote: https://github.com/x/g.git\n  revision: abc\n  specs:\n    g (1.0.0)\n\nPATH\n  remote: .\n  specs:\n    local (0.1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.16.0-x86_64-linux)\n      racc (~> 1.4)\n    rails (7.1.0.rc1)\n\nGEM\n  remote: https://gems.example.com/\n  specs:\n    private (2.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  g!\n  rails (= 7.1.0.rc1)\n\nBUNDLED WITH\n   2.4.10\n";
    let parsed = parse(text).unwrap();
    let got: Vec<String> = parsed.iter().map(|p| format!("{} {}", p.name, p.version)).collect();
    assert_eq!(got, ["nokogiri 1.16.0", "rails 7.1.0.rc1", "private 2.0.0"]);
    let direct: Vec<Option<bool>> = parsed.iter().map(|p| p.direct).collect();
    assert_eq!(direct, [Some(false), Some(true), Some(false)], "only what DEPENDENCIES names is direct");
}
