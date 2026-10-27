//! `Gemfile.lock` → `RubyGems`: the `specs:` of every `GEM` section (gems
//! from a gem server). `GIT`, `PATH` and `PLUGIN SOURCE` sections are local
//! or unversioned and skipped. A platform suffix (`1.16.0-x86_64-linux`)
//! is dropped: RubyGems versions never contain "-".

use super::{Package, lines, plausible};
use crate::error::Result;

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let mut out = Vec::new();
    let mut section = "";
    let mut in_specs = false;
    for line in lines(text)? {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        match indent {
            0 => {
                section = line.trim_end();
                in_specs = false;
            }
            2 => in_specs = line.trim_end() == "  specs:",
            4 if section == "GEM" && in_specs => {
                let spec = line.trim().trim_end_matches('!');
                let Some((name, rest)) = spec.split_once(" (") else { continue };
                let version = rest.trim_end_matches(')').split('-').next().unwrap_or("");
                if plausible(version) {
                    out.push(Package::new("RubyGems", name, version));
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gem_sections_only() {
        let text = "GIT\n  remote: https://github.com/x/g.git\n  revision: abc\n  specs:\n    g (1.0.0)\n\nPATH\n  remote: .\n  specs:\n    local (0.1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.16.0-x86_64-linux)\n      racc (~> 1.4)\n    rails (7.1.0.rc1)\n\nGEM\n  remote: https://gems.example.com/\n  specs:\n    private (2.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  g!\n  rails (= 7.1.0.rc1)\n\nBUNDLED WITH\n   2.4.10\n";
        let got: Vec<String> = parse(text).unwrap().iter().map(|p| format!("{} {}", p.name, p.version)).collect();
        assert_eq!(got, ["nokogiri 1.16.0", "rails 7.1.0.rc1", "private 2.0.0"]);
    }
}
