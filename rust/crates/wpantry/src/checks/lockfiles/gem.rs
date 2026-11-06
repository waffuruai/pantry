//! `Gemfile.lock` → `RubyGems`: the `specs:` of every `GEM` section (gems
//! from a gem server). `GIT`, `PATH` and `PLUGIN SOURCE` sections are local
//! or unversioned and skipped. A platform suffix (`1.16.0-x86_64-linux`)
//! is dropped: RubyGems versions never contain "-". The `DEPENDENCIES`
//! section names what the Gemfile asks for: those gems are direct, the
//! rest came with them. Bundler groups (`:development`, `:test`) are in
//! the Gemfile, not the lock, so the scope stays unknown.

use super::{Package, lines, plausible};
use crate::error::Result;
use std::collections::BTreeSet;

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let mut out = Vec::new();
    let mut asked: BTreeSet<String> = BTreeSet::new();
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
            2 if section == "DEPENDENCIES" => {
                let dep = line.trim().trim_end_matches('!');
                let name = dep.split_once(" (").map(|(n, _)| n).unwrap_or(dep);
                asked.insert(name.to_string());
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
    for p in &mut out {
        p.direct = Some(asked.contains(&p.name));
    }
    Ok(out)
}

#[cfg(test)]
#[path = "gem_tests.rs"]
mod tests;
