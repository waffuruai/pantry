//! `pubspec.lock` → `Pub`, read line by line: the `packages:` map, each
//! package's `source:` and `version:`. Only `hosted` packages (pub.dev or
//! another package server) count; `git`, `path` and `sdk` ones are skipped.

use super::{Package, lines, plausible, unquote};
use crate::error::Result;

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let mut out = Vec::new();
    let mut in_packages = false;
    // (name, source, version) of the package being read.
    let mut cur: Option<(String, String, String)> = None;
    let mut flush = |cur: &mut Option<(String, String, String)>| {
        if let Some((name, source, version)) = cur.take()
            && source == "hosted"
            && plausible(&version)
        {
            out.push(Package::new("Pub", &name, &version));
        }
    };
    for line in lines(text)? {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let item = line.trim();
        if indent == 0 {
            flush(&mut cur);
            in_packages = item == "packages:";
        } else if in_packages && indent == 2 {
            flush(&mut cur);
            cur = item.strip_suffix(':').map(|n| (unquote(n).to_string(), String::new(), String::new()));
        } else if in_packages
            && indent == 4
            && let Some(c) = cur.as_mut()
            && let Some((k, v)) = item.split_once(':')
        {
            match k {
                "source" => c.1 = unquote(v).to_string(),
                "version" => c.2 = unquote(v).to_string(),
                _ => {}
            }
        }
    }
    flush(&mut cur);
    Ok(out)
}

#[cfg(test)]
#[path = "pubspec_tests.rs"]
mod tests;
