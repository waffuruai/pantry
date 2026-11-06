//! `mix.lock` → `Hex`, read line by line. Each dependency is one line,
//! `"app": {:hex, :package, "version", "hash", [build tools], [deps],
//! "repo", "outer hash"},`. Only `:hex` tuples count, under the package
//! name (an aliased app's key differs from it) and only from the public
//! `hexpm` repository (`hexpm:org` is a private organization). `:git` and
//! `:path` dependencies are skipped.

use super::{Package, lines, plausible};
use crate::error::Result;

/// The top-level elements of an Elixir tuple's body, split at commas
/// outside strings, lists, tuples and maps.
fn elements(body: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut start, mut in_str, mut escaped) = (0i32, 0, false, false);
    for (i, c) in body.char_indices() {
        if in_str {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '[' | '{' => depth += 1,
            ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(body[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(body[start..].trim());
    out
}

fn string(e: &str) -> Option<&str> {
    e.strip_prefix('"')?.strip_suffix('"')
}

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let mut out = Vec::new();
    for line in lines(text)? {
        let Some((_, tuple)) = line.split_once(": {:hex,") else { continue };
        let body = tuple.trim_end().trim_end_matches(',').trim_end().strip_suffix('}').unwrap_or(tuple);
        let e = elements(body);
        let Some(name) = e.first().and_then(|n| n.strip_prefix(':')) else { continue };
        let name = string(name).unwrap_or(name); // :"quoted-atom"
        let Some(version) = e.get(1).and_then(|v| string(v)) else { continue };
        let repo = e.get(5).and_then(|r| string(r)).unwrap_or("hexpm");
        if repo == "hexpm" && plausible(version) {
            out.push(Package::new("Hex", name, version));
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "mix_tests.rs"]
mod tests;
