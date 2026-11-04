//! `go.mod` → `Go`, as osv-scanner reads it: `require` lines (single and
//! blocks), `replace` applied (a versioned old path only replaces that
//! version; a local-path replacement has no version and drops out), and
//! the `toolchain` directive, else the `go` directive, as package `stdlib`
//! (F5). Versions lose their "v".

use super::{Package, lines};
use crate::error::Result;
use std::collections::BTreeMap;

fn strip_v(v: &str) -> &str {
    v.strip_prefix('v').unwrap_or(v)
}

fn unquote(s: &str) -> &str {
    s.trim_matches(['"', '`'])
}

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let mut requires: Vec<(String, String, bool)> = Vec::new(); // path, version, direct
    let mut replaces: Vec<(String, String, String, String)> = Vec::new(); // old, old version, new, new version
    let (mut go, mut toolchain) = (String::new(), String::new());
    let mut block = "";
    for raw in lines(text)? {
        // `go mod tidy` marks what only another module needs.
        let indirect = raw.split_once("//").is_some_and(|(_, c)| c.trim().starts_with("indirect"));
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if !block.is_empty() {
            if line == ")" {
                block = "";
                continue;
            }
        } else {
            let (verb, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            match (verb, rest.trim()) {
                ("require" | "replace" | "exclude" | "retract" | "godebug" | "tool" | "ignore", "(") => {
                    block = verb;
                    continue;
                }
                ("go", v) => go = v.to_string(),
                ("toolchain", v) => toolchain = v.to_string(),
                _ => {}
            }
        }
        let (verb, rest) = if block.is_empty() {
            match line.split_once(char::is_whitespace) {
                Some((v, r)) => (v, r.trim()),
                None => continue,
            }
        } else {
            (block, line)
        };
        let words: Vec<&str> = rest.split_whitespace().map(unquote).collect();
        match verb {
            "require" if words.len() >= 2 => {
                requires.push((words[0].to_string(), strip_v(words[1]).to_string(), !indirect))
            }
            "replace" => {
                let Some(arrow) = words.iter().position(|w| *w == "=>") else { continue };
                let (old, new) = (&words[..arrow], &words[arrow + 1..]);
                let Some(old_path) = old.first() else { continue };
                let Some(new_path) = new.first() else { continue };
                replaces.push((
                    old_path.to_string(),
                    old.get(1).map(|v| strip_v(v).to_string()).unwrap_or_default(),
                    new_path.to_string(),
                    new.get(1).map(|v| strip_v(v).to_string()).unwrap_or_default(),
                ));
            }
            _ => {}
        }
    }
    let mut pkgs: BTreeMap<(String, String), (String, String, bool)> =
        requires.into_iter().map(|(n, v, d)| ((n.clone(), v.clone()), (n, v, d))).collect();
    for (old, old_v, new, new_v) in replaces {
        let keys: Vec<(String, String)> = pkgs
            .iter()
            .filter(|(k, p)| if old_v.is_empty() { p.0 == old } else { **k == (old.clone(), old_v.clone()) })
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            let direct = pkgs[&k].2;
            pkgs.insert(k, (new.clone(), new_v.clone(), direct));
        }
    }
    let mut out: Vec<Package> = pkgs.into_values().map(|(n, v, d)| Package::new("Go", &n, &v).direct(d)).collect();
    let stdlib = if toolchain.is_empty() {
        go
    } else {
        toolchain.split('-').next().unwrap_or("").trim_start_matches("go").to_string()
    };
    if !stdlib.is_empty() {
        out.push(Package::new("Go", "stdlib", &stdlib));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indirect_marks_transitive_requires() {
        let text =
            "module m\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.0.0\n\tgolang.org/x/net v0.17.0 // indirect\n)\n";
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
}
