//! `pnpm-lock.yaml` → `npm`, read line by line. The `packages:` keys name
//! every installed package: v9 as `name@version`, v6 as `/name@version`,
//! v5 as `/name/version`; peer suffixes (`(…)`, v5's `_…`) are dropped. An
//! entry's own `name:` and `version:` (tarball and git dependencies) win
//! over its key. Local and git versions are skipped.

use super::{Package, lines, plausible};
use crate::error::Result;

fn unquote(s: &str) -> &str {
    s.trim().trim_matches(['\'', '"'])
}

/// (name, version) from a `packages:` key.
fn split_key(key: &str, v5: bool) -> (String, String) {
    let key = unquote(key);
    let key = key.strip_prefix('/').unwrap_or(key);
    let key = key.split('(').next().unwrap_or(key);
    if v5 {
        return match key.rsplit_once('/') {
            Some((name, ver)) => (name.to_string(), ver.split('_').next().unwrap_or(ver).to_string()),
            None => (String::new(), String::new()),
        };
    }
    match key.rfind('@') {
        Some(i) if i > 0 => (key[..i].to_string(), key[i + 1..].to_string()),
        _ => (key.to_string(), String::new()),
    }
}

pub fn parse(text: &str) -> Result<Vec<Package>> {
    let mut out = Vec::new();
    let mut v5 = false;
    let mut in_packages = false;
    let mut current: Option<(String, String)> = None;
    let mut flush = |cur: &mut Option<(String, String)>| {
        if let Some((n, v)) = cur.take()
            && plausible(&v)
        {
            out.push(Package::new("npm", &n, &v));
        }
    };
    for line in lines(text)? {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 {
            flush(&mut current);
            if let Some(v) = line.strip_prefix("lockfileVersion:") {
                v5 = unquote(v).starts_with('5');
            }
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        let item = line.trim();
        if indent == 2 && item.ends_with(':') {
            flush(&mut current);
            current = Some(split_key(&item[..item.len() - 1], v5));
        } else if indent == 4
            && let Some(cur) = current.as_mut()
        {
            if let Some(n) = item.strip_prefix("name:") {
                cur.0 = unquote(n).to_string();
            } else if let Some(v) = item.strip_prefix("version:") {
                cur.1 = unquote(v).to_string();
            }
        }
    }
    flush(&mut current);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_across_versions() {
        assert_eq!(split_key("'@babel/core@7.22.0'", false), ("@babel/core".into(), "7.22.0".into()));
        assert_eq!(split_key("/react-dom@18.2.0(react@18.2.0)", false), ("react-dom".into(), "18.2.0".into()));
        assert_eq!(split_key("/@types/node/20.1.0", true), ("@types/node".into(), "20.1.0".into()));
        assert_eq!(split_key("/foo/1.0.0_react@18.2.0", true), ("foo".into(), "1.0.0".into()));
        assert_eq!(
            split_key("foo@https://codeload.github.com/x/y/tar.gz/abc", false).1,
            "https://codeload.github.com/x/y/tar.gz/abc"
        );
    }
}
