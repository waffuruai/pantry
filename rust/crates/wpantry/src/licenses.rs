//! Dependency licenses (`--licenses`), from deps.dev: each locked package's
//! declared licenses, judged against an allowlist of SPDX ids. A package
//! passes when its license expression can be satisfied with allowed ids
//! (`MIT OR GPL-3.0-only` passes an allowlist holding MIT); one with no
//! identifiable license is only counted. deps.dev's `non-standard` (custom
//! terms, such as a license that needs a company licence) is a license no
//! allowlist holds, so it is reported, not counted as unknown.
//! deps.dev covers npm, PyPI, crates.io, Go, Maven, NuGet and RubyGems; the
//! rest count as unknown. Answers are cached for 30 days.

use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::json;
use crate::net::{self, Net};
use crate::system::Status;
use serde_json::{Value, json};
use std::sync::Mutex;

pub const API: &str = "https://api.deps.dev/v3/systems";
pub const TTL: f64 = 30.0 * DAY;

/// deps.dev's system for an OSV ecosystem.
pub fn system(eco: &str) -> Option<&'static str> {
    Some(match eco {
        "npm" => "npm",
        "PyPI" => "pypi",
        "crates.io" => "cargo",
        "Go" => "go",
        "Maven" => "maven",
        "NuGet" => "nuget",
        "RubyGems" => "rubygems",
        _ => return None,
    })
}

/// A path segment, percent-encoded (`@scope/name` → `%40scope%2Fname`).
fn segment(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Whether an SPDX license expression can be satisfied with `allowed` ids:
/// OR needs one side, AND both; `X WITH exception` is judged as X; ids
/// compare case-insensitively, and `X+` (or-later) as X.
pub fn satisfied(expr: &str, allowed: &[String]) -> Option<bool> {
    let spaced = expr.replace('(', " ( ").replace(')', " ) ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    let mut i = 0;
    let v = or(&tokens, &mut i, allowed)?;
    (i == tokens.len()).then_some(v)
}

fn or(t: &[&str], i: &mut usize, allowed: &[String]) -> Option<bool> {
    let mut v = and(t, i, allowed)?;
    while t.get(*i).is_some_and(|w| w.eq_ignore_ascii_case("OR")) {
        *i += 1;
        let rhs = and(t, i, allowed)?;
        v = v || rhs;
    }
    Some(v)
}

fn and(t: &[&str], i: &mut usize, allowed: &[String]) -> Option<bool> {
    let mut v = atom(t, i, allowed)?;
    while t.get(*i).is_some_and(|w| w.eq_ignore_ascii_case("AND")) {
        *i += 1;
        let rhs = atom(t, i, allowed)?;
        v = v && rhs;
    }
    Some(v)
}

fn atom(t: &[&str], i: &mut usize, allowed: &[String]) -> Option<bool> {
    let w = *t.get(*i)?;
    *i += 1;
    if w == "(" {
        let v = or(t, i, allowed)?;
        if t.get(*i) != Some(&")") {
            return None;
        }
        *i += 1;
        return Some(v);
    }
    if w == ")" || w.eq_ignore_ascii_case("AND") || w.eq_ignore_ascii_case("OR") {
        return None;
    }
    if t.get(*i).is_some_and(|x| x.eq_ignore_ascii_case("WITH")) {
        *i += 2; // the exception doesn't change which license it is
    }
    let id = w.trim_end_matches('+');
    Some(allowed.iter().any(|a| a.eq_ignore_ascii_case(id)))
}

/// deps.dev lookups in flight at once: a first run asks about every locked
/// package, thousands of small GETs.
const PARALLEL: usize = 16;

/// The licenses deps.dev declares for one package version (empty when
/// unknown), cached.
fn fetch(net: &dyn Net, sys: &str, name: &str, version: &str) -> Result<Vec<String>> {
    let url = format!("{API}/{sys}/packages/{}/versions/{}", segment(name), segment(version));
    let Some(v) = net::get_json(net, &url, &[])? else { return Ok(Vec::new()) };
    Ok(json::strs_at(&v, "licenses").into_iter().filter(|l| !l.is_empty()).collect())
}

/// One package's verdict: None passes, Some(["UNKNOWN"]) has no license we
/// can judge, Some(ids) are the licenses outside the allowlist.
pub fn judge(licenses: &[String], allowed: &[String]) -> Option<Vec<String>> {
    if licenses.is_empty() {
        return Some(vec!["UNKNOWN".into()]);
    }
    // deps.dev lists one expression per declared license; any one passing is enough.
    let mut verdicts = licenses.iter().map(|l| satisfied(l, allowed));
    if verdicts.any(|v| v == Some(true)) {
        return None;
    }
    if licenses.iter().all(|l| satisfied(l, allowed).is_none()) {
        return Some(vec!["UNKNOWN".into()]);
    }
    Some(licenses.to_vec())
}

/// Licenses for many (ecosystem, name, version), cached for 30 days and
/// fetched at most [`PARALLEL`] at a time. Packages deps.dev doesn't cover map to [].
/// `Offline` when none could be fetched and nothing was cached.
pub fn lookup(
    cache: &Cache,
    net: &dyn Net,
    items: &[(String, String, String)],
    offline: bool,
    status: Status,
) -> Result<Vec<Vec<String>>> {
    let key = |(e, n, v): &(String, String, String)| format!("license:{e}:{n}@{v}");
    let mut out: Vec<Option<Vec<String>>> = Vec::with_capacity(items.len());
    let mut todo = Vec::new();
    for (i, it) in items.iter().enumerate() {
        match cache.run(&key(it))? {
            Some((_, at, v)) if offline || at > crate::system::now() - TTL => {
                out.push(Some(json::strs_at(&json!({"l": v}), "l")))
            }
            _ if system(&it.0).is_none() => out.push(Some(Vec::new())),
            _ if offline => out.push(None),
            _ => {
                out.push(None);
                todo.push(i);
            }
        }
    }
    let results = Mutex::new(Vec::new());
    let failed = Mutex::new(None);
    let queue = Mutex::new(todo.iter());
    std::thread::scope(|s| {
        for _ in 0..PARALLEL.min(todo.len()) {
            s.spawn(|| {
                while let Some(&i) = { queue.lock().expect("lock").next() } {
                    let (e, n, v) = &items[i];
                    match fetch(net, system(e).unwrap_or(""), n, v) {
                        Ok(l) => {
                            let mut r = results.lock().expect("lock");
                            r.push((i, l));
                            status(&format!("Fetching licenses from deps.dev ({}/{})", r.len(), todo.len()));
                        }
                        Err(e) => {
                            failed.lock().expect("lock").get_or_insert(e);
                            return;
                        }
                    }
                }
            });
        }
    });
    for (i, l) in results.into_inner().expect("lock") {
        cache.put_run(&key(&items[i]), "", &Value::from(l.clone()))?;
        out[i] = Some(l);
    }
    cache.commit()?;
    if let Some(e) = failed.into_inner().expect("lock")
        && out.iter().any(Option::is_none)
    {
        return Err(Error::Offline(format!("deps.dev: {e}")));
    }
    Ok(out.into_iter().map(Option::unwrap_or_default).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{Fake, Response};

    fn ids(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn spdx_expressions() {
        let allow = ids(&["MIT", "Apache-2.0", "BSD-3-Clause"]);
        assert_eq!(satisfied("MIT", &allow), Some(true));
        assert_eq!(satisfied("mit", &allow), Some(true));
        assert_eq!(satisfied("MIT OR GPL-3.0-only", &allow), Some(true));
        assert_eq!(satisfied("MIT AND GPL-3.0-only", &allow), Some(false));
        assert_eq!(satisfied("(Apache-2.0 OR MIT) AND BSD-3-Clause", &allow), Some(true));
        assert_eq!(satisfied("Apache-2.0 WITH LLVM-exception", &allow), Some(true));
        assert_eq!(satisfied("GPL-2.0+", &allow), Some(false));
        assert_eq!(satisfied("MIT AND", &allow), None);
        assert_eq!(judge(&[], &allow), Some(ids(&["UNKNOWN"])));
        assert_eq!(judge(&ids(&["GPL-3.0-only"]), &allow), Some(ids(&["GPL-3.0-only"])));
        assert_eq!(judge(&ids(&["GPL-3.0-only", "MIT"]), &allow), None);
        assert_eq!(judge(&ids(&["non-standard"]), &allow), Some(ids(&["non-standard"])), "custom terms need review");
    }

    #[test]
    fn lookup_caches_and_encodes_names() {
        let d = crate::system::TempDir::new("lic").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        let net = Fake::new(|r| {
            Ok(match r.url.as_str() {
                "https://api.deps.dev/v3/systems/npm/packages/%40types%2Fnode/versions/20.11.0" => {
                    Response::ok(r#"{"licenses": ["MIT"]}"#)
                }
                _ => Response { status: 404, body: vec![], etag: None },
            })
        });
        let items = vec![
            ("npm".to_string(), "@types/node".to_string(), "20.11.0".to_string()),
            ("npm".into(), "gone".into(), "1.0.0".into()),
            ("Hex".into(), "x".into(), "1".into()),
        ];
        assert_eq!(lookup(&c, &net, &items, false, &|_| {}).unwrap(), vec![ids(&["MIT"]), vec![], vec![]]);
        let quiet = Fake::new(|_| panic!("cached"));
        assert_eq!(lookup(&c, &quiet, &items[..1], false, &|_| {}).unwrap(), vec![ids(&["MIT"])]);
        assert!(matches!(
            lookup(&c, &Fake::offline(), &[("npm".into(), "new".into(), "1".into())], false, &|_| {}),
            Err(Error::Offline(_))
        ));
    }
}
