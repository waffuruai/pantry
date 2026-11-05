//! deps.dev: each locked package's declared licenses, fetched side by
//! side and cached for 30 days. deps.dev covers npm, PyPI, crates.io, Go,
//! Maven, NuGet and RubyGems; the rest count as unknown.

use crate::checks::ecosystems::deps_dev;
use crate::component::Status;
use crate::db::{Cache, DAY};
use crate::error::{Error, Result};
use crate::utils::json;
use crate::utils::net::{self, Net};
use serde_json::{Value, json};
use std::sync::Mutex;

pub const API: &str = "https://api.deps.dev/v3/systems";
pub const TTL: f64 = 30.0 * DAY;

/// A path segment, percent-encoded (`@scope/name` → `%40scope%2Fname`).
fn segment(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
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
            Some((_, at, v)) if offline || at > crate::utils::os::now() - TTL => {
                out.push(Some(json::strs_at(&json!({"l": v}), "l")))
            }
            _ if deps_dev(&it.0).is_none() => out.push(Some(Vec::new())),
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
                    match fetch(net, deps_dev(e).unwrap_or(""), n, v) {
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
    use crate::sources::testing::ids;
    use crate::utils::net::{Fake, Response};

    #[test]
    fn lookup_caches_and_encodes_names() {
        let d = crate::utils::temp::TempDir::new("lic").unwrap();
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
