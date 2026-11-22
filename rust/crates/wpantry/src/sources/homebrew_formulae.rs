//! Where a Homebrew formula's source comes from, from formulae.brew.sh's
//! API (`api/formula/<name>.json`): its stable and head URLs, its homepage
//! and its current stable version. A formula built from a git host's
//! release (`github.com/libexpat/libexpat/releases/download/...`) names
//! its upstream repo there, which is what OSV's GIT ecosystem is keyed by.
//! The API has no CPE or vendor field.
//!
//! One request per installed formula, sending its name only; each answer
//! is kept for the source's `refresh`, and one that can't be refreshed
//! stays in use. A formula the API doesn't know (a tap's) is kept as one
//! with no repo.
//!
//! Example:
//!
//! ```text
//! api/formula/expat.json -> {"urls": {"stable": {"url": "https://github.com/libexpat/libexpat/releases/download/R_2_10_0/expat-2.10.0.tar.xz"}},
//!                            "homepage": "https://libexpat.github.io/", "versions": {"stable": "2.10.0"}}
//! repo                   -> https://github.com/libexpat/libexpat
//! ```

use crate::db::Cache;
use crate::error::Result;
use crate::sources::cve_records::segment;
use crate::sources::fetch;
use crate::sources::file::url;
use crate::utils::json::{arr_at, str_at};
use crate::utils::net::Net;
use serde_json::{Value, json};

/// The source's id in `sources.toml`.
pub const ID: &str = "homebrew-formulae";
/// Requests in flight at once.
const PARALLEL: usize = 8;

/// What the check needs of a formula.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Formula {
    /// The upstream git repo its URLs name, case kept (OSV's GIT names are
    /// case-sensitive); "" when none does.
    pub repo: String,
    /// The current stable version, "" when unknown.
    pub stable: String,
}

fn key(name: &str) -> String {
    format!("homebrew_formula:{name}")
}

/// The git repo a URL is on, for the hosts whose paths name one:
/// `https://github.com/<owner>/<repo>`, Codeberg's the same, and GitLab's
/// path up to `/-/` (its groups nest). None for any other URL.
pub fn repo_of(u: &str) -> Option<String> {
    let rest = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://"))?;
    let (host, path) = rest.split_once('/')?;
    let host = host.to_ascii_lowercase();
    let path = path.split(['?', '#']).next().unwrap_or("");
    let parts: Vec<&str> = match host.as_str() {
        "github.com" | "www.github.com" | "codeberg.org" => path.split('/').take(2).collect(),
        "gitlab.com" => path.split("/-/").next().unwrap_or("").split('/').collect(),
        _ => return None,
    };
    let parts: Vec<&str> = parts.into_iter().filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return None;
    }
    let host = if host == "www.github.com" { "github.com" } else { host.as_str() };
    let path = parts.join("/");
    let path = path.strip_suffix(".git").unwrap_or(&path);
    let ok = path.split('/').all(|p| p.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)));
    ok.then(|| format!("https://{host}/{path}"))
}

/// What is kept of the API's answer: the URLs that may name the repo, in
/// order (stable, head, homepage), and the stable version.
pub fn trim(v: &Value) -> Value {
    let urls = &v["urls"];
    let candidates: Vec<&str> = [str_at(&urls["stable"], "url"), str_at(&urls["head"], "url"), str_at(v, "homepage")]
        .into_iter()
        .filter(|u| !u.is_empty())
        .collect();
    json!({"urls": candidates, "stable": str_at(&v["versions"], "stable")})
}

/// `name`'s formula from the cache; None when it was never fetched.
pub fn formula(cache: &Cache, name: &str) -> Result<Option<Formula>> {
    let Some(text) = cache.get(&key(name))? else { return Ok(None) };
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let repo = arr_at(&v, "urls").iter().filter_map(Value::as_str).find_map(repo_of).unwrap_or_default();
    Ok(Some(Formula { repo, stable: str_at(&v, "stable").to_string() }))
}

/// Fetch the formulae whose copy isn't fresh, side by side, and keep them.
pub fn prefetch(cache: &Cache, net: &dyn Net, names: &[String], offline: bool) -> Result<()> {
    let keys: Vec<(String, String)> = names.iter().map(|n| (key(n), n.clone())).collect();
    fetch::prefetch(cache, ID, &keys, PARALLEL, offline, |name| fetch_formula(net, name))
}

fn fetch_formula(net: &dyn Net, name: &str) -> Result<Value> {
    let u = url(ID).replace("{}", &segment(name));
    match fetch::get_json(net, ID, &u, &[])? {
        None => Ok(json!({"urls": [], "stable": ""})),
        Some(v) if v.is_object() => Ok(trim(&v)),
        Some(_) => Err(fetch::invalid(ID, &format!("{name}: not a formula"))),
    }
}

#[cfg(test)]
#[path = "homebrew_formulae_tests.rs"]
mod tests;
