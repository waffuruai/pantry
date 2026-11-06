//! Breach lookups for an email address: Have I Been Pwned when
//! HIBP_API_KEY is set (its email lookup is paid), otherwise XposedOrNot's
//! free lookup. Answers are cached for a week; only the address is sent.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::sources::fetch;
use crate::sources::file::url;
use crate::utils::json;
use crate::utils::net::Net;
use crate::utils::os::now;
use crate::utils::sha256;
use serde_json::Value;
use std::collections::BTreeMap;

pub const WEEK: f64 = 7.0 * 86400.0;

pub(crate) fn hibp_key() -> Option<String> {
    std::env::var("HIBP_API_KEY").ok().filter(|k| !k.is_empty())
}

/// Percent-encoding as Python's `urllib.parse.quote` (`/` kept).
pub fn quote(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' | b'/' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn names(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default()
}

pub(crate) fn check_emails(
    cache: &Cache,
    net: &dyn Net,
    offline: bool,
    emails: Vec<String>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut out = BTreeMap::new();
    for email in emails {
        let key = format!("breach:{}", sha256::hex(email.as_bytes()));
        let run = cache.run(&key)?;
        let found = match &run {
            Some((_, at, res)) if offline || *at > now() - WEEK => names(res),
            _ if offline => continue,
            _ => match lookup(net, &email) {
                Ok(n) => {
                    cache.put_run(&key, "", &Value::from(n.clone()))?;
                    n
                }
                Err(e) if e.is_source() => match &run {
                    Some((_, _, res)) => names(res),
                    None => continue,
                },
                Err(e) => return Err(e),
            },
        };
        if !found.is_empty() {
            out.insert(email, found);
        }
    }
    cache.commit()?;
    Ok(out)
}

fn lookup(net: &dyn Net, email: &str) -> Result<Vec<String>> {
    lookup_with(net, email, hibp_key())
}

/// Have I Been Pwned with `key`, else XposedOrNot.
fn lookup_with(net: &dyn Net, email: &str, key: Option<String>) -> Result<Vec<String>> {
    if let Some(key) = key {
        let r = fetch::request(
            net,
            "haveibeenpwned",
            &url("haveibeenpwned").replace("{}", &quote(email)),
            None,
            &[("hibp-api-key", &key)],
            None,
        )?;
        if r.status == 404 {
            return Ok(Vec::new());
        }
        let v = json::parse(&r.body, json::MAX_DOCUMENT)?;
        return Ok(v
            .as_array()
            .map(|a| a.iter().map(|b| json::str_at(b, "Name").to_string()).collect())
            .unwrap_or_default());
    }
    let r = fetch::request(net, "xposedornot", &url("xposedornot").replace("{}", &quote(email)), None, &[], None)?;
    if r.status == 404 {
        return Ok(Vec::new());
    }
    let v = json::parse(&r.body, json::MAX_DOCUMENT).map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(json::arr_at(&v, "breaches").iter().flat_map(names).collect())
}

#[cfg(test)]
#[path = "breaches_tests.rs"]
mod tests;
