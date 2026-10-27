//! Opt-in: is the developer's email in known breach data?
//!
//! This is the one check that sends personal data off the machine, so it
//! never runs until the user says yes (asked once on a terminal, or
//! `wscanner breach --enable`), and the answer is remembered. Have I Been
//! Pwned is used when HIBP_API_KEY is set (its email lookup is paid);
//! otherwise XposedOrNot's free lookup. Results are cached for a week. The
//! library never reads the terminal: the CLI passes the question's answerer.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::json;
use crate::net::{self, Net};
use crate::sha256;
use crate::system::{now, run, which};
use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::time::Duration;

pub const WEEK: f64 = 7.0 * 86400.0;

/// Asks the user a yes/no question; None when nobody can answer.
pub type Ask<'a> = &'a dyn Fn(&str) -> Option<bool>;

fn hibp_key() -> Option<String> {
    std::env::var("HIBP_API_KEY").ok().filter(|k| !k.is_empty())
}

/// True/false once decided; None when undecided and nobody can be asked.
pub fn consent(cache: &Cache, ask: Option<Ask>) -> Result<Option<bool>> {
    match cache.get("breach_consent")?.as_deref() {
        Some("yes") => return Ok(Some(true)),
        Some("no") => return Ok(Some(false)),
        _ => {}
    }
    let Some(ask) = ask else { return Ok(None) };
    let emails = emails_to_check().join(", ");
    let emails = if emails.is_empty() { "your git email".to_string() } else { emails };
    let service = if hibp_key().is_some() { "Have I Been Pwned" } else { "XposedOrNot" };
    let Some(yes) = ask(&format!("Check {emails} against breach data? This sends the address to {service}. [y/N] "))
    else {
        return Ok(None);
    };
    cache.set("breach_consent", if yes { "yes" } else { "no" })?;
    cache.commit()?;
    Ok(Some(yes))
}

/// The developer's addresses: git's global user.email and, with the GitHub
/// CLI, the account's emails. No-reply addresses are skipped.
pub fn emails_to_check() -> Vec<String> {
    let mut found = Vec::new();
    if let Some(git) = which("git") {
        found.push(run(
            &[git.as_os_str(), "config".as_ref(), "--global".as_ref(), "user.email".as_ref()],
            Duration::from_secs(15),
        ));
    }
    if let Some(gh) = which("gh") {
        let out = crate::system::exec(
            &[
                gh.as_os_str(),
                OsStr::new("api"),
                OsStr::new("user/emails"),
                OsStr::new("--jq"),
                OsStr::new(".[].email"),
            ],
            &[],
            Duration::from_secs(30),
        );
        let emails = match out {
            Ok(o) if o.code == Some(0) => o.stdout,
            _ => crate::system::exec(
                &[
                    gh.as_os_str(),
                    OsStr::new("api"),
                    OsStr::new("user"),
                    OsStr::new("--jq"),
                    OsStr::new(".email // empty"),
                ],
                &[],
                Duration::from_secs(30),
            )
            .map(|o| o.stdout)
            .unwrap_or_default(),
        };
        found.push(emails);
    }
    let mut out: Vec<String> = Vec::new();
    for e in found.iter().flat_map(|f| f.split_whitespace()) {
        let e = e.trim().to_lowercase();
        if e.contains('@') && !e.contains("noreply") && !out.contains(&e) {
            out.push(e);
        }
    }
    out
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

/// {email: [breach name, ...]} for the emails that appear in breaches.
pub fn check(cache: &Cache, net: &dyn Net, offline: bool) -> Result<BTreeMap<String, Vec<String>>> {
    let mut out = BTreeMap::new();
    for email in emails_to_check() {
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
    if let Some(key) = hibp_key() {
        let r = net::request(
            net,
            &format!("https://haveibeenpwned.com/api/v3/breachedaccount/{}", quote(email)),
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
    let r =
        net::request(net, &format!("https://api.xposedornot.com/v1/check-email/{}", quote(email)), None, &[], None)?;
    if r.status == 404 {
        return Ok(Vec::new());
    }
    let v = json::parse(&r.body, json::MAX_DOCUMENT).map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(json::arr_at(&v, "breaches").iter().flat_map(names).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_and_consent() {
        assert_eq!(quote("a.b+c@example.com"), "a.b%2Bc%40example.com");
        let d = crate::system::TempDir::new("breach").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        assert_eq!(consent(&c, None).unwrap(), None, "undecided, and nobody to ask");
        assert_eq!(consent(&c, Some(&|_| None)).unwrap(), None);
        assert_eq!(consent(&c, Some(&|q| Some(q.contains("against breach data")))).unwrap(), Some(true));
        assert_eq!(consent(&c, Some(&|_| panic!("asked once"))).unwrap(), Some(true));
    }
}
