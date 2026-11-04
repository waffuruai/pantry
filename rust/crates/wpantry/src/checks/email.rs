//! Opt-in: is the developer's email in known breach data?
//!
//! This is the one check that sends personal data off the machine, so it
//! never runs until the user says yes (asked once on a terminal, or
//! `wpantry breach --enable`), and the answer is remembered. The lookups and
//! their week-long cache are in [`crate::sources::breaches`]. The library
//! never reads the terminal: the CLI passes the question's answerer.

use crate::db::Cache;
use crate::error::Result;
use crate::sources::breaches::{check_emails, hibp_key};
use crate::utils::net::Net;
use crate::utils::process::run;
use crate::utils::process::which;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::time::Duration;

/// Asks the user a yes/no question (the CLI adds the `[y/N]` and the
/// default, no); None when nobody can answer.
pub type Ask<'a> = &'a dyn Fn(&str) -> Option<bool>;

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
    let Some(yes) = ask(&format!("Check {emails} against breach data? This sends the address to {service}.")) else {
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
        let out = crate::utils::process::exec(
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
            _ => crate::utils::process::exec(
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
    emails_from(&found)
}

/// The distinct, lowercased addresses in what git and gh printed.
fn emails_from(found: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in found.iter().flat_map(|f| f.split_whitespace()) {
        let e = e.trim().to_lowercase();
        if e.contains('@') && !e.contains("noreply") && !out.contains(&e) {
            out.push(e);
        }
    }
    out
}

/// {email: [breach name, ...]} for the emails that appear in breaches.
pub fn check(cache: &Cache, net: &dyn Net, offline: bool) -> Result<BTreeMap<String, Vec<String>>> {
    check_emails(cache, net, offline, emails_to_check())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::sources::breaches::quote;

    #[test]
    fn quoting_and_consent() {
        assert_eq!(quote("a.b+c@example.com"), "a.b%2Bc%40example.com");
        let d = crate::utils::temp::TempDir::new("breach").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        assert_eq!(consent(&c, None).unwrap(), None, "undecided, and nobody to ask");
        assert_eq!(consent(&c, Some(&|_| None)).unwrap(), None);
        assert_eq!(consent(&c, Some(&|q| Some(q.contains("against breach data")))).unwrap(), Some(true));
        assert_eq!(consent(&c, Some(&|_| panic!("asked once"))).unwrap(), Some(true));
    }

    #[test]
    fn a_no_is_remembered_too() {
        let d = crate::utils::temp::TempDir::new("breach").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        c.set("breach_consent", "no").unwrap();
        assert_eq!(consent(&c, Some(&|_| panic!("decided"))).unwrap(), Some(false));
    }

    #[test]
    fn addresses_are_distinct_lowercased_and_never_noreply() {
        let found = [
            "Dev@Example.com\n".to_string(),
            "dev@example.com\n123+dev@users.noreply.github.com\nother@x.io\nnot-an-email".into(),
        ];
        assert_eq!(emails_from(&found), ["dev@example.com", "other@x.io"]);
        assert!(emails_from(&[]).is_empty());
    }
}
