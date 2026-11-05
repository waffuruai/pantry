//! Opt-in: is the developer's email in known breach data?
//!
//! This is the one check that sends personal data off the machine, so it
//! never runs until the user says yes (asked once on a terminal, or
//! `wpantry breach --enable`), and the answer is remembered. The lookups and
//! their week-long cache are in [`crate::sources::breaches`]. The library
//! never reads the terminal: the CLI passes the question's answerer.

use crate::checks::Scan;
use crate::db::Cache;
use crate::error::Result;
use crate::finding::Finding;
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

/// The opt-in email breach check.
pub fn breach(scan: &mut Scan) -> Result<()> {
    let ask = if scan.opts.ask { scan.asker } else { None };
    if crate::checks::email::consent(&scan.cache, ask)? != Some(true) {
        return Ok(());
    }
    scan.status("Checking your email against breach data");
    for (email, names) in crate::checks::email::check(&scan.cache, scan.net, scan.opts.offline)? {
        let shown = names.iter().take(6).cloned().collect::<Vec<_>>().join(", ");
        let more = if names.len() > 6 { format!(" and {} more", names.len() - 6) } else { String::new() };
        scan.add(Finding {
            kind: "account".into(),
            component: email,
            location: "breach data".into(),
            vuln_id: "BREACH".into(),
            status: "warn".into(),
            note: format!("in {} breaches: {shown}{more}", names.len()),
            fix_cmd: "Change any password reused from those sites; turn on 2FA".into(),
            ..Default::default()
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Options;
    use crate::checks::supply_chain::testing;
    use crate::utils::net::Fake;
    use crate::utils::temp::TempDir;

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

    /// Nothing is sent anywhere without consent: undecided and nobody to
    /// ask is nothing; asked and declined is remembered.
    #[test]
    fn the_breach_check_needs_consent() {
        let d = TempDir::new("breach").unwrap();
        let net = Fake::new(|r| panic!("asked {} without consent", r.url));
        let mut s = testing::scan(&net, &d, Options::default());
        breach(&mut s).unwrap();
        assert!(s.findings.is_empty());
        let asked = std::sync::Mutex::new(Vec::new());
        let ask = |q: &str| {
            asked.lock().unwrap().push(q.to_string());
            Some(false)
        };
        let mut s = testing::scan(&net, &d, Options { ask: true, ..Default::default() }).with_ask(&ask);
        breach(&mut s).unwrap();
        assert_eq!(asked.lock().unwrap().len(), 1);
        assert_eq!(s.cache.get("breach_consent").unwrap().as_deref(), Some("no"));
        breach(&mut s).unwrap();
        assert_eq!(asked.lock().unwrap().len(), 1, "remembered");
        assert!(s.findings.is_empty());
    }
}
