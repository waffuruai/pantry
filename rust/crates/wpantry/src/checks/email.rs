//! Opt-in: is the developer's email in known breach data?
//!
//! This is the one check that sends personal data off the machine, so it
//! never runs until the user says yes (asked once on a terminal, or
//! `wpantry breach --enable`), and the answer is remembered. Have I Been
//! Pwned is used when HIBP_API_KEY is set (its email lookup is paid);
//! otherwise XposedOrNot's free lookup. Results are cached for a week. The
//! library never reads the terminal: the CLI passes the question's answerer.

use crate::db::Cache;
use crate::error::{Error, Result};
use crate::utils::json;
use crate::utils::net::{self, Net};
use crate::utils::os::now;
use crate::utils::process::run;
use crate::utils::process::which;
use crate::utils::sha256;
use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::time::Duration;

pub const WEEK: f64 = 7.0 * 86400.0;

/// Asks the user a yes/no question (the CLI adds the `[y/N]` and the
/// default, no); None when nobody can answer.
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
    check_emails(cache, net, offline, emails_to_check())
}

fn check_emails(
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
    use crate::utils::net::{Fake, Response};
    use serde_json::json;

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

    fn fake() -> Fake {
        Fake::new(|r| {
            let email = r.url.rsplit('/').next().unwrap_or("");
            if r.url.starts_with("https://haveibeenpwned.com/") {
                assert!(r.header("hibp-api-key").is_some());
                return Ok(match email {
                    "clean%40example.com" => Response { status: 404, body: Vec::new(), etag: None },
                    "bad%40example.com" => Response::ok("<html>"),
                    _ => Response::ok(json!([{"Name": "Adobe"}, {"Name": "LinkedIn"}]).to_string()),
                });
            }
            Ok(match email {
                "clean%40example.com" => Response { status: 404, body: Vec::new(), etag: None },
                "down%40example.com" => Response { status: 503, body: Vec::new(), etag: None },
                "bad%40example.com" => Response::ok("<html>"),
                "broken%40example.com" => return Err(Error::Missing("not a source failure".into())),
                _ => Response::ok(json!({"breaches": [["Adobe", "LinkedIn"]]}).to_string()),
            })
        })
    }

    #[test]
    fn lookups_read_both_services() {
        let net = fake();
        let key = Some("k".to_string());
        assert_eq!(lookup_with(&net, "pwned@example.com", key.clone()).unwrap(), ["Adobe", "LinkedIn"]);
        assert_eq!(lookup_with(&net, "clean@example.com", key.clone()).unwrap(), Vec::<String>::new());
        assert!(matches!(lookup_with(&net, "bad@example.com", key), Err(Error::Invalid(_))));
        assert_eq!(lookup_with(&net, "pwned@example.com", None).unwrap(), ["Adobe", "LinkedIn"]);
        assert_eq!(lookup_with(&net, "clean@example.com", None).unwrap(), Vec::<String>::new());
        assert!(matches!(lookup_with(&net, "bad@example.com", None), Err(Error::Invalid(_))));
        assert!(matches!(lookup_with(&net, "down@example.com", None), Err(Error::Offline(_))));
        let urls: Vec<String> = net.requests().iter().map(|r| r.url.clone()).collect();
        assert_eq!(urls[0], "https://haveibeenpwned.com/api/v3/breachedaccount/pwned%40example.com");
        assert_eq!(urls[3], "https://api.xposedornot.com/v1/check-email/pwned%40example.com");
    }

    #[test]
    fn answers_are_cached_a_week_and_stale_beats_nothing() {
        let d = crate::utils::temp::TempDir::new("breach").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        let emails = |s: &[&str]| s.iter().map(|e| e.to_string()).collect::<Vec<_>>();
        let net = fake();
        let got = check_emails(&c, &net, false, emails(&["pwned@example.com", "clean@example.com"])).unwrap();
        assert_eq!(
            got,
            BTreeMap::from([("pwned@example.com".to_string(), vec!["Adobe".to_string(), "LinkedIn".into()])])
        );
        // Within the week, and offline, the cached answer is served.
        let quiet = Fake::new(|_| panic!("cached"));
        assert_eq!(check_emails(&c, &quiet, false, emails(&["pwned@example.com"])).unwrap().len(), 1);
        assert_eq!(check_emails(&c, &quiet, true, emails(&["pwned@example.com"])).unwrap().len(), 1);
        assert!(check_emails(&c, &quiet, true, emails(&["never@example.com"])).unwrap().is_empty(), "offline, unasked");
        // Unreachable: the week-old answer is kept; an address never answered is skipped.
        let key = format!("breach:{}", sha256::hex(b"pwned@example.com"));
        c.conn
            .execute("UPDATE runs SET ran_at = ran_at - ? WHERE source = ?", rusqlite::params![WEEK + 1.0, key])
            .unwrap();
        assert_eq!(
            check_emails(&c, &Fake::offline(), false, emails(&["pwned@example.com", "new@example.com"])).unwrap().len(),
            1
        );
        assert!(matches!(check_emails(&c, &net, false, emails(&["broken@example.com"])), Err(Error::Missing(_))));
    }
}
