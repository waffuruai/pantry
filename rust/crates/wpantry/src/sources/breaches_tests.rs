use super::*;
use crate::utils::net::{Fake, Response};
use serde_json::json;

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
    assert_eq!(got, BTreeMap::from([("pwned@example.com".to_string(), vec!["Adobe".to_string(), "LinkedIn".into()])]));
    // Within the week, and offline, the cached answer is served.
    let quiet = Fake::new(|_| panic!("cached"));
    assert_eq!(check_emails(&c, &quiet, false, emails(&["pwned@example.com"])).unwrap().len(), 1);
    assert_eq!(check_emails(&c, &quiet, true, emails(&["pwned@example.com"])).unwrap().len(), 1);
    assert!(check_emails(&c, &quiet, true, emails(&["never@example.com"])).unwrap().is_empty(), "offline, unasked");
    // Unreachable: the week-old answer is kept; an address never answered is skipped.
    let key = format!("breach:{}", sha256::hex(b"pwned@example.com"));
    c.conn.execute("UPDATE runs SET ran_at = ran_at - ? WHERE source = ?", rusqlite::params![WEEK + 1.0, key]).unwrap();
    assert_eq!(
        check_emails(&c, &Fake::offline(), false, emails(&["pwned@example.com", "new@example.com"])).unwrap().len(),
        1
    );
    assert!(matches!(check_emails(&c, &net, false, emails(&["broken@example.com"])), Err(Error::Missing(_))));
}
