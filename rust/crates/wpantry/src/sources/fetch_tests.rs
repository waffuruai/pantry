use super::*;
use crate::sources::file::parse;
use crate::sources::testing::cache;
use crate::utils::net::Fake;

fn one(body: &str) -> Source {
    parse(&format!("[[source]]\nid = \"t\"\nurl = \"https://api.osv.dev/x\"\n{body}\n")).unwrap().remove(0)
}

#[test]
fn a_file_is_refetched_when_due_and_pinned_and_capped() {
    let (_d, c) = cache();
    let net = Fake::new(|_| Ok(Response::ok("hello")));
    let s = one("max_bytes = 100\nrefresh = \"1d\"");
    assert_eq!(file_of(&c, &net, &s, "t", false).unwrap().as_deref(), Some(&b"hello"[..]));
    assert_eq!(file_of(&c, &net, &s, "t", false).unwrap(), None, "fresh: not asked again");
    assert_eq!(net.requests().len(), 1);
    let pinned = one(&format!("max_bytes = 100\nsha256 = \"{}\"", "0".repeat(64)));
    c.unset("p_at").unwrap();
    assert_eq!(file_of(&c, &net, &pinned, "p", false).unwrap(), None, "a copy that fails its pin isn't kept");
    let good = one(&format!("max_bytes = 100\nsha256 = \"{}\"", crate::utils::sha256::hex(b"hello")));
    assert!(file_of(&c, &net, &good, "g", false).unwrap().is_some());
    let small = one("max_bytes = 3");
    assert_eq!(file_of(&c, &net, &small, "s", false).unwrap(), None, "over its cap: unreachable, the last copy stays");
    assert_eq!(file_of(&c, &net, &s, "o", true).unwrap(), None, "offline asks nothing");
}

#[test]
fn the_listing_is_every_source_with_its_state() {
    let (_d, c) = cache();
    record("t-listed", Ok(10));
    save_matching(&c, |id| id == "t-listed").unwrap();
    let sources = parse(
        "[[source]]\nid = \"t-listed\"\nurl = \"https://a.b/\"\n[[source]]\nid = \"t-never\"\nurl = \"https://a.b/\"\n",
    )
    .unwrap();
    let all = listing_of(&c, &sources).unwrap();
    assert_eq!(
        all.iter().map(|l| (l.source.id.as_str(), l.fresh, l.state.bytes)).collect::<Vec<_>>(),
        [("t-listed", true, 10), ("t-never", false, 0)]
    );
    assert_eq!(listing(&c).unwrap().len(), crate::sources::file::bundled().len());
}

#[test]
fn outcomes_are_kept_and_a_failure_keeps_the_last_success() {
    let (_d, c) = cache();
    record("t-ok", Ok(5));
    save_matching(&c, |id| id.starts_with("t-")).unwrap();
    let first = states(&c).unwrap()["t-ok"].clone();
    assert!(first.success > 0.0 && first.error.is_empty() && first.bytes == 5);
    rejected("t-ok", "garbage");
    save_matching(&c, |id| id.starts_with("t-")).unwrap();
    let after = states(&c).unwrap()["t-ok"].clone();
    assert_eq!((after.success, after.bytes), (first.success, 5), "the last success stays");
    assert_eq!(after.error, "rejected: garbage");
    note::<()>("t-git", &Err(Error::Offline("no network".into())));
    let e = invalid("t-bad", "no rows");
    assert!(matches!(e, Error::Invalid(m) if m == "t-bad: no rows"));
    save_matching(&c, |id| id.starts_with("t-")).unwrap();
    let all = states(&c).unwrap();
    assert_eq!((all["t-git"].success, all["t-git"].error.as_str()), (0.0, "no network"));
    assert_eq!(all["t-bad"].error, "rejected: no rows");
}
