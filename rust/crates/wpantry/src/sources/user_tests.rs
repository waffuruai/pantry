use super::*;
use crate::sources::file::merged;
use crate::sources::testing::cache;
use crate::utils::net::{Fake, Response};

fn user(body: &str) -> Source {
    let all = merged(&format!("[[source]]\n{body}\n")).unwrap();
    all.into_iter().last().unwrap()
}

#[test]
fn a_new_host_is_used_only_after_a_yes_kept_by_id_and_url() {
    let (_d, c) = cache();
    let s =
        user("id = \"team-rules\"\nkind = \"yara\"\nformat = \"yara\"\nurl = \"https://rules.example.com/team.yar\"");
    assert!(consent(&c, None, &s).unwrap().unwrap_err().contains("needs your yes"), "--no-input: not used");
    let yes = |_: &str| Some(true);
    assert_eq!(consent(&c, Some(&yes), &s).unwrap(), Ok(()));
    assert_eq!(consent(&c, None, &s).unwrap(), Ok(()), "the yes is kept");
    let moved = Source { url: "https://other.example.com/team.yar".into(), ..s.clone() };
    assert!(consent(&c, None, &moved).unwrap().is_err(), "a new URL is asked about again");
    let no = |_: &str| Some(false);
    assert_eq!(consent(&c, Some(&no), &moved).unwrap(), Err("you said no to it".into()));
    assert!(consent(&c, None, &moved).unwrap().is_err(), "the no is kept");
    let known =
        user("id = \"mirror\"\nkind = \"hosts\"\nformat = \"lines\"\nurl = \"https://feodotracker.abuse.ch/x.txt\"");
    assert_eq!(consent(&c, None, &known).unwrap(), Ok(()), "a host wpantry already asks needs no yes");
    let lookup = user(
        "id = \"our-lookup\"\nkind = \"hash-lookup\"\nformat = \"circl\"\nurl = \"https://hashlookup.circl.lu/x/\"\nsends = \"sha256\"",
    );
    assert!(consent(&c, None, &lookup).unwrap().is_err(), "sending a hash always needs its own yes");
}

#[test]
fn file_sources_land_in_their_places_and_leave_when_dropped() {
    let (d, c) = cache();
    let rules = d.path().join("rules");
    let mine = vec![
        user("id = \"t-rules\"\nkind = \"yara\"\nformat = \"yara\"\nurl = \"https://api.osv.dev/r.yar\""),
        user("id = \"t-hosts\"\nkind = \"hosts\"\nformat = \"lines\"\nurl = \"https://api.osv.dev/h.txt\""),
    ];
    let net = Fake::new(|r| {
        Ok(Response::ok(if r.url.ends_with(".yar") { "rule t { condition: true }" } else { "bad.example\n" }))
    });
    assert!(fetch_files(&c, &net, &rules, &mine, &mine, false).is_empty());
    assert!(rules.join("user-t-rules.yar").is_file() && rules.join("iocs/user-t-hosts.hosts.txt").is_file());
    assert!(fetch_files(&c, &net, &rules, &mine[..1], &mine, false).is_empty());
    assert!(rules.join("iocs/user-t-hosts.hosts.txt").exists(), "listed but not used this run (deep, say): kept");
    assert!(fetch_files(&c, &net, &rules, &mine[..1], &mine[..1], false).is_empty());
    assert!(!rules.join("iocs/user-t-hosts.hosts.txt").exists(), "a source no longer listed leaves");
    let gone = Fake::offline();
    std::fs::remove_file(rules.join("user-t-rules.yar")).unwrap();
    assert_eq!(
        fetch_files(&c, &gone, &rules, &mine[..1], &mine[..1], false).len(),
        1,
        "unreachable with no copy: said so"
    );
}
