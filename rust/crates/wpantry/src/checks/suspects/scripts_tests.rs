use super::super::ids;
use super::*;

const PAGE: &str = "<html><script src=\"https://cdn.perf.example/tag.js\"></script><script src=\"/app.js\"></script><script src=\"https://cdn.jsdelivr.net/x.js\" integrity=\"sha384-abc\" crossorigin=\"anonymous\"></script></html>";

#[test]
fn an_unpinned_script_warns_and_fails_on_a_signing_project() {
    let t = third_party_scripts("index.html", PAGE, false);
    assert_eq!(ids(&t), [("SUSPECT-THIRD-PARTY-SCRIPT", false)]);
    assert_eq!(
        t[0].note,
        "loads cdn.perf.example's script with no integrity hash: whoever controls that host controls this page"
    );
    let t = third_party_scripts("index.html", PAGE, true);
    assert_eq!(ids(&t), [("SUSPECT-THIRD-PARTY-SCRIPT", true)]);
    assert!(t[0].note.contains(", on a project that asks wallets to sign"), "{}", t[0].note);
    let two = "<script src=\"https://a.example/1.js\"></script>\n<script src=\"https://b.example/2.js\"></script>";
    let t = third_party_scripts("p.html", two, false);
    assert_eq!(t.len(), 1, "one finding per page");
    assert!(t[0].note.contains("a.example"));
    let later = "<p>hi</p>\n\n<script src='//cdn.example/x.js'></script>";
    let t = third_party_scripts("p.html", later, false);
    assert_eq!((t[0].line, t[0].note.contains("cdn.example")), (3, true), "scheme-relative, on its line");
}

#[test]
fn plain_http_fails() {
    let t = third_party_scripts("index.html", "<script src='http://x.y/a.js'></script>", false);
    assert_eq!(ids(&t), [("SUSPECT-THIRD-PARTY-SCRIPT", true)]);
    assert!(t[0].note.contains("x.y's script with no integrity hash, over plain http:"), "{}", t[0].note);
}

#[test]
fn local_pinned_and_inline_scripts_are_nothing() {
    assert!(third_party_scripts("index.html", "<script src=\"/local.js\"></script>", true).is_empty());
    assert!(third_party_scripts("index.html", "<script src=\"./app.js\"></script>", true).is_empty());
    let pinned = "<script src=\"https://cdn.example/x.js\" integrity=\"sha384-abc\"></script>";
    assert!(third_party_scripts("index.html", pinned, true).is_empty());
    assert!(third_party_scripts("index.html", "<script>alert(1)</script>", true).is_empty(), "inline");
    assert!(
        third_party_scripts("index.html", "<p>&lt;script src=https://x.y/a.js&gt;</p>", true).is_empty(),
        "escaped prose"
    );
    assert!(third_party_scripts("index.html", "<script type=module></script>", true).is_empty(), "no src");
}

#[test]
fn attributes_quoted_or_bare() {
    assert_eq!(attr("<script src=\"a.js\" defer", "src"), Some("a.js"));
    assert_eq!(attr("<script src='a.js'", "src"), Some("a.js"));
    assert_eq!(attr("<script src=a.js defer", "src"), Some("a.js"));
    assert_eq!(attr("<script src=a.js/", "src"), Some("a.js"));
    assert_eq!(attr("<script defer", "src"), None);
    assert_eq!(attr("<script src=", "src"), None, "an empty value is no value");
}
