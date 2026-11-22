use super::{cwe_id, plain_id};

/// Oracle: an id the desktop may show and link is short and plain.
/// Known bad: a slash (a path in a link), a space, a quote, or more
/// than 64 characters is never a plain id.
#[test]
fn only_short_plain_ids_are_kept() {
    for id in ["CVE-2026-1", "GHSA-43w2-9j62-hq99", "RHSA-2024:1234", "PYSEC-2024_1.a"] {
        assert!(plain_id(id), "{id}");
    }
    let long = format!("CVE-2026-{}", "1".repeat(56));
    assert_eq!(long.len(), 65);
    for id in ["", "CVE-2026-1/../x", "GHSA a", "CVE-2026-1\"", "CVE-\u{202E}1", long.as_str()] {
        assert!(!plain_id(id), "{id:?}");
    }
    assert!(plain_id(&long[..64]));
}

#[test]
fn weakness_ids_read_in_their_usual_spelling() {
    assert_eq!(cwe_id(" cwe-79 ").as_deref(), Some("CWE-79"));
    for raw in ["NVD-CWE-Other", "CWE-noinfo", "CWE-", "CWE-1234567"] {
        assert_eq!(cwe_id(raw), None, "{raw}");
    }
}
