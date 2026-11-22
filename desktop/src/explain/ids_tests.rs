use super::*;
use crate::explain::is_advisory;
use crate::explain::kinds::advisory_shaped;
use crate::explain::tests::{advisory, own};

#[test]
fn ids_link_to_their_database() {
    assert_eq!(
        advisory_url("CVE-2021-25900").unwrap(),
        "https://www.cve.org/CVERecord?id=CVE-2021-25900"
    );
    assert_eq!(
        advisory_url("GHSA-43w2-9j62-hq99").unwrap(),
        "https://github.com/advisories/GHSA-43w2-9j62-hq99"
    );
    assert_eq!(
        advisory_url("RUSTSEC-2021-0003").unwrap(),
        "https://osv.dev/vulnerability/RUSTSEC-2021-0003"
    );
    assert_eq!(advisory_url("DEMO-2026-0001"), None);
    assert_eq!(advisory_url("x?y=<script>"), None);
    let mut f = advisory(&[], "");
    f.aliases = vec![
        "GHSA-aaaa-bbbb-cccc".into(),
        "CVE-2026-12345".into(),
        "bad id".into(),
    ];
    let ids: Vec<String> = identifiers(&f).into_iter().map(|i| i.id).collect();
    assert_eq!(ids, ["CVE-2026-12345", "GHSA-aaaa-bbbb-cccc"]);
}

/// Oracle: EPSS is an estimate of attempts, so the words never say
/// this computer will be attacked, and the label does not repeat it.
#[test]
fn epss_reads_as_a_chance_out_of_100() {
    assert_eq!(epss_text(0.0213), "about 2 in 100 (EPSS)");
    assert_eq!(epss_text(0.001), "less than 1 in 100 (EPSS)");
    assert!(epss_text(0.97).starts_with("about 97 in 100"));
    for text in [epss_text(0.5), EPSS_LABEL.to_owned()] {
        assert!(!text.contains("being attacked"), "{text}");
    }
}

/// Oracle: OSV's id shapes are advisories, Pantry's markers are not;
/// an id with only aliases or only weakness types is an advisory.
#[test]
fn advisory_ids_are_recognised_by_shape() {
    for id in [
        "CVE-2026-1",
        "GHSA-43w2-9j62-hq99",
        "ghsa-43w2-9j62-hq99",
        "RUSTSEC-2021-0003",
        "DEBIAN-CVE-2024-1234",
        "CURL-CVE-2023-38545",
        "PYSEC-2024-1",
        "DEMO-2026-0001",
    ] {
        assert!(advisory_shaped(id), "{id}");
        assert!(
            advisory_url(id).is_some() || id.starts_with("DEMO-"),
            "{id}"
        );
    }
    assert_eq!(
        advisory_url("DEBIAN-CVE-2024-1234").unwrap(),
        "https://osv.dev/vulnerability/DEBIAN-CVE-2024-1234"
    );
    assert!(
        advisory_url("ghsa-43w2-9j62-hq99")
            .unwrap()
            .starts_with("https://osv.dev/")
    );
    for id in [
        "EOL",
        "OS-UPDATE",
        "SUSPECT-RAW-IP",
        "IMG-2-SCRIPT",
        "POSTURE-SIP",
        "INSTALL-HOOK",
        "CLIPPER-EXTENSION",
        "MAL-2026-1",
        "",
    ] {
        assert!(!advisory_shaped(id), "{id}");
    }
    let mut aliases_only = own("project", "SOMETHING");
    aliases_only.aliases = vec!["CVE-2026-1".into()];
    assert!(is_advisory(&aliases_only));
    let mut cwe_only = own("project", "SOMETHING");
    cwe_only.cwe = vec!["CWE-79".into()];
    assert!(is_advisory(&cwe_only));
    assert!(!is_advisory(&own("project", "SOMETHING")));
}

/// Oracle: an id that is not plain (a slash, a space, over 64
/// characters) is never shown as an identifier or turned into a link.
#[test]
fn unsafe_ids_give_no_identifier_and_no_url() {
    let long = format!("CVE-2026-{}", "1".repeat(60));
    for id in ["CVE-2026-1/../x", "GHSA-a/b", long.as_str()] {
        assert_eq!(advisory_url(id), None, "{id}");
        let mut f = advisory(&[], "");
        f.vuln_id = id.into();
        f.aliases = vec![id.into()];
        assert!(identifiers(&f).is_empty(), "{id}: {:?}", identifiers(&f));
    }
    let ok = format!("CVE-2026-{}", "1".repeat(55));
    assert_eq!(ok.len(), 64);
    assert!(advisory_url(&ok).is_some());
}
