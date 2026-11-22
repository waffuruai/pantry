use super::*;
use crate::explain::ids::Identifier;
use crate::explain::keywords::{CRASHES, keyword_sentence};
use crate::explain::kinds::{INSTALL_SCRIPT, MALICIOUS, MISSING_TOOL, kind_sentence};
use crate::explain::weaknesses::{WEAKNESSES, cwe_sentence, main_cwe, weakness};

pub(super) fn advisory(cwe: &[&str], summary: &str) -> Finding {
    serde_json::from_value(serde_json::json!({
        "kind": "project", "component": "demo", "version": "1.0", "location": "",
        "vuln_id": "CVE-2026-12345", "status": "fail", "note": "", "fixed": "1.1",
        "severity": "HIGH", "kev": false, "fix_cmd": "",
        "summary": summary, "cwe": cwe,
    }))
    .unwrap()
}

#[test]
fn every_weakness_in_the_table_gives_its_sentence() {
    for (number, name, sentence) in WEAKNESSES {
        let id = format!("CWE-{number}");
        let e = explain(&advisory(&[&id], ""));
        assert_eq!(
            (e.sentence.as_str(), e.source),
            (*sentence, Source::Cwe),
            "{id}"
        );
        assert_eq!(cwe_name(&id), Some(*name));
        assert!(!sentence.contains('—'), "{id}: no em-dashes");
    }
    // The ones the brief names are all there.
    for n in [
        787, 125, 119, 416, 94, 77, 78, 89, 79, 22, 502, 287, 862, 863, 306, 269, 200, 918, 352,
        400, 770, 190, 20, 798, 327, 295, 362, 601, 611, 1321, 434, 476, 1333,
    ] {
        assert!(weakness(n).is_some(), "CWE-{n} missing");
    }
}

#[test]
fn a_known_weakness_never_falls_back_to_the_generic_sentence() {
    // Known bad: the generic sentence for a finding whose CWE is known.
    let e = explain(&advisory(&["CWE-79"], ""));
    assert_ne!(e.sentence, GENERIC);
    assert_eq!(e.source, Source::Cwe);
    // The first known one wins over an unknown one listed first.
    let e = explain(&advisory(&["CWE-99999", "CWE-89"], ""));
    assert_eq!(e.sentence, cwe_sentence("CWE-89").unwrap());
}

#[test]
fn an_unknown_weakness_falls_back_to_the_summary_then_the_neutral_sentence() {
    let e = explain(&advisory(
        &["CWE-99999"],
        "Remote code execution in the parser",
    ));
    assert_eq!(e.source, Source::Keyword);
    assert!(e.sentence.contains("run their own programs"));
    let e = explain(&advisory(&["CWE-99999"], "A bug in the parser"));
    assert_eq!((e.sentence.as_str(), e.source), (GENERIC, Source::Generic));
    // Empty everything: neutral, nothing invented.
    let e = explain(&advisory(&[], ""));
    assert_eq!((e.sentence.as_str(), e.source), (GENERIC, Source::Generic));
    let mut unfixed = advisory(&[], "");
    unfixed.fixed.clear();
    assert_eq!(explain(&unfixed).sentence, GENERIC_UNFIXED);
}

#[test]
fn summary_words_map_to_their_consequence() {
    let cases = [
        (
            "Denial of service via crafted header",
            "crash or stop responding",
        ),
        ("Information disclosure in logs", "Private information"),
        ("Local privilege escalation", "more control"),
        ("Certificate spoofing", "pretend to be"),
        ("Signature check bypass", "get around a security check"),
        ("Stored XSS in comments", "someone else's script"),
    ];
    for (summary, expected) in cases {
        let e = explain(&advisory(&[], summary));
        assert_eq!(e.source, Source::Keyword, "{summary}");
        assert!(e.sentence.contains(expected), "{summary}: {}", e.sentence);
    }
    // Whole words: "xss" inside another word is not cross-site scripting.
    assert_eq!(keyword_sentence("the axssy module"), None);
}

#[test]
fn every_kind_explains_itself() {
    let make = |kind: &str, id: &str| -> Finding {
        serde_json::from_value(serde_json::json!({
            "kind": kind, "component": "x", "version": "", "location": "",
            "vuln_id": id, "status": "warn", "note": "", "fixed": "",
            "severity": "", "kev": false, "fix_cmd": "",
        }))
        .unwrap()
    };
    for (kind, id) in [
        ("secret", "aws-access-token"),
        ("runtime", "EOL"),
        ("tool", "OUTDATED"),
        ("malware", "MALWARE"),
        ("posture", "POSTURE-SIP"),
        ("suspect-code", "SUSPECT-RAW-IP"),
        ("hidden-text", "HIDDEN-BIDI"),
        ("document", "DOC-MACRO"),
        ("persistence", "PERSISTENCE-NEW"),
        ("clipper", "CLIPPER-PERSISTENCE"),
        ("browser", "BROWSER"),
        ("os", "OS-UPDATE"),
        ("license", "LICENSE"),
        ("install-script", "INSTALL-SCRIPT"),
        ("repo-hook", "core.hooksPath"),
        ("account", "BREACH"),
        ("config", "IGNORE-PROTECTED"),
        ("mcp", "UNPINNED"),
        ("extension", "DEPRECATED"),
        ("unchecked", "UNCHECKED"),
    ] {
        let e = explain(&make(kind, id));
        assert_eq!(e.source, Source::Kind, "{kind} {id}");
        assert_ne!(e.sentence, GENERIC_CHECK);
    }
    // An unknown kind with no marker: the neutral sentence.
    let e = explain(&make("queue", "SOMETHING"));
    assert_eq!(
        (e.sentence.as_str(), e.source),
        (GENERIC_CHECK, Source::Generic)
    );
}

/// Oracle: the KEV line claims only what the scan read. Known bad:
/// "It is not on the public list" for a scan that never read the list,
/// and any KEV line on Pantry's own markers.
#[test]
fn attacks_say_whether_kev_lists_it() {
    let mut f = advisory(&[], "");
    assert_eq!(attacks(&f, true), Some(NOT_LISTED));
    assert_eq!(attacks(&f, false), Some(KEV_UNKNOWN));
    f.kev = true;
    assert_eq!(attacks(&f, true), Some(EXPLOITED));
    assert_eq!(attacks(&f, false), Some(EXPLOITED));
    for id in ["EOL", "OUTDATED", "MISSING", "UNPINNED", "BREACH"] {
        let marker = own("tool", id);
        assert_eq!(attacks(&marker, true), None, "{id}");
        assert_eq!(attacks(&marker, false), None, "{id}");
    }
    let mut unchecked = own("unchecked", "");
    unchecked.cwe = vec!["CWE-787".into()];
    assert_eq!(attacks(&unchecked, true), None);
    assert_eq!(attacks(&malicious("MAL-2026-1", &[]), true), None);
}

pub(super) fn own(kind: &str, id: &str) -> Finding {
    serde_json::from_value(serde_json::json!({
        "kind": kind, "component": "x", "version": "", "location": "",
        "vuln_id": id, "status": "warn", "note": "", "fixed": "",
        "severity": "", "kev": false, "fix_cmd": "",
    }))
    .unwrap()
}

/// A malicious-package finding as the scanner emits it: `CRITICAL`
/// (its severity step turns MALICIOUS into CRITICAL), `kev` true.
fn malicious(id: &str, aliases: &[&str]) -> Finding {
    serde_json::from_value(serde_json::json!({
        "kind": "project", "component": "evil-pkg", "version": "1.0", "location": "",
        "vuln_id": id, "status": "fail", "note": "Malicious code in evil-pkg (npm)",
        "fixed": "", "severity": "CRITICAL", "kev": true, "fix_cmd": "npm uninstall evil-pkg",
        "summary": "Malicious code in evil-pkg (npm)", "aliases": aliases,
    }))
    .unwrap()
}

/// Oracle: CWE precedence picks the most serious, most specific
/// weakness, whatever order the advisory lists them in.
#[test]
fn the_most_serious_known_weakness_wins() {
    let out_of_bounds = "A specially made file or message could corrupt this program's memory, which can crash it or let someone run their own programs on this computer.";
    for list in [
        &["CWE-20", "CWE-787"][..],
        &["CWE-787", "CWE-20"],
        &["CWE-119", "CWE-787"],
        &["CWE-200", "CWE-99999", "CWE-787"],
    ] {
        let e = explain(&advisory(list, ""));
        assert_eq!(e.sentence, out_of_bounds, "{list:?}");
    }
    // Code injection outranks a crash; SQL injection outranks input
    // validation.
    assert_eq!(
        explain(&advisory(&["CWE-476", "CWE-94"], "")).sentence,
        "Someone could slip their own code into this program and have it run."
    );
    assert_eq!(
        explain(&advisory(&["CWE-20", "CWE-89"], "")).sentence,
        "Someone could send text that tricks this program's database into showing, changing or deleting data."
    );
    assert_eq!(main_cwe(&["CWE-284".into(), "CWE-862".into()]), Some(862));
    assert_eq!(main_cwe(&["CWE-1".into()]), None);
}

/// Oracle: a flaw that only crashes or freezes a program never says
/// anyone can run anything (literal expectations, not the table).
#[test]
fn crash_only_weaknesses_never_say_run() {
    let expected = [
        (
            476,
            "A specially made file or message could make this program crash.",
        ),
        (
            674,
            "A specially made file or message could make this program crash.",
        ),
        (
            835,
            "A specially made file or message could make this program freeze.",
        ),
        (
            1333,
            "A specially crafted piece of text could make this program work so hard it freezes.",
        ),
        (
            400,
            "Someone could overload this program so it slows down or stops working.",
        ),
        (
            770,
            "Someone could make this program use up memory or other resources until it slows down or stops working.",
        ),
    ];
    for (n, sentence) in expected {
        let e = explain(&advisory(&[&format!("CWE-{n}")], ""));
        assert_eq!(e.sentence, sentence, "CWE-{n}");
        assert!(!e.sentence.contains("run"), "CWE-{n}: {}", e.sentence);
    }
    assert_eq!(keyword_sentence("Stack overflow in parser"), Some(CRASHES));
    assert_eq!(
        keyword_sentence("Denial of service via stack overflow"),
        Some(CRASHES),
        "denial of service is a crash, not memory corruption"
    );
}

/// Oracle: one case per keyword phrase, each giving its group's
/// sentence; and the known-bad cases (negations, other words, a phrase
/// inside or at the start of a longer word) giving nothing.
/// Oracle: a malicious-package report's own MAL id is listed and links
/// to osv.dev, as a MAL alias does. Known-bad: the primary MAL id was
/// dropped, leaving no id at all.
#[test]
fn a_primary_mal_id_is_listed() {
    let f: Finding = serde_json::from_value(serde_json::json!({
        "kind": "malware", "component": "evil-pkg", "version": "1.0", "location": "",
        "vuln_id": "MAL-2026-1234", "status": "fail", "note": "", "fixed": "",
        "severity": "CRITICAL", "kev": false, "fix_cmd": "",
    }))
    .unwrap();
    assert_eq!(
        identifiers(&f),
        vec![Identifier {
            id: "MAL-2026-1234".into(),
            url: Some("https://osv.dev/vulnerability/MAL-2026-1234".into()),
        }]
    );
}

/// Oracle: known harmful packages, as the scanner builds them (a MAL-
/// id, or a GHSA with a MAL- alias, severity CRITICAL, kev true), get
/// the malware sentence and are never advisories.
#[test]
fn malicious_packages_get_the_malware_sentence() {
    for f in [
        malicious("MAL-2026-1", &[]),
        malicious("GHSA-aaaa-bbbb-cccc", &["MAL-2026-2"]),
        {
            let mut f = own("extension", "MALICIOUS");
            f.severity = "CRITICAL".into();
            f
        },
    ] {
        assert!(is_malicious(&f), "{}", f.vuln_id);
        assert!(!is_advisory(&f), "{}", f.vuln_id);
        let e = explain(&f);
        assert_eq!((e.sentence.as_str(), e.source), (MALICIOUS, Source::Kind));
        let lead = own_lead(&f, "evil-pkg").unwrap();
        assert!(
            lead.contains("known harmful") && lead.ends_with("Remove it."),
            "{lead}"
        );
        assert!(!lead.contains("worth a look"));
    }
    // A plain GHSA is not malicious.
    assert!(!is_malicious(&advisory(&[], "")));
}

/// Oracle: the two kinds of unchecked area read differently, and
/// neither claims a problem.
#[test]
fn excluded_and_unfinished_unchecked_areas_differ() {
    let mut skipped = own("unchecked", "");
    skipped.excluded = true;
    let unfinished = own("unchecked", "");
    assert_eq!(
        explain(&skipped).sentence,
        "You chose to skip this area, so Pantry did not look here."
    );
    assert_eq!(
        explain(&unfinished).sentence,
        "Pantry could not finish this check, so it does not know whether there is a problem here."
    );
}

/// Oracle: Pantry's own markers lead with what Pantry found, never the
/// advisory words "security hole" or "no fix released".
#[test]
fn own_markers_lead_with_their_own_sentence() {
    for (kind, id, expected) in [
        ("mcp", "UNPINNED", "x is not fixed to one version."),
        (
            "runtime",
            "EOL",
            "x no longer gets security fixes from its maker.",
        ),
        (
            "tool",
            "MISSING",
            "x is not installed, so one of Pantry's checks could not run.",
        ),
        ("account", "BREACH", "x appears in a known data breach."),
        (
            "clipper",
            "CLIPPER-EXTENSION",
            "x may be swapping copied wallet addresses.",
        ),
        ("tool", "OUTDATED", "x is out of date."),
        (
            "repo-hook",
            "INSTALL-HOOK",
            "x runs its own commands when it is installed.",
        ),
    ] {
        let f = own(kind, id);
        assert_eq!(own_lead(&f, "x").as_deref(), Some(expected), "{kind} {id}");
        assert!(!is_advisory(&f));
    }
    assert_eq!(
        kind_sentence(&own("repo-hook", "INSTALL-HOOK")),
        Some(INSTALL_SCRIPT)
    );
    assert_eq!(kind_sentence(&own("tool", "MISSING")), Some(MISSING_TOOL));
}
