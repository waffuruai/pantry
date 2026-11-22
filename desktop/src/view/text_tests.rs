use super::{
    display_name, display_path, fix_sentence, matches_search, one_line, plain_sentence,
    quoted_summary,
};
use crate::data::Finding;

fn finding(fields: serde_json::Value) -> Finding {
    let mut base = serde_json::json!({
        "kind": "project", "component": "demo", "version": "1.0", "location": "",
        "vuln_id": "", "status": "warn", "note": "", "fixed": "",
        "severity": "", "kev": false, "fix_cmd": "",
    });
    for (key, value) in fields.as_object().unwrap() {
        base[key] = value.clone();
    }
    serde_json::from_value(base).unwrap()
}

/// Oracle: "security hole" and "no fix released" belong to published
/// advisories. Pantry's own checks lead with what the check found, and
/// a known-harmful package says to remove it, never "worth a look".
#[test]
fn own_checks_never_read_as_security_holes() {
    let cases = [
        (
            serde_json::json!({"kind": "tool", "component": "node", "vuln_id": "EOL", "fix_auto": true, "fix_cmd": "brew upgrade node", "note": "node 16 reached end of life"}),
            "node no longer gets security fixes from its maker.",
        ),
        (
            serde_json::json!({"kind": "tool", "component": "brew vulns", "vuln_id": "MISSING", "note": "Homebrew formulae can't be checked", "fix_cmd": "brew update"}),
            "brew vulns is not installed, so one of Pantry's checks could not run.",
        ),
        (
            serde_json::json!({"kind": "repo-hook", "component": "site", "vuln_id": "INSTALL-HOOK", "note": "postinstall runs node x.js"}),
            "site runs its own commands when it is installed.",
        ),
        (
            serde_json::json!({"vuln_id": "MAL-2026-1", "severity": "CRITICAL", "kev": true, "component": "evil-pkg", "fix_cmd": "npm uninstall evil-pkg"}),
            "evil-pkg is a known harmful package. Remove it.",
        ),
        (
            serde_json::json!({"vuln_id": "GHSA-aaaa-bbbb-cccc", "aliases": ["MAL-2026-2"], "severity": "CRITICAL", "kev": true, "component": "evil-pkg"}),
            "evil-pkg is a known harmful package. Remove it.",
        ),
        (
            serde_json::json!({"kind": "extension", "vuln_id": "MALICIOUS", "severity": "CRITICAL", "kev": true, "component": "bad-ext"}),
            "bad-ext is a known harmful",
        ),
        (
            serde_json::json!({"kind": "tool", "component": "git", "vuln_id": "SIGNING-OFF", "note": "git is set up to skip signature checks. Turn it on."}),
            "git is set up to skip signature checks.",
        ),
    ];
    for (fields, expected) in cases {
        let f = finding(fields);
        let sentence = plain_sentence(&f);
        assert!(sentence.contains(expected), "{sentence}");
        for word in [
            "security hole",
            "security flaw",
            "no fix yet",
            "worth a look",
        ] {
            assert!(!sentence.contains(word), "{sentence}");
        }
    }
    // A published advisory still says it.
    let advisory = finding(serde_json::json!({"vuln_id": "CVE-2026-1", "severity": "HIGH"}));
    assert!(plain_sentence(&advisory).contains("security"));
}

/// Oracle: the specific confirm sentence only for a command with
/// exactly the known shape for its tool. Known-bad: extra words after
/// the package (the scanner runs them as more packages or arguments),
/// padding, the fixed version only inside another word, a different
/// package, and a look-alike component name.
#[test]
fn confirm_sentence_promises_only_what_the_command_does() {
    let f = finding(serde_json::json!({
        "id": "F-1", "component": "pkg0", "version": "1.0", "fixed": "2.0",
    }));
    let specific = "Pantry will update pkg0 from version 1.0 to 2.0. To do this it will install the fixed version with npm.";
    assert_eq!(fix_sentence(&f, "npm install pkg0@2.0"), specific);
    assert_eq!(
        fix_sentence(&f, "cargo update -p pkg0 --precise 2.0"),
        "Pantry will update pkg0 from version 1.0 to 2.0. To do this it will update the project's Cargo lockfile."
    );
    assert_eq!(
        fix_sentence(&f, "brew upgrade --cask pkg0"),
        "Pantry will update pkg0. To do this it will update it with Homebrew."
    );
    assert!(fix_sentence(&f, "mise upgrade brew:pkg0").ends_with("update it with mise."));
    assert!(fix_sentence(&f, "wpantry fix secret F-1").ends_with("saved secret."));
    let generic = "Pantry will run one command.";
    for command in [
        "npm install pkg0@2.0; touch marker",
        "npm install pkg0@2.0 ; touch marker",
        &format!("npm install pkg0@2.0{}; touch marker", " ".repeat(300)),
        "npm install pkg0@2.0 other-package",
        "npm install pkg0@2.0 --registry=http://example.invalid",
        "npm install pkg0@12.0",
        "npm install other@2.0",
        "npm install pkg0@2.0 # 2.0",
        "brew upgrade pkg0 other",
        "wpantry fix secret F-2",
        "touch marker",
    ] {
        assert_eq!(fix_sentence(&f, command), generic, "{command:?}");
    }
    let look_alike = finding(serde_json::json!({
        "component": "\u{0440}kg0", "version": "1.0", "fixed": "2.0",
    }));
    assert_eq!(
        fix_sentence(&look_alike, "npm install \u{0440}kg0@2.0"),
        generic
    );
}

/// Oracle: an advisory row reads the same whether or not the notice
/// says what the flaw does, so earlier-scan rows (often without a
/// weakness type) match the rows above them. Known-bad: the old
/// "known security hole" wording.
#[test]
fn advisory_rows_share_one_lead() {
    for (fixed, kev, lead) in [
        ("", false, "left-pad has a security flaw with no fix yet."),
        (
            "2.0",
            false,
            "left-pad is out of date and has a security flaw.",
        ),
        (
            "",
            true,
            "left-pad has a security flaw that attackers are using, with no fix yet.",
        ),
    ] {
        let bare = finding(serde_json::json!({
            "component": "left-pad", "vuln_id": "CVE-2026-1", "fixed": fixed, "kev": kev,
        }));
        let explained = finding(serde_json::json!({
            "component": "left-pad", "vuln_id": "CVE-2026-1", "fixed": fixed, "kev": kev,
            "cwe": ["CWE-787"],
        }));
        assert_eq!(plain_sentence(&bare), lead);
        let full = plain_sentence(&explained);
        assert!(full.starts_with(lead), "{full}");
        assert!(full.contains("run their own programs"), "{full}");
        for sentence in [plain_sentence(&bare), full] {
            assert!(!sentence.contains("security hole"), "{sentence}");
        }
    }
}

/// Oracle: search finds a row by any text people can see or copy from
/// it: aliases, weakness ids, the explanation and the summary.
#[test]
fn search_matches_aliases_weaknesses_and_shown_text() {
    let f = finding(serde_json::json!({
        "vuln_id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-4242"],
        "cwe": ["CWE-89"], "summary": "Quoting flaw in the query builder", "severity": "HIGH",
    }));
    for search in ["cve-2026-4242", "cwe-89", "query builder", "database"] {
        assert!(matches_search(&f, search), "{search}");
    }
    assert!(!matches_search(&f, "nothing like this"));
}

/// Known-bad: hidden characters, line breaks and runs of spaces in
/// scanner text, a 1000-character summary with quote marks, and a
/// long multi-line name. Shown text is one clean line, cut at a word.
#[test]
fn shown_text_is_one_clean_short_line() {
    assert_eq!(one_line("a\u{202E}b \n\n  c\td", 100), "ab c d");
    let long = "word ".repeat(200);
    let quoted = quoted_summary(&format!("He said \u{201c}hi\u{201d} and \"bye\" {long}"));
    assert!(quoted.chars().count() <= 300, "{}", quoted.chars().count());
    assert!(quoted.ends_with('…'), "{quoted}");
    assert!(
        quoted.starts_with("He said 'hi' and 'bye' word"),
        "{quoted}"
    );
    assert!(!quoted.contains(['"', '\u{201c}', '\u{201d}']));
    assert!(
        !quoted.trim_end_matches('…').ends_with("wor"),
        "cut at a word"
    );
    let name = display_name(&finding(
        serde_json::json!({"component": format!("first line\nsecond {}", "x".repeat(200))}),
    ));
    assert!(name.chars().count() <= 40, "{name}");
    assert!(!name.contains('\n'));
    let sentence = plain_sentence(&finding(
        serde_json::json!({"component": "x\n".repeat(80), "vuln_id": "CVE-2026-1", "fixed": "2"}),
    ));
    assert!(sentence.contains("is out of date"), "{sentence}");
}

#[test]
fn paths_show_home_as_a_tilde_and_elide_the_middle() {
    let home = Some("/Users/sam");
    assert_eq!(
        display_path("/Users/sam/Projects/site", home, 56),
        "~/Projects/site"
    );
    // A sibling folder that only starts with the home path is not home.
    assert_eq!(
        display_path("/Users/samantha/site", home, 56),
        "/Users/samantha/site"
    );
    let long = "/var/folders/y2/mjncn_qn211bjbdr94zpzps40000gn/T/pantry-tests-4f5b/recipe-site";
    let shown = display_path(long, home, 40);
    assert_eq!(shown.chars().count(), 40);
    assert!(shown.starts_with("/var/folders/") && shown.ends_with("/recipe-site"));
    assert!(shown.contains('…'));
    // Known bad: an elided path is never returned unchanged.
    assert_ne!(shown, long);
    assert_eq!(display_path("short", None, 40), "short");
}
