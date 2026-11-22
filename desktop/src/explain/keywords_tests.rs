use super::*;
use crate::explain::weaknesses::weakness;

#[test]
fn every_keyword_phrase_maps_and_negations_do_not() {
    for group in KEYWORDS {
        let expected = match group.meaning {
            Keyword::Cwe(n) => weakness(n).unwrap().2,
            Keyword::Text(s) => s,
        };
        for phrase in group.words {
            let summary = match group.near.first() {
                Some(near) => format!("A {near} {phrase} in the parser"),
                None => format!("A {phrase} in the parser"),
            };
            // An earlier, more serious group may claim a phrase that
            // contains its words; the first group that matches wins.
            let first = KEYWORDS
                .iter()
                .position(|g| {
                    g.words
                        .iter()
                        .any(|w| mentions(&clause_words(&summary), w, g.near))
                })
                .unwrap();
            let got = keyword_sentence(&summary);
            assert!(got.is_some(), "{summary}");
            if std::ptr::eq(&KEYWORDS[first], group) {
                assert_eq!(got, Some(expected), "{summary}");
            }
        }
    }
    for summary in [
        "Remote code execution is not possible",
        "This does not crash the server",
        "No code execution, only a warning",
        "Sandboxed code execution in the plugin host",
        "Cache bypass for static files",
        "Proxy bypass list ignored",
        "the axssy module",
        "crashpad reporter update",
        "bypassable typo fixed",
        "Spoofed? No. Spoofingly named variable",
        "Not a denial of service",
        "This flaw cannot be used to execute arbitrary code",
        "This flaw can't be used to execute arbitrary code",
        "Code execution is not exploitable in default setups",
        "Remote code execution no longer applies after 2.0",
        "Remote code execution is unlikely",
        "Attackers are unable to inject SQL",
    ] {
        assert_eq!(keyword_sentence(summary), None, "{summary}");
    }
    // Taken back later in the clause, or only a lesser outcome is left.
    let runs = weakness(94).map(|w| w.2);
    for summary in [
        "Remote code execution was ruled out; a memory leak slows the server",
        "Incomplete fix for a remote code execution flaw now only permits denial of service",
        "An RCE-class remote code execution bug only allows a crash",
    ] {
        let got = keyword_sentence(summary);
        assert!(got != Some(RUNS_CODE) && got != runs, "{summary}: {got:?}");
    }
    assert_eq!(
        keyword_sentence(
            "Incomplete fix for a remote code execution flaw now only permits denial of service"
        ),
        Some(CRASHES)
    );
    // Two negations cancel: it can still happen.
    for summary in [
        "Fails to prevent code execution when loading a crafted file",
        "Does not properly prevent remote code execution",
    ] {
        assert_eq!(keyword_sentence(summary), Some(RUNS_CODE), "{summary}");
    }
    // A negation of something else nearby does not deny it.
    assert_eq!(
        keyword_sentence("No authentication is required to execute arbitrary code"),
        Some(RUNS_CODE)
    );
    // SQL and browser scripts are not programs run on this computer.
    assert_eq!(
        keyword_sentence("Allows attackers to execute arbitrary SQL commands"),
        weakness(89).map(|w| w.2)
    );
    assert_eq!(
        keyword_sentence("Lets a page execute arbitrary JavaScript in the browser"),
        weakness(79).map(|w| w.2)
    );
    assert_eq!(
        keyword_sentence("Allows execution of arbitrary queries"),
        weakness(89).map(|w| w.2)
    );
    // A bypass with a security word close by is one.
    assert!(
        keyword_sentence("Allows a bypass of the sandbox")
            .is_some_and(|s| s.contains("get around"))
    );
    // A negation in another clause does not cancel this one.
    assert_eq!(
        keyword_sentence("Not reachable by default; remote code execution when enabled"),
        Some(RUNS_CODE)
    );
}
