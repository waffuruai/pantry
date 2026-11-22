use super::*;
use crate::data::Update;
use crate::pantry::output::json;
use crate::pantry::tests::output;
use crate::pantry::{CANCELLED, NEWER_FORMAT, START_FAILED, TIMED_OUT};

#[test]
fn friendly_errors_map_known_failures() {
    let missing = Problem::from_scanner(&format!(
        "{START_FAILED} /x/wpantry. No such file or directory (os error 2)"
    ));
    assert_eq!(missing.kind, ProblemKind::ScannerMissing);
    assert!(!missing.summary.contains("os error"));
    assert!(missing.details.contains("os error 2"));
    let cases = [
        (CANCELLED.to_owned(), ProblemKind::Cancelled),
        (format!("{TIMED_OUT} 30 minutes."), ProblemKind::TimedOut),
        (
            "sudo: a terminal is required to read the password".into(),
            ProblemKind::NeedsPassword,
        ),
        (
            "A newer scan is available. Refresh and preview the fix again.".into(),
            ProblemKind::StaleFix,
        ),
        (
            "open /Users/x/Documents: Permission denied (os error 13)".into(),
            ProblemKind::Permission,
        ),
        (
            "error sending request: dns error: failed to lookup address".into(),
            ProblemKind::Offline,
        ),
        (
            format!("{NEWER_FORMAT} report format (2)."),
            ProblemKind::VersionMismatch,
        ),
        (
            "error: unexpected argument '--no-personal-files' found".into(),
            ProblemKind::VersionMismatch,
        ),
    ];
    for (raw, kind) in cases {
        let problem = Problem::from_scanner(&raw);
        assert_eq!(problem.kind, kind, "{raw}");
        assert_eq!(problem.details, raw.trim(), "raw text stays under details");
        assert_ne!(problem.summary, raw);
    }
}

/// Oracle: the words fit the task. A fix stopped part way says it may
/// have partly run; only a scan is told to scan fewer folders; an
/// update check never talks about security notices or saved data.
#[test]
fn problems_are_worded_for_their_task() {
    let timeout = format!("{TIMED_OUT} 15 minutes.");
    let fix = Problem::for_fix(&timeout);
    assert_eq!(fix.kind, ProblemKind::FixStopped);
    assert!(
        fix.summary.contains("may have partly run"),
        "{}",
        fix.summary
    );
    assert!(!fix.summary.contains("fewer folders"), "{}", fix.summary);
    let cancelled = Problem::for_fix(CANCELLED);
    assert_eq!(cancelled.kind, ProblemKind::FixStopped);
    assert!(!cancelled.summary.contains("Nothing else was changed"));
    let scan = Problem::for_scan(&timeout).summary;
    assert!(scan.contains("fewer folders"), "{scan}");
    assert!(!scan.contains("smaller folder"), "{scan}");
    assert!(
        !Problem::from_scanner(&timeout)
            .summary
            .contains("fewer folders")
    );
    // Other fix failures keep their own words.
    assert_eq!(
        Problem::for_fix("sudo: a password is required").kind,
        ProblemKind::NeedsPassword
    );
    let update = Problem::for_update("error sending request: dns error: failed to lookup address");
    assert_eq!(
        update.kind,
        ProblemKind::Failed,
        "no Scan with saved data button"
    );
    assert!(
        update.summary.contains("check for updates"),
        "{}",
        update.summary
    );
    for word in ["security notice", "saved data"] {
        assert!(!update.summary.contains(word), "{}", update.summary);
    }
}

/// Known-bad: "offline" inside other text (a flag name, a file name)
/// is not a network failure.
#[test]
fn offline_is_not_matched_inside_other_words() {
    for raw in [
        "error: --offline needs a saved copy; the cache has none",
        "could not open /tmp/offline-cache.db: Permission denied",
    ] {
        assert_ne!(
            Problem::from_scanner(raw).kind,
            ProblemKind::Offline,
            "{raw}"
        );
    }
}

/// Oracle: empty or broken output is the scanner misbehaving, not a
/// version mismatch: never "Reinstall", and what it printed is kept.
#[test]
fn garbage_output_is_unexpected_not_reinstall() {
    for (stdout, said) in [
        ("", "It printed nothing."),
        ("<html>proxy error</html>", "proxy error"),
    ] {
        let error = json::<Update>(output(0, stdout, ""), &[0]).err().unwrap();
        let problem = Problem::from_scanner(&error);
        assert_eq!(problem.kind, ProblemKind::Failed, "{error}");
        assert!(!problem.needs_reinstall());
        assert!(
            problem.summary.contains("something unexpected"),
            "{}",
            problem.summary
        );
        assert!(problem.details.contains(said), "{}", problem.details);
    }
}

/// Known-bad input: text the mapping does not know must not be
/// guessed at. It gets the generic summary, raw text under details.
#[test]
fn unknown_errors_stay_raw_under_details() {
    let raw = "thread 'main' panicked at src/x.rs:1:1: index out of bounds";
    let problem = Problem::from_scanner(raw);
    assert_eq!(problem.kind, ProblemKind::Failed);
    assert_eq!(problem.details, raw);
    assert!(!problem.summary.contains("panicked"));
}
