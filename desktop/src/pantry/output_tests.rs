use super::*;
use crate::data::Update;
use crate::pantry::tests::output;
use crate::pantry::{Problem, UNVERIFIED};

/// Known-bad: bidi overrides and isolates, zero-width marks, tag
/// characters, blank fillers and escape codes in any string the
/// scanner sends, object keys included, are removed before anything
/// shows them.
#[test]
fn scanner_text_loses_hidden_characters() {
    let raw = "{\"current\":\"0.6.0\",\"latest\":\"0.6\\u202e1.0\\u001b[31m\",\"available\":false,\"assets\":[\"a\\u200bb\\u2066c\\u2069\"]}";
    let update: Update = json(output(0, raw, ""), &[0]).unwrap();
    assert_eq!(update.latest, "0.61.0[31m");
    assert_eq!(update.assets.unwrap(), ["abc"]);
    let mut keyed: serde_json::Value =
        serde_json::from_str("{\"na\\u2067me\":{\"k\\u200d\":\"v\\u2028w\"}}").unwrap();
    clean_value(&mut keyed);
    assert_eq!(keyed, serde_json::json!({"name": {"k": "vw"}}));
    for c in [
        '\u{2028}',
        '\u{2029}',
        '\u{2066}',
        '\u{2069}',
        '\u{206A}',
        '\u{206F}',
        '\u{E0000}',
        '\u{E0041}',
        '\u{E007F}',
        '\u{3164}',
        '\u{115F}',
        '\u{FFA0}',
    ] {
        assert!(hidden(c), "U+{:04X}", c as u32);
        assert_eq!(clean(&format!("a{c}b")), "ab", "U+{:04X}", c as u32);
    }
    // Ordinary text, accents and other scripts are never hidden.
    assert_eq!(clean("café 한국 ✓ — x"), "café 한국 ✓ — x");
    assert_eq!(
        clean("tab\tand\nnewline stay\u{7}"),
        "tab\tand\nnewline stay"
    );
    let problem = Problem::from_scanner("bad \u{202E}txt.exe");
    assert_eq!(problem.details, "bad txt.exe");
}

/// Known-bad: the dry-run command is checked as the scanner sent it,
/// before cleaning. A right-to-left override, a tag character, a line
/// break or a tab in it, or an answer for another scan, is refused
/// with the plain "could not verify" sentence, which is also what the
/// person sees.
#[test]
fn fix_previews_are_checked_before_cleaning() {
    let preview = |command: &str, scan: i64| {
        let body = serde_json::json!({"schema": 1, "scan": scan, "command": command});
        verified_preview(output(0, &body.to_string(), ""), 7)
    };
    assert_eq!(preview("brew upgrade jq", 7).unwrap(), "brew upgrade jq");
    for command in [
        "npm install left-pad@1.3.0 \u{202E}gpj.exe",
        "brew upgrade jq\u{E0072}\u{E006D}",
        "brew upgrade jq\nrm marker",
        "brew upgrade jq\r",
        "brew\tupgrade jq",
        "brew upgrade\u{2028}jq",
        "brew upgrade \u{3164}jq",
        "   ",
    ] {
        assert_eq!(preview(command, 7).unwrap_err(), UNVERIFIED, "{command:?}");
    }
    assert_eq!(preview("brew upgrade jq", 8).unwrap_err(), UNVERIFIED);
    let wrong_schema = verified_preview(
        output(
            0,
            r#"{"schema":2,"scan":7,"command":"brew upgrade jq"}"#,
            "",
        ),
        7,
    );
    assert_eq!(wrong_schema.unwrap_err(), UNVERIFIED);
    let problem = Problem::from_scanner(UNVERIFIED);
    assert_eq!(problem.summary, UNVERIFIED);
    assert_eq!(problem.details, "", "no second copy under Show details");
    assert!(!problem.needs_reinstall());
}

/// Oracle: a command is accepted only when every byte is printable
/// ASCII with single spaces outside quotes. Known-bad: each character
/// a deny-list missed (Unicode spaces, blank symbols, variation
/// selectors, look-alike letters, fullwidth and ligature forms,
/// combining marks), a padded command, a 20000-byte command and a
/// non-ASCII path.
#[test]
fn only_plain_ascii_commands_count_as_shown() {
    for good in [
        "npm install pkg0@2.0",
        "cargo update -p rustls --precise 0.23.18",
        "touch 'a  b'",
        "sudo apt-get update && sudo apt-get install --only-upgrade curl",
    ] {
        assert!(shown_as_runs(good), "{good:?}");
    }
    let base = "npm install pkg0@2.0";
    let long = format!("npm install {} ; touch marker", "a".repeat(20000));
    let padded = format!("{base}{}; touch marker", " ".repeat(300));
    let mut bad: Vec<String> = [
        "\u{00A0}",
        "\u{2000}",
        "\u{200A}",
        "\u{202F}",
        "\u{205F}",
        "\u{3000}",
        "\u{1680}",
        "\u{2800}",
        "\u{034F}",
        "\u{FE0F}",
        "\u{E0100}",
        "\u{2065}",
        "\u{180B}",
        "\u{FFF9}",
        "\u{FFFC}",
        "\u{1D173}",
        "\u{17B5}",
        "\u{0301}",
        "\u{FFFD}",
        "\u{E000}",
        "\u{0378}",
        "\u{FF1B}",
    ]
    .iter()
    .map(|c| format!("{base}{c}x"))
    .collect();
    bad.extend([
        "npm install \u{0440}kg0@2.0".into(),
        "npm install \u{FF50}\u{FF4B}\u{FF47}\u{FF10}@2.0".into(),
        "npm install con\u{FB01}g@2.0".into(),
        "touch /Users/s\u{00E9}b/marker".into(),
        format!(" {base}"),
        format!("{base} "),
        format!("{base}  ; touch marker"),
        padded,
        long,
        String::new(),
    ]);
    for command in &bad {
        assert!(!shown_as_runs(command), "{command:?}");
        let body = serde_json::json!({"schema": 1, "scan": 7, "command": command});
        assert_eq!(
            verified_preview(output(0, &body.to_string(), ""), 7).unwrap_err(),
            UNVERIFIED,
            "{command:?}"
        );
    }
    assert!(shown_as_runs(&"a".repeat(COMMAND_MAX)));
    assert!(!shown_as_runs(&"a".repeat(COMMAND_MAX + 1)));
}

/// Oracle: garbage with an escape code in it is reported as unexpected
/// output, and the details shown for it carry no escape code.
#[test]
fn garbage_output_has_clean_details() {
    let error = verified_preview(output(0, "\u{1b}[31mnot json\u{202E}", ""), 7).unwrap_err();
    let problem = Problem::from_scanner(&error);
    assert!(problem.summary.contains("something unexpected"));
    assert!(
        problem.details.contains("[31mnot json"),
        "{}",
        problem.details
    );
    assert!(
        !problem.details.chars().any(hidden),
        "{:?}",
        problem.details
    );
}
