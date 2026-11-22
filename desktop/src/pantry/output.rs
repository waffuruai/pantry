//! Reading what the scanner printed: exit codes, JSON, fix previews, and
//! scanner text made safe to show (no control or bidi override characters).

use super::{Result, UNEXPECTED, UNSUPPORTED, UNVERIFIED};
use std::process::Output;

pub(super) fn checked(out: Output, codes: &[i32]) -> Result<String> {
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if out.status.code().is_some_and(|code| codes.contains(&code)) {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let message = [stdout.as_str(), stderr.trim()]
        .into_iter()
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if message.is_empty() {
        Err(format!("Pantry exited with {}.", out.status))
    } else {
        Err(message)
    }
}

/// The command a fix dry run says it would run, checked on the raw text
/// before anything is cleaned: a command with hidden characters, a line
/// break or a tab cannot be shown as it would run, and an answer for a
/// different scan is not the fix that was asked about. Both are refused
/// with [`UNVERIFIED`].
///
/// ```ignore
/// verified_preview(output(0, r#"{"schema":1,"scan":7,"command":"brew upgrade x"}"#, ""), 7)
///     == Ok("brew upgrade x".into());
/// ```
pub(super) fn verified_preview(out: Output, scan: i64) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Preview {
        schema: i64,
        scan: i64,
        command: String,
    }
    let text = checked(out, &[0])?;
    let preview: Preview = serde_json::from_str(&text)
        .map_err(|error| format!("{UNEXPECTED} {error}\n{}", excerpt(&text)))?;
    if preview.schema != 1 || preview.scan != scan || !shown_as_runs(&preview.command) {
        return Err(UNVERIFIED.into());
    }
    Ok(preview.command)
}

/// Longest fix command Pantry will show and run.
pub const COMMAND_MAX: usize = 2000;

/// True when a fix command reads on screen exactly as it runs. An
/// allow-list: printable ASCII only (so no look-alike letters, Unicode
/// spaces, variation selectors or blank symbols), no leading or trailing
/// space, single spaces between words outside quotes (a long run of spaces
/// can push the rest of the command out of view), and at most
/// [`COMMAND_MAX`] bytes. A command with a non-ASCII path is refused too,
/// rather than shown in a form people can't check.
///
/// ```text
/// npm install left-pad@2.0              -> true
/// npm install left-pad@2.0\u{a0}x        -> false (no-break space)
/// npm install left-pad@2.0    ; x       -> false (a run of spaces)
/// touch 'a  b'                          -> true  (spaces inside quotes)
/// ```
pub fn shown_as_runs(command: &str) -> bool {
    if command.is_empty()
        || command.len() > COMMAND_MAX
        || command.trim() != command
        || !command.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return false;
    }
    let mut quote = None;
    let mut previous = 0u8;
    for b in command.bytes() {
        match (quote, b) {
            (None, b'\'' | b'"') => quote = Some(b),
            (Some(q), _) if b == q => quote = None,
            (None, b' ') if previous == b' ' => return false,
            _ => {}
        }
        previous = b;
    }
    true
}

/// The scanner's JSON, with every string made safe to show (`clean`).
/// Empty or broken output is `UNEXPECTED`, with what it said in details.
pub(super) fn json<T: serde::de::DeserializeOwned>(out: Output, codes: &[i32]) -> Result<T> {
    let text = checked(out, codes)?;
    let mut value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| format!("{UNEXPECTED} {error}\n{}", excerpt(&text)))?;
    clean_value(&mut value);
    serde_json::from_value(value).map_err(|error| format!("{UNSUPPORTED} {error}"))
}

/// The start of what the scanner printed, for Show details.
pub(super) fn excerpt(text: &str) -> String {
    let text = clean(text);
    if text.trim().is_empty() {
        return "It printed nothing.".into();
    }
    let mut short: String = text.chars().take(500).collect();
    if short.len() < text.len() {
        short.push('…');
    }
    format!("It printed: {short}")
}

/// Characters that change how text reads without being seen: controls
/// other than newline and tab, line and paragraph separators,
/// bidirectional overrides and isolates, zero-width marks, the old
/// formatting controls U+206A-206F, tag characters, blank Hangul fillers,
/// and the soft hyphen.
pub fn hidden(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

/// Scanner text made safe to show: `hidden` characters removed.
pub fn clean(text: &str) -> String {
    text.chars().filter(|c| !hidden(*c)).collect()
}

/// `clean` every string in a JSON document, keys included.
fn clean_value(value: &mut serde_json::Value) {
    use serde_json::Value;
    match value {
        Value::String(text) if text.chars().any(hidden) => *text = clean(text),
        Value::Array(items) => items.iter_mut().for_each(clean_value),
        Value::Object(map) => {
            let dirty = map.keys().any(|key| key.chars().any(hidden));
            if dirty {
                let entries: Vec<_> = std::mem::take(map).into_iter().collect();
                map.extend(entries.into_iter().map(|(key, value)| (clean(&key), value)));
            }
            map.values_mut().for_each(clean_value);
        }
        _ => {}
    }
}

#[cfg(test)]
#[path = "output_tests.rs"]
mod tests;
