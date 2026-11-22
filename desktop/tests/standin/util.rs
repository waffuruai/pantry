//! Shared pieces of the stand-in scanner: its JSON state file, timestamps in
//! the scanner's format, and pid files written whole.

use serde_json::{Value, json};
use std::path::Path;

/// The state file's JSON, or `default` when it does not exist yet.
pub fn load(path: &str, default: Value) -> Value {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).expect("stand-in state is JSON"),
        Err(_) => default,
    }
}

pub fn save(path: &str, state: &Value) {
    std::fs::write(path, state.to_string()).expect("write stand-in state");
}

/// Append this call's arguments to `state["log"]`.
pub fn log_call(state: &mut Value, args: &[String]) {
    state["log"]
        .as_array_mut()
        .expect("log is a list")
        .push(json!(args));
}

/// Write this process's pid through a temporary file, so a reader never
/// sees an empty pid file.
pub fn write_pid(path: &Path) {
    let partial = path.with_extension("partial");
    std::fs::write(&partial, std::process::id().to_string()).expect("write pid");
    std::fs::rename(&partial, path).expect("publish pid");
}

/// What `wpantry schedule --json` says with nothing installed.
pub fn unscheduled() -> Value {
    json!({"schema": 1, "installed": false, "backend": "launchd", "enabled": null,
           "interval": null, "every": null, "at": null, "last_run": null})
}

/// Now, as the scanner writes it: `2026-05-05 20:11 UTC`.
pub fn stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs();
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let (year, month, day) = civil(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days`).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Python-style truthiness for a knob: absent, null, false, 0, "" and
/// empty lists or objects are off.
pub fn on(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Whether the list knob `value` names `id`.
pub fn lists(value: &Value, id: &str) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item == id))
}

/// The argument after `flag`.
pub fn after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let at = args.iter().position(|arg| arg == flag)?;
    args.get(at + 1).map(String::as_str)
}

pub fn has(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}
