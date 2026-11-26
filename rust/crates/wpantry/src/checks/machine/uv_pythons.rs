//! What the installed uv can install, so `uv python upgrade` is offered
//! unattended only when it would change something.
//!
//! uv only knows the Python builds that existed when that uv was released.
//! On a machine whose uv is older than the Python fix a scan names, `uv
//! python upgrade` does nothing and every finding it was offered for reads
//! "still there" afterwards. The scan asks uv once ([`ask`]), stamps the
//! answer on the uv-managed Pythons and the pip packages that ride on them
//! ([`stamp`]), and [`adjust`] decides where the fixed version is known
//! (`checks::fix_with`), as the end-of-life rule for pip does.

use crate::checks::ecosystems::versions;
use crate::checks::machine::catalog::Cycle;
use crate::component::Component;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

/// The command a uv-managed Python's fix is.
pub const UPGRADE: &str = "uv python upgrade";
/// `extra` keys: the newest patch uv can install on the Python's release
/// line, the uv's version, the Python's release line and installed version,
/// and (pip packages only) that the package is bundled with the Python.
pub const NEWEST: &str = "uv_newest";
pub const UV_VERSION: &str = "uv_version";
pub const LINE: &str = "uv_line";
pub const INSTALLED: &str = "uv_installed";
pub const BUNDLED: &str = "uv_bundled";

/// The newest patch of each release line (`3.12`) this uv can install, and
/// the uv's version ("" when it didn't say).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UvPythons {
    pub uv: String,
    pub newest: BTreeMap<String, String>,
}

/// Ask the uv on PATH what it can install: None when there is none, or it
/// didn't answer (two read-only calls, each bounded to 15 seconds).
pub fn ask() -> Option<UvPythons> {
    let uv = crate::utils::process::which("uv")?.display().to_string();
    ask_with(&|args| {
        let mut argv: Vec<&str> = vec![&uv];
        argv.extend_from_slice(args);
        let argv: Vec<&std::ffi::OsStr> = argv.iter().map(std::ffi::OsStr::new).collect();
        crate::utils::process::run(&argv, Duration::from_secs(15))
    })
}

/// [`ask`] with the way to run uv given: JSON first (`--output-format json`,
/// uv 0.5 and later), the plain list when that is not understood.
pub fn ask_with(uv: &dyn Fn(&[&str]) -> String) -> Option<UvPythons> {
    let json = uv(&["python", "list", "--all-versions", "--output-format", "json"]);
    let newest = match parse_json(&json) {
        Some(n) => n,
        None => parse_plain(&uv(&["python", "list", "--all-versions"])),
    };
    if newest.is_empty() {
        return None;
    }
    let said = uv(&["--version"]);
    let version = said.lines().find_map(|l| l.trim().strip_prefix("uv ")).and_then(|r| r.split_whitespace().next());
    Some(UvPythons { uv: version.unwrap_or("").to_string(), newest })
}

/// Whether a list entry is something uv can install: a download it knows of,
/// or a build it keeps itself. A Python from another manager that uv merely
/// found (Homebrew's) is not.
fn installable(download: bool, place: &str) -> bool {
    download || place.replace('\\', "/").contains("/uv/python/")
}

/// The newest patch per line among `found` (version, installable).
fn newest_of(found: impl Iterator<Item = String>) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for v in found {
        // Plain releases only: `3.15.0a1` and `3.13.1+freethreaded` are not
        // what `uv python upgrade` moves a release line to.
        let parts: Vec<&str> = v.split('.').collect();
        if parts.len() != 3 || !parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())) {
            continue;
        }
        let line = Cycle::Minor.of(&v);
        if out.get(&line).is_none_or(|have| versions::lt(have, &v)) {
            out.insert(line, v);
        }
    }
    out
}

/// `uv python list --output-format json`: an array of entries with
/// `version`, `implementation`, `variant`, `path` and `url`. None when the
/// text holds no such array.
pub fn parse_json(text: &str) -> Option<BTreeMap<String, String>> {
    let Value::Array(entries) = crate::checks::machine::packages::json_in(text, '[', ']')? else { return None };
    let text_of = |e: &Value, k: &str| e.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let found = entries.iter().filter_map(|e| {
        let cpython = e.get("implementation").and_then(Value::as_str).is_none_or(|i| i == "cpython");
        let plain = e.get("variant").and_then(Value::as_str).is_none_or(|v| v == "default");
        let place = format!("{} {}", text_of(e, "path"), text_of(e, "symlink"));
        let ok = cpython && plain && installable(!text_of(e, "url").is_empty(), &place);
        ok.then(|| text_of(e, "version"))
    });
    Some(newest_of(found))
}

/// The plain `uv python list` lines: `cpython-3.12.13-macos-aarch64-none`,
/// then a path or `<download available>`. Lines that don't have that shape
/// are skipped.
pub fn parse_plain(text: &str) -> BTreeMap<String, String> {
    let found = text.lines().filter_map(|l| {
        let (key, rest) = l.trim().split_once(char::is_whitespace)?;
        let version = key.strip_prefix("cpython-")?.split('-').next()?;
        installable(rest.contains("<download available>"), rest).then(|| version.to_string())
    });
    newest_of(found)
}

/// Record what uv answered on a uv-managed Python's runtime (`bundled`
/// false) or on a package bundled with it (`bundled` true), whose Python is
/// `installed`. A release line uv didn't list is left unknown.
pub fn stamp(c: &mut Component, known: &UvPythons, line: &str, installed: &str, bundled: bool) {
    let Some(newest) = known.newest.get(line) else { return };
    c.extra.insert(NEWEST.into(), newest.clone());
    c.extra.insert(UV_VERSION.into(), known.uv.clone());
    c.extra.insert(LINE.into(), line.into());
    c.extra.insert(INSTALLED.into(), installed.into());
    if bundled {
        c.extra.insert(BUNDLED.into(), "1".into());
    }
}

/// The fix `fix_cmd` (unattended: `auto`) of `c` for a fixed version `safe`,
/// with `uv python upgrade` kept unattended only when uv can install what
/// fixes it. Anything not stamped, any other command, and a fix on another
/// release line (which `uv python upgrade` would not install) is unchanged.
///
/// Example: python 3.12.13, fixed in 3.12.14, uv 0.10.12 knowing 3.12.13 as
/// its newest: not unattended, "update uv first, then run uv python upgrade".
pub fn adjust(c: &Component, safe: &str, fix_cmd: String, auto: bool) -> (String, bool) {
    if !auto || fix_cmd != UPGRADE {
        return (fix_cmd, auto);
    }
    let Some(newest) = c.extra.get(NEWEST) else { return (fix_cmd, auto) };
    let uv = match c.extra.get(UV_VERSION).filter(|v| !v.is_empty()) {
        Some(v) => format!("uv {v}"),
        None => "This uv".to_string(),
    };
    if c.extra.contains_key(BUNDLED) {
        let installed = c.extra.get(INSTALLED).map_or("", String::as_str);
        if versions::lt(installed, newest) {
            return (fix_cmd, auto);
        }
        let text = format!(
            "{uv} knows no Python build newer than {installed}, and this comes with the Python build, so nothing would change. Update uv first, then run {UPGRADE}: a newer Python build brings a newer pip, and the re-check confirms it"
        );
        return (text, false);
    }
    let safe = versions::bare(safe);
    let on_line = c.extra.get(LINE).is_some_and(|l| Cycle::Minor.of(safe) == *l);
    if safe.is_empty() || !on_line || versions::same_or_newer(newest, safe) {
        return (fix_cmd, auto);
    }
    let text = format!(
        "{uv} does not know a Python release that fixes this yet (the newest it can install is {newest}, the fix is {safe}). Update uv first, then run {UPGRADE}"
    );
    (text, false)
}

/// What to tell a person about a bundled package whose unattended fix stays
/// (`uv python upgrade`), or None for any other finding.
pub fn bundled_note(c: &Component, fix_cmd: &str, auto: bool) -> Option<&'static str> {
    (auto && fix_cmd == UPGRADE && c.extra.contains_key(BUNDLED) && c.extra.contains_key(NEWEST)).then_some(
        "it is bundled with this uv Python, so the newer Python build brings a newer one, and the re-check confirms it",
    )
}

#[cfg(test)]
#[path = "uv_pythons_tests.rs"]
mod tests;
