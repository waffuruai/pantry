//! Erlang/OTP installs, read from their release files: `erl` is never run
//! (asking it for its version boots a VM and runs code). An OTP install
//! keeps `bin/erl` under its root, often behind a symlink from a prefix's
//! `bin/`, and names its full version in `releases/<major>/OTP_VERSION`;
//! `releases/start_erl.data` says which major is the current one.
//!
//! Checked against OSV as release tags of the OTP repo (`OTP-27.3.2`) and
//! against endoflife.date's `erlang` by major. A Homebrew or distro `erl`
//! is left to `brew vulns` and the OS update check, as for every catalog
//! tool ([`owner`]).
//!
//! OSV's tag lists for the OTP repo leave out the patches made on side
//! branches (`OTP-27.0.1`, `OTP-27.2.4`: patches of a minor release that a
//! later minor replaced) and a few others (`OTP-26.2.1`): asked about one,
//! OSV answers with few or no advisories, however vulnerable it is. Such an
//! install is reported not checked ([`unlisted`]), and such a tag is never
//! recommended as a fix ([`side_branch`]).
//!
//! TODO: CVE records give OTP's real ranges (`>= OTP-27.0-rc1, < OTP-27.3.3`
//! for CVE-2025-32433); judging side-branch installs by them would replace
//! "not checked" with a verdict.

use crate::checks::TAG_PREFIX;
use crate::checks::machine::catalog::ERLANG_DIRS;
use crate::checks::machine::tools::updater;
use crate::component::Component;
use crate::utils::files::{home, owner, read_capped};
use crate::utils::net::github;
use crate::utils::process::on_path;
use crate::utils::re::Regex;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// The OTP repo, as OSV's GIT records name it.
pub fn repo() -> String {
    github("erlang/otp")
}

/// Every `erl` on PATH, in a version manager's folder or in kerl's list of
/// installations; and, for each one whose version couldn't be read, (the
/// `erl`, why) for the scan to report unchecked.
pub fn installs() -> (Vec<Component>, Vec<(String, String)>) {
    let mut dirs: Vec<String> = ERLANG_DIRS.iter().map(|d| d.to_string()).collect();
    dirs.extend(kerl_installs(&home().join(".kerl/otp_installations")));
    from(on_path("erl", &dirs))
}

/// The `bin` folders kerl's `otp_installations` lists (`<build> <path>` per
/// line).
fn kerl_installs(list: &Path) -> Vec<String> {
    let text = read_capped(list, 1 << 20).unwrap_or_default();
    text.lines()
        .filter_map(|l| l.split_once(' ').map(|(_, p)| p.trim()))
        .filter(|p| p.starts_with('/'))
        .map(|p| format!("{}/bin", p.trim_end_matches('/')))
        .collect()
}

/// `installs` for the `erl`s found, as (shown path, real path).
fn from(found: Vec<(String, String)>) -> (Vec<Component>, Vec<(String, String)>) {
    let mut out = Vec::new();
    let mut unread = Vec::new();
    let mut seen = Vec::new();
    for (shown, real) in found {
        // A version manager's shim: the installs it points to are found in
        // their own folders. mise's shims are links to the mise binary, so
        // only the path as shown says it is one.
        if shown.contains("/shims/") || real.contains("/shims/") || !owner(&real).is_empty() {
            continue;
        }
        let Some(root) = root_of(Path::new(&real)) else {
            unread.push((shown, format!("{real} is not in an OTP install's bin folder")));
            continue;
        };
        if seen.contains(&root) {
            continue;
        }
        seen.push(root.clone());
        let v = match version(&root) {
            Ok(v) => v,
            Err(why) => {
                unread.push((shown, why));
                continue;
            }
        };
        let (fix, auto) = updater(&real, "erlang");
        let mut c = Component::new("runtime", "erlang", &v, &shown);
        c.osv = Some(("GIT".into(), repo(), format!("OTP-{v}")));
        c.eol = Some(("erlang".into(), v.split('.').next().unwrap_or("").to_string()));
        // asdf and mise name installs `27.3.3`, not the tag `OTP-27.3.3`.
        c.extra.insert(TAG_PREFIX.into(), "OTP-".into());
        c.fix = fix;
        c.auto = auto;
        out.push(c);
    }
    (out, unread)
}

/// A release tag's numbers (`OTP-26.2.5.11` -> 26, 2, 5, 11); None for a
/// release candidate or anything else.
fn release(tag: &str) -> Option<Vec<u64>> {
    tag.strip_prefix("OTP-")?
        .split('.')
        .map(|p| p.parse().ok().filter(|_| p.bytes().all(|b| b.is_ascii_digit())))
        .collect()
}

/// The first of `tags` showing that `tag` is a patch on a side branch: a
/// later release that shares the numbers before one of `tag`'s, where `tag`
/// has more after it. `OTP-27.0.1` is (`OTP-27.1`), `OTP-26.2.5.11` isn't:
/// no `OTP-26.3` or `OTP-26.2.6` came after it.
///
/// Example: `side_branch("OTP-27.2.4", &tags)` is `Some("OTP-27.3")`.
pub fn side_branch(tag: &str, tags: &[String]) -> Option<String> {
    let t = release(tag)?;
    tags.iter()
        .filter(|u| {
            release(u)
                .is_some_and(|u| (1..t.len().saturating_sub(1)).any(|i| u.len() > i && u[..i] == t[..i] && u[i] > t[i]))
        })
        .min_by_key(|u| release(u))
        .cloned()
}

/// Why OSV's answer for an install can't be taken as complete, or None
/// when it can: OTP's tags couldn't be listed, the install is a side-branch
/// patch ([`side_branch`]), or OSV answered no advisory at all for a
/// release with newer ones of its major after it (a tag OSV's lists leave
/// out; only the newest releases have none). `answer` is OSV's records for
/// the install, None when OSV wasn't asked or didn't answer.
pub fn unlisted(c: &Component, answer: Option<&Vec<Value>>, tags: &[String]) -> Option<String> {
    let tag = format!("OTP-{}", c.version);
    if tags.is_empty() {
        return Some(format!(
            "OTP's release tags couldn't be listed, so whether OSV's lists include {tag} isn't known"
        ));
    }
    if let Some(later) = side_branch(&tag, tags) {
        return Some(format!(
            "{tag} is a patch on a side branch ({later} came after the release it patches), which OSV's lists for OTP leave out"
        ));
    }
    let t = release(&tag)?;
    let newest = tags.iter().filter_map(|u| release(u).map(|r| (r, u))).filter(|(r, _)| r[0] == t[0] && *r > t).max();
    match (answer, newest) {
        (Some(a), Some((_, newest))) if a.is_empty() => Some(format!(
            "OSV lists no advisory for {tag} though {newest} came after it: OSV's lists for OTP leave some releases out"
        )),
        _ => None,
    }
}

/// The OTP root an `erl` (symlinks resolved) belongs to: `<root>/bin/erl`
/// or `<root>/erts-<v>/bin/erl`.
pub fn root_of(erl: &Path) -> Option<PathBuf> {
    let bin = erl.parent().filter(|b| b.file_name().is_some_and(|n| n == "bin"))?;
    let up = bin.parent()?;
    let erts = up.file_name().is_some_and(|n| n.to_string_lossy().starts_with("erts-"));
    let root = if erts { up.parent()? } else { up };
    Some(root.to_path_buf())
}

/// The full OTP version under `root`, or why it couldn't be read.
pub fn version(root: &Path) -> Result<String, String> {
    let releases = root.join("releases");
    let start = read_capped(&releases.join("start_erl.data"), 4096).unwrap_or_default();
    let major = match start.split_whitespace().nth(1) {
        Some(m) => m.to_string(),
        None => {
            // No start_erl.data: the one major under releases/, if only one.
            let majors: Vec<String> = std::fs::read_dir(&releases)
                .map(|rd| {
                    rd.filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .filter(|n| releases.join(n).join("OTP_VERSION").is_file())
                        .collect()
                })
                .unwrap_or_default();
            match majors.as_slice() {
                [one] => one.clone(),
                [] => return Err(format!("no releases/<major>/OTP_VERSION under {}", root.display())),
                _ => return Err(format!("several releases under {} and no start_erl.data", releases.display())),
            }
        }
    };
    if major.is_empty() || !major.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("{} names no OTP major", releases.join("start_erl.data").display()));
    }
    let file = releases.join(&major).join("OTP_VERSION");
    let text = read_capped(&file, 4096).map_err(|_| format!("{} can't be read", file.display()))?;
    let v = text.lines().next().unwrap_or("").trim();
    if Regex::new(r"\d+(?:\.\d+){0,4}").fullmatch(v).is_none() || v.split('.').next() != Some(major.as_str()) {
        return Err(format!("{} doesn't name an OTP {major} version", file.display()));
    }
    Ok(v.to_string())
}

#[cfg(test)]
#[path = "erlang_tests.rs"]
mod tests;
