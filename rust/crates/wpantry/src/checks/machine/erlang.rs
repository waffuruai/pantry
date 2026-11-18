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

use crate::checks::machine::catalog::ERLANG_DIRS;
use crate::checks::machine::tools::updater;
use crate::component::Component;
use crate::utils::files::{home, owner, read_capped};
use crate::utils::net::github;
use crate::utils::process::on_path;
use crate::utils::re::Regex;
use std::path::{Path, PathBuf};

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
        // their own folders.
        if real.contains("/shims/") || !owner(&real).is_empty() {
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
        c.osv = Some(("GIT".into(), github("erlang/otp"), format!("OTP-{v}")));
        c.eol = Some(("erlang".into(), v.split('.').next().unwrap_or("").to_string()));
        c.fix = fix;
        c.auto = auto;
        out.push(c);
    }
    (out, unread)
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
