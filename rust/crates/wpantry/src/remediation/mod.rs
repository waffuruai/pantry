//! Fixing what a scan found: the update plan (what `wpantry fix` runs
//! unattended, what needs a person, what is optional) as numbered steps,
//! and running the unattended ones, each bounded by a timeout and never
//! through a shell. The stopgaps for a fix that isn't out yet are in
//! [`mitigate`]; the `wpantry harden` fixes are [`ca_trust`] and [`editors`].

pub mod ca_trust;
pub mod editors;
pub mod mitigate;

use crate::checks::ecosystems::versions;
use crate::finding::Finding;

pub const MISE_FIX: &str = "mise: manual, update it the way it was installed (https://mise.jdx.dev/installing-mise.html); wpantry never updates it";

/// Of one component's findings, the one whose fix covers them all: the
/// highest fixed version (each advisory's own fix is the lowest clearing it).
pub fn covering<'a>(fs: &[&'a Finding]) -> &'a Finding {
    let mut best: Option<&Finding> = None;
    for f in fs.iter().filter(|f| !f.fixed.is_empty()) {
        if best.is_none_or(|b| versions::lt(&b.fixed, &f.fixed)) {
            best = Some(f);
        }
    }
    best.unwrap_or(fs[0])
}

/// One step of the update plan: a command (or an instruction), whether
/// `wpantry fix` runs it unattended, whether it clears a failing finding, and
/// the findings (indices into the slice `steps` was given) it covers.
#[derive(Clone, Debug, PartialEq)]
pub struct Step {
    pub cmd: String,
    pub unattended: bool,
    pub fails: bool,
    pub findings: Vec<usize>,
}

impl Step {
    /// `auto` (runs unattended), `manual` (needs you, clears a failure) or
    /// `optional` (needs you, a warning).
    pub fn mode(&self) -> &'static str {
        if self.unattended {
            "auto"
        } else if self.fails {
            "manual"
        } else {
            "optional"
        }
    }
}

/// The update plan: one fix per component, the one covering all its
/// advisories, failures before warnings; a command two components share
/// is one step covering both.
pub fn steps(findings: &[Finding]) -> Vec<Step> {
    type Component<'a> = (&'a str, &'a str, &'a str, &'a str);
    let mut groups: Vec<(Component, Vec<usize>)> = Vec::new();
    for (i, f) in findings.iter().enumerate() {
        // Every hit in one file is one decision (rotate, or allow the file),
        // not one step per line.
        let location = if f.kind == "secret" { "" } else { f.location.as_str() };
        let k = (f.kind.as_str(), f.component.as_str(), f.version.as_str(), location);
        match groups.iter_mut().find(|(key, _)| *key == k) {
            Some((_, v)) => v.push(i),
            None => groups.push((k, vec![i])),
        }
    }
    groups.sort_by_key(|(_, is)| is.iter().all(|i| findings[*i].status != "fail"));
    let mut out: Vec<Step> = Vec::new();
    for (_, is) in &groups {
        let fs: Vec<&Finding> = is.iter().map(|i| &findings[*i]).collect();
        let f = covering(&fs);
        let (cmd, unattended) = if upgrades_mise(&f.fix_cmd) {
            (MISE_FIX.to_string(), false)
        } else if f.kind == "secret" && fs.len() > 1 {
            (secrets_fix(&fs), false)
        } else {
            (f.fix_cmd.clone(), f.fix_auto)
        };
        if cmd.is_empty() {
            continue;
        }
        let fails = fs.iter().any(|x| x.status == "fail");
        match out.iter_mut().find(|s| s.cmd == cmd) {
            // The first component to name a command decides how it runs.
            Some(s) => s.findings.extend(is.iter().copied()),
            None => out.push(Step { cmd, unattended, fails, findings: is.clone() }),
        }
    }
    out
}

/// (unattended, needs you, also worth doing): the plan's commands by mode.
pub fn plan(findings: &[Finding]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let (mut auto, mut manual, mut optional) = (Vec::new(), Vec::new(), Vec::new());
    for s in steps(findings) {
        match s.mode() {
            "auto" => auto.push(s.cmd),
            "manual" => manual.push(s.cmd),
            _ => optional.push(s.cmd),
        }
    }
    (auto, manual, optional)
}

/// One step for every hit in a file: `component` is `repo/file`, and each
/// finding's own fix names its fingerprint.
fn secrets_fix(fs: &[&Finding]) -> String {
    let file = fs[0].component.as_str();
    let generic = fs.iter().all(|f| f.status != "fail");
    let ignore = fs[0]
        .fix_cmd
        .rsplit_once(" to ")
        .map(|(_, path)| path.to_string())
        .unwrap_or_else(|| "its repo's .gitleaksignore".to_string());
    let fps: Vec<&str> = fs
        .iter()
        .filter_map(|f| f.fix_cmd.strip_prefix("If it's real: rotate it, then purge it from history. If not: add "))
        .filter_map(|rest| rest.split_once(" to ").map(|(fp, _)| fp))
        .collect();
    let listed = if fps.len() <= 3 {
        fps.join(", ")
    } else {
        format!("the {} fingerprints (each hit's `fix_cmd` in `wpantry scan --json` names one)", fps.len())
    };
    format!(
        "{} hits in {file}{}: if any is real, rotate it, then purge it from history; if none are, add {listed} to {ignore}",
        fs.len(),
        if generic { " (generic rules: review)" } else { "" }
    )
}

/// Whether a fix would update mise, which only a human bumps (ops pins
/// MISE_VERSION): `brew upgrade` naming it, or upgrading everything, or
/// `mise self-update`.
pub fn upgrades_mise(cmd: &str) -> bool {
    let Some(words) = shlex_split(cmd) else { return false };
    let w: Vec<&str> = words.iter().map(String::as_str).collect();
    (w.len() >= 2 && w[..2] == ["brew", "upgrade"] && (w[2..].contains(&"mise") || w.len() == 2))
        || (w.len() >= 2 && w[..2] == ["mise", "self-update"])
}

/// What `apply` did: the exit status (1 when an unattended fix failed) and
/// each unattended command with whether it succeeded (dry runs list none).
pub struct Applied {
    pub status: i32,
    pub ran: Vec<(String, bool)>,
}

/// Run (or, on a dry run, print) the unattended fixes and list the rest.
/// `confirm` gets the unattended commands before any runs; on false
/// nothing is run.
pub fn apply(
    findings: &[Finding],
    dryrun: bool,
    confirm: &dyn Fn(&[String]) -> bool,
    out: &mut dyn FnMut(&str),
) -> Applied {
    let (auto, manual, optional) = plan(findings);
    let mut ran = Vec::new();
    if auto.is_empty() && manual.is_empty() && optional.is_empty() {
        out("Nothing to update.");
        return Applied { status: 0, ran };
    }
    out("");
    out(&format!("==> Update plan{}", if dryrun { " (dry run: nothing is changed)" } else { "" }));
    let mut status = 0;
    let declined = !dryrun && !auto.is_empty() && !confirm(&auto);
    if declined {
        out("  Nothing was changed.");
    }
    for cmd in auto.iter().filter(|_| !declined) {
        if dryrun {
            out(&format!("  would run: {cmd}"));
            continue;
        }
        out(&format!("  → {cmd}"));
        let ok = shlex_split(cmd).filter(|w| !w.is_empty()).is_some_and(|w| run_bounded(&w, APPLY_TIMEOUT));
        if !ok {
            out(&format!("  ✗ failed: {cmd}"));
            status = 1;
        }
        ran.push((cmd.clone(), ok));
    }
    for (title, cmds) in [
        ("Needs you (sudo, a shell function, a vendor update, or a change in a repo, made on a branch):", &manual),
        ("Also worth doing (warnings: outdated, or waiting on a vendor):", &optional),
    ] {
        if !cmds.is_empty() {
            out(&format!("  {title}"));
            for cmd in cmds {
                out(&format!("    • {cmd}"));
            }
        }
    }
    Applied { status, ran }
}

/// How long one unattended fix may take (a package manager download).
const APPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Run `argv` as is (no shell), with the terminal, killing it after
/// `timeout`; whether it exited 0.
fn run_bounded(argv: &[String], timeout: std::time::Duration) -> bool {
    let Ok(mut child) =
        std::process::Command::new(&argv[0]).args(&argv[1..]).stdin(std::process::Stdio::null()).spawn()
    else {
        return false;
    };
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(_) => return false,
        }
    }
}

/// POSIX shell word splitting, as Python's `shlex.split`; None on an
/// unclosed quote or a trailing backslash.
pub fn shlex_split(s: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        c => cur.push(c),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => {
                            let n = chars.next()?;
                            if !matches!(n, '\\' | '"' | '$' | '`' | '\n') {
                                cur.push('\\');
                            }
                            cur.push(n);
                        }
                        c => cur.push(c),
                    }
                }
            }
            '\\' => {
                in_word = true;
                cur.push(chars.next()?);
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    Some(words)
}

#[cfg(test)]
mod tests;
