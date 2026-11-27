//! Fixing what a scan found: the update plan (what `wpantry fix` runs
//! unattended, what needs a person, what is optional) as numbered steps,
//! and running the unattended ones, each bounded by a timeout and never
//! through a shell. The stopgaps for a fix that isn't out yet are in
//! [`mitigate`], with the two fixes wpantry makes itself: [`ca_trust`] and
//! [`editors`].

pub mod ca_trust;
pub mod dismiss;
pub mod editors;
pub mod mitigate;
pub mod queue;
pub mod recheck;
mod recheck_posture;
#[cfg(test)]
mod recheck_posture_tests;
mod recheck_project;
#[cfg(test)]
mod recheck_project_tests;
pub mod run;
pub mod secret;

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

/// The unattended fixes one `fix <ID>` for `one` runs: `one` and every other
/// finding of the same component (kind, name, version, location) in `all`
/// that has one. [`steps`] picks among them the fix that covers them all,
/// as the list and the plan do, so fixing a component for one advisory does
/// not leave its other advisories open.
pub fn component_fixes(all: &[Finding], one: &Finding) -> Vec<Finding> {
    let same = |f: &Finding| {
        (&f.kind, &f.component, &f.version, &f.location) == (&one.kind, &one.component, &one.version, &one.location)
    };
    let mut out = vec![one.clone()];
    out.extend(all.iter().filter(|f| same(f) && f.fix_auto && !f.fix_cmd.is_empty() && f.key() != one.key()).cloned());
    out
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
        // not one step per line; each rule's test hits are one of their own.
        let tests = f.location == crate::checks::supply_chain::leaks::TESTS;
        let location = if f.kind == "secret" && !tests { "" } else { f.location.as_str() };
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
        // A mise runtime's fix is two lines, install then uninstall: two
        // steps, of which only the first may run unattended.
        for (n, cmd) in split_steps(cmd).into_iter().enumerate() {
            let unattended = unattended && n == 0;
            match out.iter_mut().find(|s| s.cmd == cmd) {
                // The first component to name a command decides how it runs.
                Some(s) => s.findings.extend(is.iter().copied()),
                None => out.push(Step { cmd, unattended, fails, findings: is.clone() }),
            }
        }
    }
    out
}

/// A fix of several `mise` commands, a line each, as the steps it is; any
/// other fix (a script, a sentence) is one step.
fn split_steps(cmd: String) -> Vec<String> {
    if cmd.lines().count() > 1 && cmd.lines().all(|l| l.starts_with("mise ")) {
        cmd.lines().map(str::to_string).collect()
    } else {
        vec![cmd]
    }
}

/// The first step of a fix: the whole of it, unless it is several
/// ([`split_steps`]).
pub fn first_step(fix_cmd: &str) -> String {
    split_steps(fix_cmd.to_string()).into_iter().next().unwrap_or_default()
}

/// For each later step of a fix of several, the step before it that must
/// have worked first: `mise uninstall python@3.14.9` waits on `mise install
/// python@3.14.10`.
fn waits_on(findings: &[Finding]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for f in findings {
        let steps = split_steps(f.fix_cmd.clone());
        for pair in steps.windows(2) {
            let pair = (pair[1].clone(), pair[0].clone());
            if !out.contains(&pair) {
                out.push(pair);
            }
        }
    }
    out
}

/// Whether `step` (one command of the plan) is, or is one line of, the fix
/// `fix_cmd` a finding carries.
pub fn is_step_of(fix_cmd: &str, step: &str) -> bool {
    fix_cmd == step || (fix_cmd.lines().count() > 1 && split_steps(fix_cmd.to_string()).iter().any(|s| s == step))
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

/// One step for every hit in a file, in every version of it: the script
/// [`leaks::fix`](crate::checks::supply_chain::leaks::fix) writes, for all
/// of them. A finding whose fix doesn't name its repo keeps its own.
fn secrets_fix(fs: &[&Finding]) -> String {
    use crate::checks::supply_chain::leaks;
    let Some((repo, file)) = leaks::fix_target(&fs[0].fix_cmd) else { return fs[0].fix_cmd.clone() };
    let spots: Vec<(&str, i64, String)> = fs
        .iter()
        .flat_map(|f| leaks::places(&f.location).into_iter().map(|(line, commit)| (f.vuln_id.as_str(), line, commit)))
        .collect();
    let hits: Vec<(&str, i64, &str)> =
        spots.iter().map(|(rule, line, commit)| (*rule, *line, commit.as_str())).collect();
    if hits.is_empty() {
        return fs[0].fix_cmd.clone();
    }
    leaks::fix(&repo, &file, &hits, fs.iter().all(|f| f.status != "fail"))
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
    /// Why each command in `ran` that failed did: its exit code and the end of its stderr.
    pub failures: Vec<run::Failure>,
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
    let waiting = waits_on(findings);
    let mut ran = Vec::new();
    let mut failures = Vec::new();
    if auto.is_empty() && manual.is_empty() && optional.is_empty() {
        out("Nothing to update.");
        return Applied { status: 0, ran, failures };
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
        let run = match shlex_split(cmd).filter(|w| !w.is_empty()) {
            Some(w) => run::run_bounded(&w, APPLY_TIMEOUT),
            None => run::Run { reason: "not a command wpantry can run unattended".into(), ..Default::default() },
        };
        let ok = run.ok;
        if !ok {
            out(&format!("  ✗ failed: {cmd}"));
            let failure =
                run::Failure { cmd: cmd.clone(), exit_code: run.exit_code, reason: run.reason, stderr: run.stderr };
            for line in failure.lines() {
                out(&line);
            }
            failures.push(failure);
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
                // A step that removes the old version is only safe once the
                // step that installs the new one has worked: say so when it
                // hasn't (it failed, was declined, or this is a dry run).
                let first = waiting.iter().find(|(later, _)| later == cmd).map(|(_, first)| first);
                match first.filter(|f| auto.contains(f) && !ran.contains(&((*f).clone(), true))) {
                    Some(first) => out(&format!("    • {cmd}  (only after `{first}` has succeeded)")),
                    None => out(&format!("    • {cmd}")),
                }
            }
        }
    }
    Applied { status, ran, failures }
}

/// How long one unattended fix may take (a package manager download).
const APPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

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
