//! The findings as a work queue, for `wpantry fix list` and `wpantry fix
//! next`: one item per finding that has a fix, in the order fixes go
//! (failures first, then [`rank`]), each with its id, the plan step that
//! clears it, and who carries it out. An agent works it one item at a
//! time: `fix next --json`, then `fix <id> --dry-run`, then `--yes`.

use crate::finding::Finding;
use crate::remediation::steps;
use crate::reporters::view::rank;
use crate::utils::json::{J, obj};
use std::collections::HashSet;

/// Who carries a fix out.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum How {
    /// wpantry runs it: `wpantry fix <id>` (`--dry-run` first, `--yes` once approved).
    Wpantry,
    /// A command for you, or an agent you've approved, to run.
    You,
    /// A person at a terminal: `wpantry fix secret <id>` asks for the
    /// secret with echo off, and before it rewrites history.
    Terminal,
}

impl How {
    pub fn name(self) -> &'static str {
        match self {
            How::Wpantry => "wpantry",
            How::You => "you",
            How::Terminal => "terminal",
        }
    }
}

/// One finding to fix.
#[derive(Clone, Debug)]
pub struct Item<'a> {
    pub finding: &'a Finding,
    pub id: String,
    /// The plan step that clears it: a command, or a script for a secret.
    pub cmd: String,
    /// `auto`, `manual` or `optional`, as in the plan.
    pub mode: &'static str,
    pub how: How,
}

impl Item<'_> {
    /// The command that starts this item.
    pub fn run(&self) -> String {
        match self.how {
            How::Wpantry => format!("wpantry fix {} --dry-run", self.id),
            How::You => self.cmd.clone(),
            How::Terminal => format!("wpantry fix secret {}", self.id),
        }
    }

    pub fn to_json(&self) -> J {
        let f = self.finding;
        obj([
            ("id", self.id.as_str().into()),
            ("kind", f.kind.as_str().into()),
            ("component", f.component.as_str().into()),
            ("version", f.version.as_str().into()),
            ("location", f.location.as_str().into()),
            ("vuln_id", f.vuln_id.as_str().into()),
            ("status", f.status.as_str().into()),
            ("severity", f.severity.as_str().into()),
            ("kev", f.kev.into()),
            ("fixed", f.fixed.as_str().into()),
            ("note", f.note.as_str().into()),
            ("mode", self.mode.into()),
            ("how", self.how.name().into()),
            ("run", self.run().into()),
            ("fix_cmd", self.cmd.as_str().into()),
        ])
    }
}

/// Every finding with a fix, in the order to fix them. Coverage gaps and
/// findings with no fix aren't items.
pub fn items(findings: &[Finding]) -> Vec<Item<'_>> {
    let steps = steps(findings);
    let mut out: Vec<(usize, Item)> = Vec::new();
    for step in &steps {
        for &i in &step.findings {
            let f = &findings[i];
            if f.kind == "unchecked" || out.iter().any(|(j, _)| *j == i) {
                continue;
            }
            let how = if f.kind == "secret" {
                How::Terminal
            } else if step.unattended {
                How::Wpantry
            } else {
                How::You
            };
            out.push((i, Item { finding: f, id: f.id(), cmd: step.cmd.clone(), mode: step.mode(), how }));
        }
    }
    out.sort_by_key(|(i, it)| (it.finding.status != "fail", rank(it.finding), *i));
    out.into_iter().map(|(_, it)| it).collect()
}

/// The first item not in `done` (finding keys a fix has been tried for
/// since the scan), and how many are left with it.
pub fn next<'a, 'b>(items: &'b [Item<'a>], done: &HashSet<String>) -> (Option<&'b Item<'a>>, usize) {
    let left: Vec<&Item> = items.iter().filter(|it| !done.contains(&it.finding.key())).collect();
    (left.first().copied(), left.len())
}

/// The finding an id names, in `findings`. Case doesn't matter.
pub fn find<'a>(findings: &'a [Finding], id: &str) -> Option<&'a Finding> {
    findings.iter().find(|f| f.id().eq_ignore_ascii_case(id))
}

/// Whether a word is a finding id: `F-` and ten hex digits.
pub fn is_id(word: &str) -> bool {
    let bytes = word.as_bytes();
    bytes.len() == 12 && bytes[..2].eq_ignore_ascii_case(b"F-") && bytes[2..].iter().all(u8::is_ascii_hexdigit)
}

#[cfg(test)]
#[path = "queue_tests.rs"]
mod tests;
