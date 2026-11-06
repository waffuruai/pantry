//! The one shape every report shares: the findings grouped into areas (one
//! per kind), each area into rows (one per component, or per image or
//! extension for the packages bundled in it), everything in the order to
//! fix it; and the update plan as batches of alike commands, the ones that
//! need `sudo` kept apart. The terminal report, Markdown and (in time) the
//! HTML report draw from this, so they group and order the same way; an
//! interactive review (#166) adds a cursor and approvals to the same model.

use crate::finding::Finding;
use crate::remediation::{self, covering, shlex_split};

/// The order of areas at one rank: what is on the machine, what the repos
/// lock, what the harnesses run, then the rest.
pub const KIND_ORDER: &[&str] = &[
    "clipper",
    "malware",
    "posture",
    "persistence",
    "os",
    "runtime",
    "compiler",
    "manager",
    "pkgmgr",
    "tool",
    "datastore",
    "harness",
    "package",
    "brew",
    "app",
    "browser",
    "extension",
    "project",
    "image",
    "bundled",
    "mcp",
    "repo-hook",
    "hidden-text",
    "suspect-code",
    "document",
    "secret",
    "install-script",
    "license",
    "config",
    "account",
];

/// An area's heading.
pub fn label(kind: &str) -> String {
    let known = match kind {
        "project" => "Project dependencies",
        "mcp" => "MCP servers",
        "unchecked" => "Not checked",
        "secret" => "Committed secrets",
        "runtime" => "Runtimes",
        "os" => "Operating system",
        "compiler" => "Compilers",
        "manager" => "Version managers",
        "pkgmgr" => "Package managers",
        "tool" => "Tools",
        "datastore" => "Datastores",
        "harness" => "Agent harnesses",
        "package" => "Global packages",
        "brew" => "Homebrew",
        "app" => "Apps",
        "browser" => "Browsers",
        "extension" => "Editor extensions",
        "image" => "Container images",
        "bundled" => "Bundled packages",
        "repo-hook" => "Repo hooks",
        "posture" => "Security settings",
        "hidden-text" => "Hidden text",
        "suspect-code" => "Suspicious code",
        "document" => "Documents and images",
        "clipper" => "Clipboard hijackers",
        "malware" => "Malware",
        "persistence" => "Persistence",
        "install-script" => "Install scripts",
        "license" => "Licenses",
        "config" => "Configuration",
        "account" => "Accounts",
        _ => "",
    };
    if !known.is_empty() {
        return known.to_string();
    }
    let mut c = kind.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_else(|| "Other".into())
}

/// Many packages inside one thing (an image, an extension) are one row.
pub fn is_bundle(kind: &str) -> bool {
    matches!(kind, "image" | "bundled")
}

/// Severity labels from worst to least.
fn severity_rank(s: &str) -> Option<u32> {
    match s {
        "MALICIOUS" => Some(0),
        "CRITICAL" => Some(1),
        "HIGH" | "IMPORTANT" => Some(2),
        "MODERATE" | "MEDIUM" => Some(3),
        "LOW" => Some(4),
        _ => None,
    }
}

/// The order fixes go in (the agent skill's): failures before warnings;
/// then code that acts on its own (a clipper, malware, suspicious code,
/// hidden text, a repo that runs code on open), malicious packages,
/// committed secrets, known exploited, end of life, by severity, the rest.
pub fn rank(f: &Finding) -> u32 {
    let acts = matches!(f.kind.as_str(), "clipper" | "malware" | "suspect-code" | "hidden-text" | "repo-hook");
    let bucket = if acts && f.status == "fail" {
        0
    } else if f.severity == "MALICIOUS" || f.vuln_id == "MALICIOUS" {
        1
    } else if f.kind == "secret" && f.status == "fail" {
        2
    } else if f.kev {
        3
    } else if f.vuln_id == "EOL" {
        4
    } else if let Some(r) = severity_rank(&f.severity) {
        5 + r
    } else {
        10
    };
    if f.status == "fail" { bucket } else { 100 + bucket }
}

/// One component (or one image or extension) and its findings, ranked.
#[derive(Clone, Debug)]
pub struct Row<'a> {
    pub name: String,
    pub version: &'a str,
    pub location: &'a str,
    /// Best first; never empty.
    pub findings: Vec<&'a Finding>,
    pub fails: bool,
    pub kev: bool,
    /// The worst severity among them, or "".
    pub severity: &'a str,
    /// Each distinct id, in rank order.
    pub ids: Vec<&'a str>,
    /// What fixes the row: the command of the finding whose fix covers the
    /// rest, else any finding's command, else "update to <version>".
    pub fix: String,
}

impl<'a> Row<'a> {
    pub fn top(&self) -> &'a Finding {
        self.findings[0]
    }
}

/// One kind's rows.
#[derive(Clone, Debug)]
pub struct Area<'a> {
    pub kind: &'a str,
    pub label: String,
    pub rows: Vec<Row<'a>>,
    /// How many of its findings fail and warn.
    pub fails: usize,
    pub warns: usize,
    pub kev: bool,
}

/// Commands that can take more packages at the end: the package managers'.
const BATCHABLE: &[&str] = &[
    "brew",
    "npm",
    "pnpm",
    "yarn",
    "bun",
    "pip",
    "pip3",
    "pipx",
    "uv",
    "cargo",
    "gem",
    "go",
    "apt-get",
    "apt",
    "dnf",
    "yum",
    "zypper",
    "pacman",
    "mas",
    "mise",
    "softwareupdate",
    "rustup",
];

/// The update plan's steps that run as one command: `brew upgrade a` and
/// `brew upgrade b` are `brew upgrade a b`. A command needing `sudo` is
/// never batched with one that doesn't.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub cmd: String,
    pub sudo: bool,
    /// `auto` (wpantry fix runs it), `manual` (needs you, clears a
    /// failure) or `optional`.
    pub mode: &'static str,
    /// How many plan steps it joins, and how many findings it clears.
    pub steps: usize,
    pub findings: usize,
}

/// A command's batch key and the package it names, when it can join one:
/// a package manager's command whose last word is its one package, with
/// no shell operator anywhere.
fn batch_key(cmd: &str) -> Option<(String, String, bool)> {
    let words = shlex_split(cmd)?;
    if words.iter().any(|w| matches!(w.as_str(), "&&" | "||" | ";" | "|" | ">" | "<")) {
        return None;
    }
    let sudo = words.first().is_some_and(|w| w == "sudo");
    let rest = &words[usize::from(sudo)..];
    let (last, head) = rest.split_last()?;
    if head.len() < 2 || last.starts_with('-') || !BATCHABLE.contains(&head[0].as_str()) {
        return None;
    }
    Some((head.join(" "), last.clone(), sudo))
}

/// The update plan ([`remediation::steps`]) as batches, in plan order.
pub fn batches(findings: &[Finding]) -> Vec<Batch> {
    let mut out: Vec<(Option<String>, Vec<String>, Batch)> = Vec::new();
    for step in remediation::steps(findings) {
        let mode = step.mode();
        let key = batch_key(&step.cmd);
        let joined = key.as_ref().and_then(|(head, _, sudo)| {
            out.iter_mut().find(|(k, _, b)| k.as_deref() == Some(head.as_str()) && b.sudo == *sudo && b.mode == mode)
        });
        match (joined, &key) {
            (Some((_, args, b)), Some((_, arg, _))) => {
                if !args.contains(arg) {
                    args.push(arg.clone());
                }
                b.steps += 1;
                b.findings += step.findings.len();
            }
            _ => {
                let sudo = key.as_ref().map(|k| k.2).unwrap_or_else(|| step.cmd.trim_start().starts_with("sudo "));
                let batch = Batch { cmd: step.cmd.clone(), sudo, mode, steps: 1, findings: step.findings.len() };
                out.push((key.as_ref().map(|k| k.0.clone()), key.map(|k| vec![k.1]).unwrap_or_default(), batch));
            }
        }
    }
    out.into_iter()
        .map(|(head, args, mut b)| {
            if let Some(head) = head.filter(|_| b.steps > 1) {
                b.cmd = format!("{}{head} {}", if b.sudo { "sudo " } else { "" }, args.join(" "));
            }
            b
        })
        .collect()
}

/// Everything a report shows of one scan's findings.
#[derive(Clone, Debug)]
pub struct View<'a> {
    pub areas: Vec<Area<'a>>,
    /// What couldn't be checked.
    pub gaps: Vec<&'a Finding>,
    pub batches: Vec<Batch>,
}

impl View<'_> {
    pub fn fails(&self) -> usize {
        self.areas.iter().flat_map(|a| &a.rows).filter(|r| r.fails).count()
    }

    pub fn rows(&self) -> usize {
        self.areas.iter().map(|a| a.rows.len()).sum()
    }
}

fn fix_of(fs: &[&Finding]) -> String {
    let best = covering(fs);
    let cmd = if best.fix_cmd.is_empty() {
        fs.iter().map(|f| f.fix_cmd.as_str()).find(|c| !c.is_empty()).unwrap_or("")
    } else {
        &best.fix_cmd
    };
    match (cmd, best.fixed.as_str()) {
        ("", "") => String::new(),
        ("", fixed) => format!("update to {fixed}"),
        (cmd, _) => cmd.to_string(),
    }
}

/// `findings` grouped and ordered.
pub fn view(findings: &[Finding]) -> View<'_> {
    // A finding's place in `findings`, from its address: every finding
    // ranked here is borrowed from that slice.
    let base = findings.as_ptr() as usize;
    let index = |f: &Finding| (f as *const Finding as usize - base) / std::mem::size_of::<Finding>().max(1);
    let by_rank = |a: &&Finding, b: &&Finding| (rank(a), index(a)).cmp(&(rank(b), index(b)));
    let mut kinds: Vec<&str> = Vec::new();
    for f in findings.iter().filter(|f| f.kind != "unchecked") {
        if !kinds.contains(&f.kind.as_str()) {
            kinds.push(&f.kind);
        }
    }
    let mut areas: Vec<Area> = kinds
        .into_iter()
        .map(|kind| {
            let mut rows: Vec<Row> = Vec::new();
            for f in findings.iter().filter(|f| f.kind == kind) {
                let (name, version, location) = if is_bundle(kind) {
                    (f.component.split(" › ").next().unwrap_or("").to_string(), "", "")
                } else {
                    (f.component.clone(), f.version.as_str(), f.location.as_str())
                };
                match rows.iter_mut().find(|r| r.name == name && r.version == version && r.location == location) {
                    Some(r) => r.findings.push(f),
                    None => rows.push(Row {
                        name,
                        version,
                        location,
                        findings: vec![f],
                        fails: false,
                        kev: false,
                        severity: "",
                        ids: Vec::new(),
                        fix: String::new(),
                    }),
                }
            }
            for r in &mut rows {
                r.findings.sort_by(by_rank);
                r.fails = r.findings.iter().any(|f| f.status == "fail");
                r.kev = r.findings.iter().any(|f| f.kev);
                r.severity = r
                    .findings
                    .iter()
                    .map(|f| f.severity.as_str())
                    .filter(|s| !s.is_empty())
                    .min_by_key(|s| severity_rank(s).unwrap_or(9))
                    .unwrap_or("");
                for f in &r.findings {
                    if !f.vuln_id.is_empty() && !r.ids.contains(&f.vuln_id.as_str()) {
                        r.ids.push(&f.vuln_id);
                    }
                }
                r.fix = fix_of(&r.findings);
            }
            rows.sort_by(|a, b| by_rank(&a.top(), &b.top()));
            let all: Vec<&Finding> = rows.iter().flat_map(|r| r.findings.iter().copied()).collect();
            Area {
                kind,
                label: label(kind),
                fails: all.iter().filter(|f| f.status == "fail").count(),
                warns: all.iter().filter(|f| f.status != "fail").count(),
                kev: all.iter().any(|f| f.kev),
                rows,
            }
        })
        .collect();
    let kind_index = |k: &str| KIND_ORDER.iter().position(|x| *x == k).unwrap_or(KIND_ORDER.len());
    areas.sort_by_key(|a| (rank(a.rows[0].top()), kind_index(a.kind)));
    View { areas, gaps: findings.iter().filter(|f| f.kind == "unchecked").collect(), batches: batches(findings) }
}

#[cfg(test)]
#[path = "view_tests.rs"]
mod tests;
