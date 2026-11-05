//! The terminal report: the findings grouped by kind, each with its reason
//! and fix, then the update plan from [`crate::remediation`].

use crate::checks::Outcome;
use crate::finding::Finding;
use crate::remediation::covering;
use crate::utils::files::short;

/// Many packages inside one thing: one entry per thing.
fn bundle(kind: &str) -> Option<&'static str> {
    match kind {
        "image" => Some("image"),
        "bundled" => Some("bundles"),
        _ => None,
    }
}

fn chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// The order kinds are listed in: what's installed on the machine, then
/// what the repos lock, then what the harnesses run, then everything else.
const KIND_ORDER: &[&str] = &[
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
    "malware",
    "suspect-code",
    "document",
    "secret",
    "install-script",
    "license",
    "config",
    "account",
];

fn kind_rank(kind: &str) -> (usize, &str) {
    (KIND_ORDER.iter().position(|k| *k == kind).unwrap_or(KIND_ORDER.len()), kind)
}

/// One line of the report: a component (or one bundle) and its findings.
struct Entry<'a> {
    kind: &'a str,
    name: String,
    version: &'a str,
    location: &'a str,
    fs: Vec<&'a Finding>,
}

impl Entry<'_> {
    fn fails(&self) -> bool {
        self.fs.iter().any(|f| f.status == "fail")
    }
}

/// Findings grouped into entries, in first-seen order: one per component,
/// one per bundle (an image, an extension's bundled packages).
fn entries(findings: &[Finding]) -> Vec<Entry<'_>> {
    let mut out: Vec<Entry> = Vec::new();
    for f in findings.iter().filter(|f| f.kind != "unchecked") {
        let (name, version, location) = if bundle(&f.kind).is_some() {
            (f.component.split(" › ").next().unwrap_or("").to_string(), "", "")
        } else {
            (f.component.clone(), f.version.as_str(), f.location.as_str())
        };
        match out
            .iter_mut()
            .find(|e| e.kind == f.kind && e.name == name && e.version == version && e.location == location)
        {
            Some(e) => e.fs.push(f),
            None => out.push(Entry { kind: &f.kind, name, version, location, fs: vec![f] }),
        }
    }
    out
}

fn plural(n: usize, word: &str) -> String {
    match (n, word.strip_suffix('y')) {
        (1, _) => format!("1 {word}"),
        (_, Some(stem)) => format!("{n} {stem}ies"),
        _ => format!("{n} {word}s"),
    }
}

fn mark_of(fails: bool) -> &'static str {
    if fails { "✗" } else { "⚠" }
}

/// "name version (location)"
fn head(e: &Entry) -> String {
    let mut h = e.name.clone();
    if !e.version.is_empty() {
        h.push(' ');
        h.push_str(e.version);
    }
    if !e.location.is_empty() {
        h.push_str(&format!(" ({})", short(e.location)));
    }
    h
}

/// "Fix: …" from the finding whose fix covers the rest.
fn fix_of(fs: &[&Finding]) -> String {
    let best = covering(fs);
    let cmd = if best.fix_cmd.is_empty() {
        fs.iter().map(|f| f.fix_cmd.as_str()).find(|c| !c.is_empty()).unwrap_or("")
    } else {
        &best.fix_cmd
    };
    match (cmd, best.fixed.as_str()) {
        ("", "") => String::new(),
        ("", fixed) => format!(" Fix: update to {fixed}"),
        (cmd, _) => format!(" Fix: {cmd}"),
    }
}

fn sentence(note: &str) -> String {
    let note = note.trim().trim_end_matches('.');
    if note.is_empty() { String::new() } else { format!(" {note}.") }
}

/// `name version (location) - (ID KEV SEVERITY) Description. Fix: …`
fn line(e: &Entry) -> String {
    let mut fs = e.fs.clone();
    fs.sort_by(|a, b| (!a.kev, a.status != "fail", &a.vuln_id).cmp(&(!b.kev, b.status != "fail", &b.vuln_id)));
    let top = fs[0];
    let tags: Vec<&str> =
        [top.vuln_id.as_str(), if top.kev && top.severity != "MALICIOUS" { "KEV" } else { "" }, &top.severity]
            .into_iter()
            .filter(|t| !t.is_empty())
            .collect();
    // Our own notes print whole; an advisory's summary is cut.
    let own = matches!(top.vuln_id.as_str(), "OUTDATED" | "EOL" | "UNPINNED" | "MISSING" | "BROWSER" | "OS-UPDATE");
    let note = if own { top.note.clone() } else { chars(&top.note, 100) };
    let mut ids: Vec<&str> = fs.iter().skip(1).map(|f| f.vuln_id.as_str()).filter(|i| *i != top.vuln_id).collect();
    ids.dedup();
    let more = match ids.len() {
        0 => String::new(),
        n => {
            let shown: Vec<&str> = ids.iter().take(3).copied().collect();
            format!(" And {n} more: {}{}.", shown.join(", "), if n > 3 { ", …" } else { "" })
        }
    };
    format!("  {} {} - ({}){}{more}{}", mark_of(e.fails()), head(e), tags.join(" "), sentence(&note), fix_of(&fs))
}

/// `bundle - N packages with M advisories: pkg ver → fixed, … Fix: …`
fn bundle_line(e: &Entry) -> String {
    let mut pkgs: Vec<((&str, &str), Vec<&Finding>)> = Vec::new();
    for f in &e.fs {
        let k = (f.component.split(" › ").last().unwrap_or(""), f.version.as_str());
        match pkgs.iter_mut().find(|(key, _)| *key == k) {
            Some((_, v)) => v.push(f),
            None => pkgs.push((k, vec![f])),
        }
    }
    pkgs.sort_by(|(_, a), (_, b)| {
        (!a.iter().any(|f| f.kev), std::cmp::Reverse(a.len()))
            .cmp(&(!b.iter().any(|f| f.kev), std::cmp::Reverse(b.len())))
    });
    let shown: Vec<String> = pkgs
        .iter()
        .take(4)
        .map(|((pkg, ver), pfs)| {
            let fixed = &covering(pfs).fixed;
            if fixed.is_empty() { format!("{pkg} {ver}") } else { format!("{pkg} {ver} → {fixed}") }
        })
        .collect();
    let more = if pkgs.len() > 4 { format!(" and {} more", pkgs.len() - 4) } else { String::new() };
    let kev = if e.fs.iter().any(|f| f.kev) { ", KEV" } else { "" };
    let fix =
        e.fs.iter()
            .map(|f| f.fix_cmd.as_str())
            .find(|c| !c.is_empty())
            .map(|c| format!(" Fix: {c}"))
            .unwrap_or_default();
    format!(
        "  {} {} - ({}, {}{kev}) {}{more}.{fix}",
        mark_of(e.fails()),
        e.name,
        plural(pkgs.len(), "package"),
        plural(e.fs.len(), "advisory"),
        shown.join(", ")
    )
}

/// Print the report: the findings grouped by kind, one line per component
/// with why it's listed and how to fix it, then what couldn't be checked;
/// 1 when something fails.
pub fn report(scan: &Outcome, db: &str, out: &mut dyn FnMut(&str)) -> i32 {
    out("");
    out(&format!("==> Security scan ({})", short(db)));
    let covered: Vec<String> = scan.counts.iter().map(|(what, n)| format!("{n} {what}")).collect();
    out(&if covered.is_empty() {
        "  nothing to check".to_string()
    } else {
        format!("  checked {}", covered.join(", "))
    });

    let all = entries(&scan.findings);
    let mut kinds: Vec<&str> = Vec::new();
    for e in &all {
        if !kinds.contains(&e.kind) {
            kinds.push(e.kind);
        }
    }
    // Kinds with something failing first, then by kind.
    kinds.sort_by_key(|k| (!all.iter().any(|e| e.kind == *k && e.fails()), kind_rank(k)));
    for kind in &kinds {
        out("");
        out(kind);
        let mut group: Vec<&Entry> = all.iter().filter(|e| e.kind == *kind).collect();
        group.sort_by_key(|e| !e.fails());
        for e in group {
            out(&if bundle(kind).is_some() { bundle_line(e) } else { line(e) });
        }
    }
    let gaps: Vec<&Finding> = scan.findings.iter().filter(|f| f.kind == "unchecked").collect();
    if !gaps.is_empty() {
        out("");
        out("not checked");
        for f in &gaps {
            out(&format!("  ⚠ {} - {}", f.component, f.note));
        }
    }

    let fails = all.iter().filter(|e| e.fails()).count();
    let warns = all.len() - fails;
    out("");
    if scan.unfixed > 0 {
        out(&format!(
            "  · {} applicable advisories have no released fix yet (wpantry search --applicable)",
            scan.unfixed
        ));
    }
    if scan.unknown_licenses > 0 {
        out(&format!("  · {} project dependencies have no license wpantry can identify", scan.unknown_licenses));
    }
    let incomplete = if gaps.is_empty() {
        String::new()
    } else {
        format!(" Incomplete: {} source(s) couldn't be checked (offline?); re-run when they're reachable.", gaps.len())
    };
    if fails > 0 {
        let advisories = scan.findings.iter().filter(|f| f.status == "fail").count();
        out(&format!(
            "✗ {fails} thing(s) to update ({advisories} advisories), {warns} warning(s). See the plan: wpantry fix --dryrun{incomplete}"
        ));
    } else if !gaps.is_empty() {
        out(&format!("⚠ nothing with a released fix found in what could be checked.{incomplete}"));
    } else if warns > 0 {
        out(&format!("✓ nothing with a released fix applies; {warns} warning(s) above"));
    } else {
        out("✓ nothing with a released fix applies to what was scanned");
    }
    i32::from(fails > 0)
}

#[cfg(test)]
#[path = "text_tests.rs"]
mod tests;
