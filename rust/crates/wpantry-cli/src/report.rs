//! Print the findings, and plan or apply the fixes (`wpantry --update`).

use std::collections::HashSet;
use wpantry::check::{Finding, Outcome};
use wpantry::system::short;
use wpantry::versions;

pub const MISE_FIX: &str = "mise: manual, update it the way it was installed (https://mise.jdx.dev/installing-mise.html); wpantry never updates it";

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

/// The order kinds are listed in: what's installed on the machine, then
/// what the repos lock, then what the harnesses run, then everything else.
const KIND_ORDER: &[&str] = &[
    "posture",
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
            "✗ {fails} thing(s) to update ({advisories} advisories), {warns} warning(s). See the plan: wpantry --update --dryrun{incomplete}"
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

/// (unattended, needs you, also worth doing): one fix per component, the
/// one covering all its advisories, failures before warnings.
pub fn plan(findings: &[Finding]) -> (Vec<String>, Vec<String>, Vec<String>) {
    type Component<'a> = (&'a str, &'a str, &'a str, &'a str);
    let mut groups: Vec<(Component, Vec<&Finding>)> = Vec::new();
    for f in findings {
        // Every hit in one file is one decision (rotate, or allow the file),
        // not one step per line.
        let location = if f.kind == "secret" { "" } else { f.location.as_str() };
        let k = (f.kind.as_str(), f.component.as_str(), f.version.as_str(), location);
        match groups.iter_mut().find(|(key, _)| *key == k) {
            Some((_, v)) => v.push(f),
            None => groups.push((k, vec![f])),
        }
    }
    groups.sort_by_key(|(_, fs)| fs.iter().all(|f| f.status != "fail"));
    let (mut seen, mut auto, mut manual, mut optional) = (HashSet::new(), Vec::new(), Vec::new(), Vec::new());
    for (_, fs) in &groups {
        let f = covering(fs);
        let (cmd, unattended) = if upgrades_mise(&f.fix_cmd) {
            (MISE_FIX.to_string(), false)
        } else if f.kind == "secret" && fs.len() > 1 {
            (secrets_fix(fs), false)
        } else {
            (f.fix_cmd.clone(), f.fix_auto)
        };
        if cmd.is_empty() || !seen.insert(cmd.clone()) {
            continue;
        }
        if unattended {
            auto.push(cmd);
        } else if fs.iter().any(|x| x.status == "fail") {
            manual.push(cmd);
        } else {
            optional.push(cmd);
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
        format!("the {} fingerprints (each hit's `fix_cmd` in `wpantry check --json` names one)", fps.len())
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
mod tests {
    use super::*;

    fn f(cmd: &str, auto: bool, status: &str) -> Finding {
        Finding {
            kind: "tool".into(),
            component: cmd.rsplit(' ').next().unwrap_or("").into(),
            version: "1".into(),
            vuln_id: "CVE-1".into(),
            status: status.into(),
            fix_cmd: cmd.into(),
            fix_auto: auto,
            ..Default::default()
        }
    }

    // The test vectors the Python implementation had (`Plan` and `Mise`).
    #[test]
    fn plan_dedupes_and_splits() {
        let (auto, manual, optional) = plan(&[
            f("brew upgrade a", true, "fail"),
            f("brew upgrade a", true, "fail"),
            f("sudo apt-get install b", false, "fail"),
            f("Update App", false, "warn"),
        ]);
        assert_eq!(
            (auto, manual, optional),
            (
                vec!["brew upgrade a".to_string()],
                vec!["sudo apt-get install b".to_string()],
                vec!["Update App".to_string()]
            )
        );
    }

    /// Seventeen generic hits in one test-vector file are one decision in
    /// the plan, not seventeen steps.
    #[test]
    fn secret_hits_in_one_file_are_one_step() {
        let hit = |n: i64| Finding {
            kind: "secret".into(),
            component: "repo/TestVectors/xts.txt".into(),
            location: format!("line {n}, commit abc"),
            vuln_id: "generic-api-key".into(),
            status: "warn".into(),
            fix_cmd: format!(
                "If it's real: rotate it, then purge it from history. If not: add abc:TestVectors/xts.txt:generic-api-key:{n} to ~/repo/.gitleaksignore"
            ),
            ..Default::default()
        };
        let fs: Vec<Finding> = (1..=5).map(hit).collect();
        let (auto, manual, optional) = plan(&fs);
        assert!(auto.is_empty() && manual.is_empty());
        assert_eq!(optional.len(), 1, "{optional:?}");
        assert!(
            optional[0].starts_with("5 hits in repo/TestVectors/xts.txt (generic rules: review): "),
            "{}",
            optional[0]
        );
        assert!(optional[0].ends_with("to ~/repo/.gitleaksignore"), "{}", optional[0]);
        assert!(optional[0].contains("the 5 fingerprints"), "{}", optional[0]);
        let two: Vec<Finding> = (1..=2).map(hit).collect();
        let (_, _, optional) = plan(&two);
        assert!(
            optional[0]
                .contains("abc:TestVectors/xts.txt:generic-api-key:1, abc:TestVectors/xts.txt:generic-api-key:2"),
            "{}",
            optional[0]
        );
    }

    #[test]
    fn one_fix_per_component_covers_every_advisory() {
        let fs: Vec<Finding> = [("CVE-1", "0.23.45"), ("CVE-2", "0.23.46")]
            .iter()
            .map(|(id, safe)| Finding {
                component: "rustls".into(),
                vuln_id: id.to_string(),
                fixed: safe.to_string(),
                ..f(&format!("cargo update -p rustls --precise {safe}"), false, "fail")
            })
            .collect();
        assert_eq!(plan(&fs).1, ["cargo update -p rustls --precise 0.23.46"]);
    }

    #[test]
    fn dryrun_runs_nothing() {
        let mut lines = Vec::new();
        assert_eq!(apply(&[f("false", true, "fail")], true, &|_| true, &mut |l| lines.push(l.to_string())).status, 0);
        assert!(lines.contains(&"  would run: false".to_string()));
        let mut lines = Vec::new();
        assert_eq!(apply(&[f("false", true, "fail")], false, &|_| true, &mut |l| lines.push(l.to_string())).status, 1);
        assert!(lines.contains(&"  ✗ failed: false".to_string()));
        // Declined: the command is offered, and nothing runs.
        let mut lines = Vec::new();
        let offered = std::cell::RefCell::new(Vec::new());
        let decline = |cmds: &[String]| {
            offered.borrow_mut().extend_from_slice(cmds);
            false
        };
        assert_eq!(apply(&[f("false", true, "fail")], false, &decline, &mut |l| lines.push(l.to_string())).status, 0);
        assert_eq!(*offered.borrow(), ["false"]);
        assert!(lines.contains(&"  Nothing was changed.".to_string()));
        assert!(!lines.iter().any(|l| l.contains("failed")));
    }

    #[test]
    fn update_never_upgrades_mise() {
        let fs = [
            Finding { component: "mise".into(), ..f("brew upgrade mise", true, "fail") },
            Finding { component: "node".into(), ..f("mise install node@24.11.1", true, "fail") },
            Finding { component: "all".into(), ..f("brew upgrade", true, "warn") },
        ];
        let (auto, manual, optional) = plan(&fs);
        assert_eq!(
            (auto, manual, optional),
            (vec!["mise install node@24.11.1".to_string()], vec![MISE_FIX.to_string()], vec![])
        );
    }

    #[test]
    fn shlex() {
        assert_eq!(
            shlex_split(r#"cd '/w/my app' && echo "a \"b\" \x" c\ d"#).unwrap(),
            ["cd", "/w/my app", "&&", "echo", r#"a "b" \x"#, "c d"]
        );
        assert_eq!(shlex_split("x 'unclosed"), None);
    }

    #[test]
    fn report_groups_by_kind_with_reasons_and_fixes() {
        let adv = |id: &str, kev: bool, sev: &str, note: &str, fixed: &str| Finding {
            kind: "project".into(),
            component: "smallvec".into(),
            version: "1.6.0".into(),
            location: "/w/app/Cargo.lock".into(),
            vuln_id: id.into(),
            status: "fail".into(),
            fixed: fixed.into(),
            kev,
            severity: sev.into(),
            note: note.into(),
            fix_cmd: format!("cd /w/app && cargo update -p smallvec --precise {fixed}"),
            ..Default::default()
        };
        let scan = Outcome {
            scan_id: 1,
            findings: vec![
                Finding {
                    kind: "unchecked".into(),
                    component: "CISA KEV".into(),
                    vuln_id: "UNCHECKED".into(),
                    status: "warn".into(),
                    note: "down".into(),
                    ..Default::default()
                },
                adv("CVE-2021-25900", true, "CRITICAL", "Buffer overflow in SmallVec::insert_many", "1.6.1"),
                adv("CVE-2019-15551", false, "HIGH", "Double free", "1.0.0"),
                Finding {
                    kind: "mcp".into(),
                    component: "y-mcp (project: y)".into(),
                    version: "unpinned".into(),
                    location: "/w/app/.mcp.json".into(),
                    vuln_id: "UNPINNED".into(),
                    status: "warn".into(),
                    note: "`npx y-mcp` runs the latest release on every launch".into(),
                    fix_cmd: "Pin y-mcp to a reviewed version in /w/app/.mcp.json".into(),
                    ..Default::default()
                },
                Finding {
                    kind: "secret".into(),
                    component: "app/.env".into(),
                    location: "line 3, commit abc123".into(),
                    vuln_id: "aws-access-token".into(),
                    status: "fail".into(),
                    note: "AWS access key".into(),
                    fix_cmd: "Rotate it".into(),
                    ..Default::default()
                },
                Finding {
                    kind: "bundled".into(),
                    component: "Cursor ext x › lodash".into(),
                    version: "4.17.20".into(),
                    vuln_id: "CVE-2021-23337".into(),
                    status: "warn".into(),
                    fixed: "4.17.21".into(),
                    fix_cmd: "Update the extension".into(),
                    ..Default::default()
                },
            ],
            counts: vec![("git repos".into(), 1), ("project dependencies".into(), 10)],
            unfixed: 1,
            unknown_licenses: 0,
        };
        let mut lines = Vec::new();
        assert_eq!(report(&scan, "/c/w.db", &mut |l| lines.push(l.to_string())), 1);
        assert_eq!(
            lines,
            [
                "",
                "==> Security scan (/c/w.db)",
                "  checked 1 git repos, 10 project dependencies",
                "",
                "project",
                "  ✗ smallvec 1.6.0 (/w/app/Cargo.lock) - (CVE-2021-25900 KEV CRITICAL) Buffer overflow in SmallVec::insert_many. And 1 more: CVE-2019-15551. Fix: cd /w/app && cargo update -p smallvec --precise 1.6.1",
                "",
                "secret",
                "  ✗ app/.env (line 3, commit abc123) - (aws-access-token) AWS access key. Fix: Rotate it",
                "",
                "bundled",
                "  ⚠ Cursor ext x - (1 package, 1 advisory) lodash 4.17.20 → 4.17.21. Fix: Update the extension",
                "",
                "mcp",
                "  ⚠ y-mcp (project: y) unpinned (/w/app/.mcp.json) - (UNPINNED) `npx y-mcp` runs the latest release on every launch. Fix: Pin y-mcp to a reviewed version in /w/app/.mcp.json",
                "",
                "not checked",
                "  ⚠ CISA KEV - down",
                "",
                "  · 1 applicable advisories have no released fix yet (wpantry search --applicable)",
                "✗ 2 thing(s) to update (3 advisories), 2 warning(s). See the plan: wpantry --update --dryrun Incomplete: 1 source(s) couldn't be checked (offline?); re-run when they're reachable.",
            ]
        );
    }
}
