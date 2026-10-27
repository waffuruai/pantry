//! Print the findings, and plan or apply the fixes (`wscanner --update`).
//! The same report the Python implementation prints, line for line.

use std::collections::HashSet;
use wscanner::check::{Finding, Outcome};
use wscanner::system::short;
use wscanner::versions;

pub const MISE_FIX: &str = "mise: manual, see ops MISE_VERSION (make install-mise)";

fn mark(status: &str) -> &'static str {
    if status == "fail" { "✗" } else { "⚠" }
}

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

type Key = (String, String, String, String, String);

/// Report entries: (status, kind, name, version, location) → findings, in
/// first-seen order.
fn group(findings: &[Finding]) -> Vec<(Key, Vec<&Finding>)> {
    let mut by: Vec<(Key, Vec<&Finding>)> = Vec::new();
    for f in findings {
        let key: Key = if bundle(&f.kind).is_some() {
            (
                f.status.clone(),
                f.kind.clone(),
                f.component.split(" › ").next().unwrap_or("").into(),
                String::new(),
                String::new(),
            )
        } else if f.kind == "license" {
            (f.status.clone(), f.kind.clone(), f.note.clone(), String::new(), String::new())
        } else if f.vuln_id == "OUTDATED" && (f.kind == "app" || f.kind == "extension") {
            let editor = if f.kind == "extension" {
                f.component.rsplit('(').next().unwrap_or("").trim_end_matches(')').to_string()
            } else {
                "apps".into()
            };
            (f.status.clone(), "outdated".into(), editor, String::new(), String::new())
        } else {
            (f.status.clone(), f.kind.clone(), f.component.clone(), f.version.clone(), f.location.clone())
        };
        match by.iter_mut().find(|(k, _)| *k == key) {
            Some((_, fs)) => fs.push(f),
            None => by.push((key, vec![f])),
        }
    }
    by
}

/// Print the report; 1 when something fails.
pub fn report(scan: &Outcome, db: &str, out: &mut dyn FnMut(&str)) -> i32 {
    out("");
    out(&format!("==> Security scan ({db})"));
    let covered: Vec<String> = scan.counts.iter().map(|(what, n)| format!("{n} {what}")).collect();
    out(&if covered.is_empty() {
        "  nothing to check".to_string()
    } else {
        format!("  checked {}", covered.join(", "))
    });
    let mut by = group(&scan.findings);
    by.sort_by(|(a, _), (b, _)| (a.0 != "fail", &a.1, &a.2, &a.3, &a.4).cmp(&(b.0 != "fail", &b.1, &b.2, &b.3, &b.4)));
    for ((status, kind, comp, ver, loc), fs) in &by {
        if let Some(label) = bundle(kind) {
            bundle_entry(status, label, comp, fs, out);
        } else if kind == "license" {
            license(status, fs, out);
        } else if kind == "outdated" {
            outdated(status, comp, fs, out);
        } else if kind == "unchecked" {
            out(&format!("  ⚠ not checked: {comp}  ({})", fs[0].note));
        } else {
            entry(status, kind, format!("{comp} {ver}").trim(), loc, fs, out);
        }
    }
    let fails = by.iter().filter(|(k, _)| k.0 == "fail").count();
    let gaps = by.iter().filter(|(k, _)| k.1 == "unchecked").count();
    let warns = by.iter().filter(|(k, _)| k.0 == "warn").count() - gaps;
    if scan.unfixed > 0 {
        out(&format!(
            "  · {} applicable advisories have no released fix yet (wscanner search --applicable)",
            scan.unfixed
        ));
    }
    if scan.unknown_licenses > 0 {
        out(&format!("  · {} project dependencies have no license osv-scanner can identify", scan.unknown_licenses));
    }
    out("");
    let incomplete = if gaps > 0 {
        format!(" Incomplete: {gaps} source(s) couldn't be checked (offline?); re-run when they're reachable.")
    } else {
        String::new()
    };
    if fails > 0 {
        let advisories = scan.findings.iter().filter(|f| f.status == "fail").count();
        out(&format!(
            "✗ {fails} thing(s) to update ({advisories} advisories), {warns} warning(s). See the plan: wscanner --update --dryrun{incomplete}"
        ));
    } else if gaps > 0 {
        out(&format!("⚠ nothing with a released fix found in what could be checked.{incomplete}"));
    } else if warns > 0 {
        out(&format!("✓ nothing with a released fix applies; {warns} warning(s) above"));
    } else {
        out("✓ nothing with a released fix applies to what was scanned");
    }
    i32::from(fails > 0)
}

fn entry(status: &str, kind: &str, head: &str, loc: &str, fs: &[&Finding], out: &mut dyn FnMut(&str)) {
    let at = if loc.is_empty() { String::new() } else { format!("  ({})", short(loc)) };
    out(&format!("  {} {kind:<8} {head}{at}", mark(status)));
    let mut shown: Vec<&&Finding> = fs.iter().collect();
    shown.sort_by(|a, b| (!a.kev, &a.vuln_id).cmp(&(!b.kev, &b.vuln_id)));
    for f in shown.iter().take(4) {
        let tags: Vec<&str> = [if f.kev && f.severity != "MALICIOUS" { "KEV" } else { "" }, f.severity.as_str()]
            .into_iter()
            .filter(|t| !t.is_empty())
            .collect();
        let tags = if tags.is_empty() { String::new() } else { format!(" {}", tags.join(" ")) };
        let note = if f.vuln_id == "OUTDATED" { f.note.clone() } else { chars(&f.note, 90) }; // our own notes print whole
        out(&format!("      {}{tags}  {note}", f.vuln_id));
    }
    if shown.len() > 4 {
        out(&format!("      … and {} more", shown.len() - 4));
    }
    let best = covering(fs);
    if !best.fixed.is_empty() {
        out(&format!("      fixed in {}", best.fixed));
    }
    let cmd = if best.fix_cmd.is_empty() {
        fs.iter().map(|f| f.fix_cmd.as_str()).find(|c| !c.is_empty()).unwrap_or("")
    } else {
        &best.fix_cmd
    };
    if !cmd.is_empty() {
        out(&format!("      fix: {cmd}"));
    }
}

fn bundle_entry(status: &str, label: &str, r: &str, fs: &[&Finding], out: &mut dyn FnMut(&str)) {
    let mut pkgs: Vec<((String, String), Vec<&Finding>)> = Vec::new();
    for f in fs {
        let k = (f.component.split(" › ").last().unwrap_or("").to_string(), f.version.clone());
        match pkgs.iter_mut().find(|(key, _)| *key == k) {
            Some((_, v)) => v.push(f),
            None => pkgs.push((k, vec![f])),
        }
    }
    out(&format!("  {} {label:<8} {r}  ({} packages, {} advisories)", mark(status), pkgs.len(), fs.len()));
    pkgs.sort_by(|(_, a), (_, b)| {
        (!a.iter().any(|f| f.kev), std::cmp::Reverse(a.len()))
            .cmp(&(!b.iter().any(|f| f.kev), std::cmp::Reverse(b.len())))
    });
    for ((pkg, ver), pfs) in pkgs.iter().take(5) {
        let fixed = &covering(pfs).fixed;
        let arrow = if fixed.is_empty() { String::new() } else { format!(" → {fixed}") };
        let kev = if pfs.iter().any(|f| f.kev) { " KEV" } else { "" };
        out(&format!("      {pkg} {ver}{arrow}  ({} advisories{kev})", pfs.len()));
    }
    if pkgs.len() > 5 {
        out(&format!("      … and {} more packages", pkgs.len() - 5));
    }
    out(&format!("      fix: {}", fs[0].fix_cmd));
}

fn outdated(status: &str, grp: &str, fs: &[&Finding], out: &mut dyn FnMut(&str)) {
    let what = if grp == "apps" { "apps".to_string() } else { format!("{grp} extensions") };
    out(&format!("  {} outdated {} {what} behind their latest release", mark(status), fs.len()));
    let shown: Vec<String> = fs
        .iter()
        .take(6)
        .map(|f| format!("{} {} → {}", f.component.split(" (").next().unwrap_or(""), f.version, f.fixed))
        .collect();
    let more = if fs.len() > 6 { format!(" and {} more", fs.len() - 6) } else { String::new() };
    out(&format!("      {}{more}", shown.join(", ")));
    let auto = fs.iter().filter(|f| f.fix_auto).count();
    out(&if auto > 0 {
        format!("      fix: wscanner --update updates {auto} of them")
    } else {
        "      fix: update them from their vendors (or their own updaters)".to_string()
    });
}

fn license(status: &str, fs: &[&Finding], out: &mut dyn FnMut(&str)) {
    let mut names: Vec<&str> = fs.iter().map(|f| f.component.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    let mut where_: Vec<String> = fs
        .iter()
        .map(|f| {
            short(
                &std::path::Path::new(&f.location)
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            )
        })
        .collect();
    where_.sort();
    where_.dedup();
    out(&format!("  {} license  {}", mark(status), fs[0].note.replacen("license ", "", 1)));
    let more = if names.len() > 4 { format!(" and {} more", names.len() - 4) } else { String::new() };
    out(&format!(
        "      {} packages in {}: {}{more}",
        names.len(),
        where_.join(", "),
        names.iter().take(4).copied().collect::<Vec<_>>().join(", ")
    ));
    out("      fix: replace them, or approve the license in the licenses allowlist (--licenses)");
}

/// (unattended, needs you, also worth doing): one fix per component, the
/// one covering all its advisories, failures before warnings.
pub fn plan(findings: &[Finding]) -> (Vec<String>, Vec<String>, Vec<String>) {
    type Component<'a> = (&'a str, &'a str, &'a str, &'a str);
    let mut groups: Vec<(Component, Vec<&Finding>)> = Vec::new();
    for f in findings {
        let k = (f.kind.as_str(), f.component.as_str(), f.version.as_str(), f.location.as_str());
        match groups.iter_mut().find(|(key, _)| *key == k) {
            Some((_, v)) => v.push(f),
            None => groups.push((k, vec![f])),
        }
    }
    groups.sort_by_key(|(_, fs)| fs.iter().all(|f| f.status != "fail"));
    let (mut seen, mut auto, mut manual, mut optional) = (HashSet::new(), Vec::new(), Vec::new(), Vec::new());
    for (_, fs) in &groups {
        let f = covering(fs);
        let (cmd, unattended) =
            if upgrades_mise(&f.fix_cmd) { (MISE_FIX.to_string(), false) } else { (f.fix_cmd.clone(), f.fix_auto) };
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

/// Whether a fix would update mise, which only a human bumps (ops pins
/// MISE_VERSION): `brew upgrade` naming it, or upgrading everything, or
/// `mise self-update`.
pub fn upgrades_mise(cmd: &str) -> bool {
    let Some(words) = shlex_split(cmd) else { return false };
    let w: Vec<&str> = words.iter().map(String::as_str).collect();
    (w.len() >= 2 && w[..2] == ["brew", "upgrade"] && (w[2..].contains(&"mise") || w.len() == 2))
        || (w.len() >= 2 && w[..2] == ["mise", "self-update"])
}

/// Run (or, on a dry run, print) the unattended fixes and list the rest;
/// 1 when an unattended fix failed.
pub fn apply(findings: &[Finding], dryrun: bool, out: &mut dyn FnMut(&str)) -> i32 {
    let (auto, manual, optional) = plan(findings);
    if auto.is_empty() && manual.is_empty() && optional.is_empty() {
        out("Nothing to update.");
        return 0;
    }
    out("");
    out(&format!("==> Update plan{}", if dryrun { " (dry run: nothing is changed)" } else { "" }));
    let mut status = 0;
    for cmd in &auto {
        if dryrun {
            out(&format!("  would run: {cmd}"));
            continue;
        }
        out(&format!("  → {cmd}"));
        let ok = shlex_split(cmd)
            .filter(|w| !w.is_empty())
            .and_then(|w| std::process::Command::new(&w[0]).args(&w[1..]).status().ok())
            .is_some_and(|s| s.success());
        if !ok {
            out(&format!("  ✗ failed: {cmd}"));
            status = 1;
        }
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
    status
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

    // The Python test vectors (python/test_wscanner.py `Plan` and `Mise`).
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
        assert_eq!(apply(&[f("false", true, "fail")], true, &mut |l| lines.push(l.to_string())), 0);
        assert!(lines.contains(&"  would run: false".to_string()));
        let mut lines = Vec::new();
        assert_eq!(apply(&[f("false", true, "fail")], false, &mut |l| lines.push(l.to_string())), 1);
        assert!(lines.contains(&"  ✗ failed: false".to_string()));
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
    fn report_summarises() {
        let scan = Outcome {
            findings: vec![
                Finding {
                    kind: "unchecked".into(),
                    component: "CISA KEV".into(),
                    vuln_id: "UNCHECKED".into(),
                    status: "warn".into(),
                    note: "down".into(),
                    ..Default::default()
                },
                Finding { fixed: "1.2".into(), ..f("brew upgrade a", true, "fail") },
            ],
            counts: vec![("git repos".into(), 2)],
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
                "  checked 2 git repos",
                "  ✗ tool     a 1",
                "      CVE-1  ",
                "      fixed in 1.2",
                "      fix: brew upgrade a",
                "  ⚠ not checked: CISA KEV  (down)",
                "  · 1 applicable advisories have no released fix yet (wscanner search --applicable)",
                "",
                "✗ 1 thing(s) to update (1 advisories), 0 warning(s). See the plan: wscanner --update --dryrun Incomplete: 1 source(s) couldn't be checked (offline?); re-run when they're reachable.",
            ]
        );
    }
}
