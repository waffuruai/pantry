//! Markdown: the latest scan's findings, area by area as tables, what
//! couldn't be checked and the update plan; with `--history` the
//! exposure, remediation and audit logs after them.

use super::view::{self, View};
use super::{History, Part, Report};
use crate::history::{Exposure, stamp};
use crate::utils::files::short;

/// A table cell: no pipes, newlines or control characters.
pub fn cell(s: &str) -> String {
    s.replace('|', "\\|").chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

fn code(s: &str) -> String {
    if s.is_empty() { String::new() } else { format!("`{}`", cell(s).replace('`', "'")) }
}

fn cut(s: &str, n: usize) -> String {
    let s = s.trim().trim_end_matches('.');
    if s.chars().count() > n { format!("{}…", s.chars().take(n).collect::<String>()) } else { s.to_string() }
}

/// The report.
pub fn report(r: &Report) -> String {
    if r.part == Part::Summary {
        return super::summary::md(&super::summary::summary(r));
    }
    if !r.part.findings() {
        let mut t = String::from("# wpantry report\n");
        if let Some(h) = &r.history {
            history(&mut t, h, r.part);
        }
        return t;
    }
    let scan = &r.scan.row;
    let mut t = format!(
        "# wpantry report\n\nScan #{} finished {} on {} by {}, wpantry {}; scope {}.\n",
        scan.id,
        stamp(scan.finished_at),
        cell(&scan.host),
        cell(&scan.user),
        scan.version,
        cell(&scan.scope)
    );
    if !r.outcome.counts.is_empty() {
        let checked: Vec<String> = r.outcome.counts.iter().map(|(what, n)| format!("{n} {what}")).collect();
        t.push_str(&format!("\nChecked {}.\n", checked.join(", ")));
    }
    findings(&mut t, &view::view(&r.outcome.findings), r);
    if let Some(h) = r.history.as_ref().filter(|_| r.part == Part::All) {
        history(&mut t, h, r.part);
    }
    t
}

fn findings(t: &mut String, v: &View, r: &Report) {
    if v.areas.is_empty() && v.gaps.is_empty() {
        t.push_str("\nNothing with a released fix applies to what was scanned.\n");
    }
    for a in &v.areas {
        let kev = if a.kev { ", known exploited" } else { "" };
        t.push_str(&format!("\n## {} ({} fail, {} warn{kev})\n\n", a.label, a.fails, a.warns));
        t.push_str("| | Component | Version | Advisory | Severity | Why | Fix |\n|---|---|---|---|---|---|---|\n");
        for row in &a.rows {
            let mark = if row.fails { "✗" } else { "⚠" };
            let name = if row.location.is_empty() {
                row.name.clone()
            } else {
                format!("{} ({})", row.name, short(row.location))
            };
            let mut ids = row.ids.first().map(|i| i.to_string()).unwrap_or_default();
            if row.ids.len() > 1 {
                ids.push_str(&format!(" +{}", row.ids.len() - 1));
            }
            if row.kev {
                ids.push_str(" (KEV)");
            }
            t.push_str(&format!(
                "| {mark} | {} | {} | {} | {} | {} | {} |\n",
                cell(&name),
                cell(row.version),
                cell(&ids),
                cell(row.severity),
                cell(&cut(&row.top().note, 140)),
                code(&row.fix)
            ));
        }
    }
    if !v.gaps.is_empty() {
        t.push_str("\n## Not checked\n\n");
        for g in &v.gaps {
            t.push_str(&format!("- {}: {}\n", cell(&g.component), cell(&g.note)));
        }
    }
    if !v.batches.is_empty() {
        t.push_str("\n## Update plan\n\n| Mode | Command | Runs as | Clears |\n|---|---|---|---|\n");
        for b in &v.batches {
            let who = if b.sudo { "root (sudo)" } else { "you" };
            t.push_str(&format!("| {} | {} | {who} | {} |\n", b.mode, code(&b.cmd), b.findings));
        }
    }
    let mut notes = Vec::new();
    if r.outcome.unfixed > 0 {
        notes.push(format!(
            "{} applicable advisories have no released fix yet (`wpantry search --applicable`).",
            r.outcome.unfixed
        ));
    }
    if r.outcome.unknown_licenses > 0 {
        notes
            .push(format!("{} project dependencies have no license wpantry can identify.", r.outcome.unknown_licenses));
    }
    if !notes.is_empty() {
        t.push('\n');
        for n in notes {
            t.push_str(&format!("- {n}\n"));
        }
    }
}

fn history(t: &mut String, h: &History, part: Part) {
    t.push_str(&format!("\n# History: the last {} days\n", h.since_days));
    if part.exposure() {
        exposure_log(t, h);
    }
    if part.remediation() {
        remediation_log(t, h);
    }
    if part.audit() {
        audit_log(t, h);
    }
}

fn exposure_log(t: &mut String, h: &History) {
    let open = h.exposures.iter().filter(|e| e.resolved_at.is_none()).count();
    let closed: Vec<&Exposure> = h.exposures.iter().filter(|e| e.resolved_at.is_some()).collect();
    let median = {
        let mut d: Vec<f64> = closed.iter().map(|e| e.days_exposed).collect();
        d.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        d.get(d.len() / 2).copied().unwrap_or(0.0)
    };
    t.push_str(&format!(
        "\n## Exposure log\n\n{open} open, {} resolved; median time to resolve {median} days.\n\n",
        closed.len()
    ));
    let heads: Vec<&str> = super::EXPOSURE_COLUMNS.iter().map(|(_, h)| *h).collect();
    t.push_str(&format!("| {} |\n|{}\n", heads.join(" | "), "---|".repeat(heads.len())));
    for e in &h.exposures {
        let cells: Vec<String> = super::exposure_cells(e).iter().map(|c| cell(c)).collect();
        t.push_str(&format!("| {} |\n", cells.join(" | ")));
    }
}

fn remediation_log(t: &mut String, h: &History) {
    t.push_str(
        "\n## Remediation log\n\n| When | Who | Command | Mode | Result | Verified by scan |\n|---|---|---|---|---|---|\n",
    );
    for f in &h.fixes {
        t.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            stamp(f.at),
            cell(&super::summary::who(f)),
            code(&f.command),
            f.mode,
            if f.ok { "ok" } else { "failed" },
            f.verified_scan.map(|s| format!("#{s}")).unwrap_or_else(|| "-".into())
        ));
    }
}

fn audit_log(t: &mut String, h: &History) {
    t.push_str("\n## Audit log\n\n### Scans\n\n| # | Finished | Host | User | wpantry | Scope | Fails | Warns | Unchecked |\n|---|---|---|---|---|---|---|---|---|\n");
    for s in &h.scans {
        t.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            s.id,
            stamp(s.finished_at),
            cell(&s.host),
            cell(&s.user),
            s.version,
            cell(&s.scope),
            s.fails,
            s.warns,
            s.unchecked
        ));
    }
    t.push_str("\n### Events\n\n| When | Event | Detail |\n|---|---|---|\n");
    for e in &h.events {
        t.push_str(&format!("| {} | {} | {} |\n", stamp(e.at), e.kind, cell(&e.detail.to_string())));
    }
}
