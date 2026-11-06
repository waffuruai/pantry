//! The terminal report: the latest scan grouped as the HTML report groups
//! it ([`wpantry::reporters::view`]), each area a heading over a table of
//! its rows, then what couldn't be checked and the update plan in batches.
//! Lines are spans with a role; [`paint`] maps roles to colours, so the
//! words are the same with colour or without (`--txt`, a pipe, `NO_COLOR`).
//! Drawn from the view's model, an interactive review (#166) later adds a
//! cursor and approvals to the same rows and batches.

use crate::style::{Style, clean};
use wpantry::reporters::Report;
use wpantry::reporters::view::{self, Area, Row, View};
use wpantry::utils::files::short;

/// What a span is, for its colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Plain,
    Heading,
    Dim,
    Fail,
    Warn,
    Good,
    /// A severity or tag that needs attention now (KEV, Critical, High).
    Hot,
    /// A command to run.
    Command,
}

pub type Line = Vec<(Role, String)>;

/// The terminal's width, when there is one; the report fits it.
pub fn width() -> usize {
    if let Some(n) = std::env::var("COLUMNS").ok().and_then(|c| c.trim().parse::<usize>().ok()).filter(|n| *n >= 40) {
        return n;
    }
    // `stty size` reads the terminal on its stdin: "rows cols".
    let tty = std::fs::File::open("/dev/tty").ok();
    let cols = tty.and_then(|t| {
        let out = std::process::Command::new("stty").arg("size").stdin(t).stderr(std::process::Stdio::null()).output();
        let text = String::from_utf8(out.ok()?.stdout).ok()?;
        text.split_whitespace().nth(1)?.parse::<usize>().ok()
    });
    cols.filter(|n| *n >= 40).unwrap_or(DEFAULT_WIDTH)
}

/// The width without a terminal (`--txt`, a pipe, a file).
pub const DEFAULT_WIDTH: usize = 120;

fn chars(s: &str) -> usize {
    s.chars().count()
}

/// `s` cut to `n` characters, `…` marking the cut.
fn fit(s: &str, n: usize) -> String {
    if chars(s) <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn pad(s: &str, n: usize) -> String {
    let s = fit(s, n);
    let fill = n.saturating_sub(chars(&s));
    format!("{s}{}", " ".repeat(fill))
}

fn plural(n: usize, word: &str) -> String {
    match (n, word.strip_suffix('y')) {
        (1, _) => format!("1 {word}"),
        (_, Some(stem)) => format!("{n} {stem}ies"),
        _ => format!("{n} {word}s"),
    }
}

fn hot(severity: &str) -> Role {
    match severity {
        "MALICIOUS" | "CRITICAL" | "HIGH" | "IMPORTANT" => Role::Hot,
        "MODERATE" | "MEDIUM" => Role::Warn,
        _ => Role::Plain,
    }
}

/// A row's cells: component, version, advisory, severity, fix.
fn cells(area: &Area, row: &Row) -> [String; 5] {
    if view::is_bundle(area.kind) {
        let pkgs: Vec<&str> = {
            let mut p: Vec<&str> = Vec::new();
            for f in &row.findings {
                let pkg = f.component.rsplit(" › ").next().unwrap_or("");
                if !p.contains(&pkg) {
                    p.push(pkg);
                }
            }
            p
        };
        let adv = format!("{}, {}", plural(pkgs.len(), "package"), plural(row.findings.len(), "advisory"));
        return [row.name.clone(), String::new(), adv, row.severity.to_string(), row.fix.clone()];
    }
    let mut adv = row.ids.first().map(|i| i.to_string()).unwrap_or_default();
    if row.ids.len() > 1 {
        adv.push_str(&format!(" +{}", row.ids.len() - 1));
    }
    [row.name.clone(), row.version.to_string(), adv, row.severity.to_string(), row.fix.clone()]
}

/// The column widths for an area's rows in `width` characters: each column
/// as wide as its widest cell, within a cap; the fix takes what's left.
fn columns(rows: &[[String; 5]], width: usize) -> [usize; 5] {
    // The component is what a reader looks for: on a wide terminal it gets
    // a third of the line.
    let caps = [36.max(width / 3), 18, 24, 10];
    let heads = ["COMPONENT", "VERSION", "ADVISORY", "SEVERITY"];
    let mut w = [0usize; 5];
    for (i, cap) in caps.iter().enumerate() {
        let widest = rows.iter().map(|r| chars(&r[i])).max().unwrap_or(0).max(chars(heads[i]));
        w[i] = widest.min(*cap);
    }
    // No row has a version (rules, settings, files): no version column.
    if rows.iter().all(|r| r[1].is_empty()) {
        w[1] = 0;
    }
    // "  ✗ " before the cells, two spaces between them, and room for the
    // fix: on a narrow terminal the component gives way first, then the
    // advisory and the version.
    const FIX: usize = 16;
    let used = |w: &[usize; 5]| 4 + w[..4].iter().map(|n| if *n == 0 { 0 } else { n + 2 }).sum::<usize>();
    for (col, floor) in [(0, 12), (2, 14), (1, 8)] {
        if w[col] > 0 && used(&w) + FIX > width {
            w[col] = w[col].saturating_sub(used(&w) + FIX - width).max(floor);
        }
    }
    w[4] = width.saturating_sub(used(&w)).max(FIX);
    w
}

/// A table line: the cells at their widths, two spaces apart, an empty
/// column left out.
fn cells_line(cells: Vec<(Role, &str)>, w: &[usize; 5]) -> Line {
    let mut out: Line = Vec::new();
    for (i, (role, text)) in cells.into_iter().enumerate() {
        if w[i] == 0 {
            continue;
        }
        if i == 4 {
            out.push((role, fit(text, w[i])));
        } else {
            out.push((role, pad(text, w[i])));
            out.push((Role::Plain, "  ".into()));
        }
    }
    out
}

fn area_lines(area: &Area, width: usize, out: &mut Vec<Line>) {
    let mut head: Line = vec![(Role::Heading, area.label.clone()), (Role::Dim, "  ".into())];
    let mut counts = Vec::new();
    if area.fails > 0 {
        counts.push(format!("{} fail", area.fails));
    }
    if area.warns > 0 {
        counts.push(format!("{} warn", area.warns));
    }
    head.push((Role::Dim, counts.join(" · ")));
    if area.kev {
        head.push((Role::Hot, "  known exploited".into()));
    }
    out.push(Vec::new());
    out.push(head);
    let rows: Vec<[String; 5]> = area.rows.iter().map(|r| cells(area, r)).collect();
    let w = columns(&rows, width);
    let heads = ["COMPONENT", "VERSION", "ADVISORY", "SEVERITY", "FIX"];
    let mut head: Line = vec![(Role::Dim, "    ".into())];
    head.extend(cells_line(heads.iter().map(|h| (Role::Dim, *h)).collect(), &w));
    out.push(head);
    for (row, c) in area.rows.iter().zip(&rows) {
        let (mark, role) = if row.fails { ("✗", Role::Fail) } else { ("⚠", Role::Warn) };
        let clean_cells: Vec<String> = c.iter().map(|x| clean(x)).collect();
        let mut line: Line = vec![(Role::Plain, "  ".into()), (role, mark.into()), (Role::Plain, " ".into())];
        line.extend(cells_line(
            vec![
                (Role::Plain, clean_cells[0].as_str()),
                (Role::Plain, clean_cells[1].as_str()),
                (if row.kev { Role::Hot } else { Role::Plain }, clean_cells[2].as_str()),
                (hot(row.severity), clean_cells[3].as_str()),
                (Role::Command, clean_cells[4].as_str()),
            ],
            &w,
        ));
        out.push(line);
        // Under it: where it is, and why it's listed.
        let mut why = String::new();
        if !row.location.is_empty() {
            why.push_str(&short(row.location));
            why.push_str(" · ");
        }
        if row.kev {
            why.push_str("known exploited · ");
        }
        why.push_str(row.top().note.trim());
        out.push(vec![(Role::Dim, format!("    {}", fit(&clean(&why), width.saturating_sub(4))))]);
    }
}

/// The report's lines for a terminal `width` wide.
pub fn lines(report: &Report, db: &str, width: usize) -> Vec<Line> {
    let r = &report.outcome;
    let v: View = view::view(&r.findings);
    let mut out: Vec<Line> = Vec::new();
    let finished = wpantry::history::stamp(report.scan.row.finished_at);
    out.push(Vec::new());
    out.push(vec![
        (Role::Heading, format!("==> Security scan #{}", r.scan_id)),
        (Role::Dim, format!("  {finished} · {}", short(db))),
    ]);
    let covered: Vec<String> = r.counts.iter().map(|(what, n)| format!("{n} {what}")).collect();
    let checked =
        if covered.is_empty() { "nothing to check".to_string() } else { format!("checked {}", covered.join(", ")) };
    out.push(vec![(Role::Dim, format!("  {checked}"))]);
    for a in &v.areas {
        area_lines(a, width, &mut out);
    }
    if !v.gaps.is_empty() {
        out.push(Vec::new());
        out.push(vec![(Role::Warn, "Not checked".into())]);
        for g in &v.gaps {
            out.push(vec![
                (Role::Plain, "  ".into()),
                (Role::Warn, "⚠".into()),
                (Role::Plain, fit(&clean(&format!(" {} - {}", g.component, g.note)), width.saturating_sub(3))),
            ]);
        }
    }
    if !v.batches.is_empty() {
        out.push(Vec::new());
        out.push(vec![
            (Role::Heading, "Update plan".into()),
            (Role::Dim, "  wpantry fix runs the automatic ones".into()),
        ]);
        for b in &v.batches {
            let mode = match b.mode {
                "auto" => "automatic",
                "manual" => "needs you",
                _ => "optional",
            };
            let mut line: Line = vec![(Role::Plain, format!("  {mode:<10} "))];
            if b.sudo {
                line.push((Role::Hot, "sudo ".into()));
            }
            let cmd = b.cmd.strip_prefix("sudo ").unwrap_or(&b.cmd);
            line.push((Role::Command, fit(&clean(cmd), width.saturating_sub(30))));
            line.push((Role::Dim, format!("  clears {}", plural(b.findings, "finding"))));
            out.push(line);
        }
    }
    out.push(Vec::new());
    if r.unfixed > 0 {
        out.push(vec![(
            Role::Dim,
            format!("  · {} applicable advisories have no released fix yet (wpantry search --applicable)", r.unfixed),
        )]);
    }
    if r.unknown_licenses > 0 {
        out.push(vec![(
            Role::Dim,
            format!("  · {} project dependencies have no license wpantry can identify", r.unknown_licenses),
        )]);
    }
    let fails = v.fails();
    let warns = v.rows() - fails;
    let incomplete = if v.gaps.is_empty() {
        String::new()
    } else {
        format!(
            " Incomplete: {} source(s) couldn't be checked (offline?); re-run when they're reachable.",
            v.gaps.len()
        )
    };
    out.push(if fails > 0 {
        let advisories = r.findings.iter().filter(|f| f.status == "fail").count();
        vec![(
            Role::Fail,
            format!(
                "✗ {fails} thing(s) to update ({advisories} advisories), {warns} warning(s). See the plan: wpantry fix --dryrun{incomplete}"
            ),
        )]
    } else if !v.gaps.is_empty() {
        vec![(Role::Warn, format!("⚠ nothing with a released fix found in what could be checked.{incomplete}"))]
    } else if warns > 0 {
        vec![(Role::Good, format!("✓ nothing with a released fix applies; {warns} warning(s) above"))]
    } else {
        vec![(Role::Good, "✓ nothing with a released fix applies to what was scanned".into())]
    });
    if let Some(h) = &report.history {
        history_lines(h, width, &mut out);
    }
    out
}

fn history_lines(h: &wpantry::reporters::History, width: usize, out: &mut Vec<Line>) {
    use wpantry::history::stamp;
    use wpantry::reporters::{EXPOSURE_COLUMNS, exposure_cells};
    out.push(Vec::new());
    out.push(vec![(Role::Heading, format!("History, the last {} days", h.since_days))]);
    // The exposure log, in the columns every format shares; the first seven
    // fit a terminal, dates to the day.
    let open = h.exposures.iter().filter(|e| e.resolved_at.is_none()).count();
    out.push(Vec::new());
    out.push(vec![
        (Role::Heading, "Exposure log".into()),
        (Role::Dim, format!("  {open} open · {} resolved", h.exposures.len() - open)),
    ]);
    let day = |s: &str| if s == "open" { s.to_string() } else { s.chars().take(10).collect() };
    let rows: Vec<[String; 7]> = h
        .exposures
        .iter()
        .map(|e| {
            let c = exposure_cells(e);
            let advisory = if e.kev { format!("{} KEV", c[5]) } else { c[5].clone() };
            [day(&c[0]), day(&c[1]), c[2].clone(), c[3].clone(), c[4].clone(), advisory, c[9].clone()]
        })
        .collect();
    let heads: Vec<&str> =
        [0, 1, 2, 3, 4, 5, 9].iter().map(|i| if *i == 9 { "Days" } else { EXPOSURE_COLUMNS[*i].1 }).collect();
    let mut w: Vec<usize> =
        (0..7).map(|i| rows.iter().map(|r| chars(&r[i])).max().unwrap_or(0).max(chars(heads[i]))).collect();
    w[3] = w[3].min(32);
    w[4] = w[4].min(16);
    w[5] = w[5].min(24);
    let used: usize = 2 + w.iter().map(|n| n + 2).sum::<usize>();
    if used > width {
        w[3] = w[3].saturating_sub(used - width).max(12);
    }
    let line = |cells: Vec<String>| cells.iter().zip(&w).map(|(c, n)| pad(c, *n)).collect::<Vec<_>>().join("  ");
    out.push(vec![(
        Role::Dim,
        format!("  {}", line(heads.iter().map(|h| h.to_uppercase()).collect())).trim_end().into(),
    )]);
    for (r, e) in rows.iter().zip(&h.exposures) {
        let role = if e.resolved_at.is_some() { Role::Good } else { Role::Plain };
        let cells: Vec<String> = r.iter().map(|c| clean(c)).collect();
        out.push(vec![(Role::Plain, "  ".into()), (role, line(cells).trim_end().to_string())]);
    }
    out.push(Vec::new());
    out.push(vec![(Role::Heading, "Remediation log".into()), (Role::Dim, format!("  {} fixes run", h.fixes.len()))]);
    for f in &h.fixes {
        let (mark, role) = if f.ok { ("✓", Role::Good) } else { ("✗", Role::Fail) };
        let verified = f.verified_scan.map(|s| format!("  verified by scan #{s}")).unwrap_or_default();
        out.push(vec![
            (Role::Plain, "  ".into()),
            (role, mark.into()),
            (Role::Plain, format!(" {} ", stamp(f.at))),
            (Role::Command, clean(&f.command)),
            (Role::Dim, verified),
        ]);
    }
    out.push(Vec::new());
    out.push(vec![(Role::Heading, "Audit log".into()), (Role::Dim, format!("  {} scans", h.scans.len()))]);
    for s in h.scans.iter().rev() {
        out.push(vec![(
            Role::Dim,
            clean(&format!(
                "  #{} {} {}@{} · {} · {} fail, {} warn, {} not checked",
                s.id,
                stamp(s.finished_at),
                s.user,
                s.host,
                s.scope,
                s.fails,
                s.warns,
                s.unchecked
            )),
        )]);
    }
}

/// A line in `style`'s colours.
pub fn paint(line: &Line, style: Style) -> String {
    line.iter()
        .map(|(role, s)| match role {
            Role::Plain => s.clone(),
            Role::Heading => style.bold(s),
            Role::Dim => style.dim(s),
            Role::Fail | Role::Hot => style.red(s),
            Role::Warn => style.yellow(s),
            Role::Good => style.green(s),
            Role::Command => style.cyan(s),
        })
        .collect::<String>()
        .trim_end()
        .to_string()
}

#[cfg(test)]
#[path = "tui_tests.rs"]
mod tests;
