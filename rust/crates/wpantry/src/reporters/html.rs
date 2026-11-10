//! The standalone HTML report: one page, offline, the scan's findings, its
//! scope, the update plan and the history, rendered in the browser from a
//! bundle embedded in the page.
use super::Report;
use crate::checks::Options;
use crate::utils::json::{J, obj};
use std::path::PathBuf;

const TEMPLATE: &str = include_str!("../../assets/report/report.html");
const TOKEN: &str = "{{PANTRY_BUNDLE}}";
/// The brand faces (SIL OFL, `assets/fonts/`), embedded so a report opens
/// offline without fetching a font.
const FONTS: [(&str, &[u8]); 4] = [
    ("{{FONT_SERIF}}", include_bytes!("../../assets/report/fonts/instrument-serif-latin-400-normal.woff2")),
    ("{{FONT_SERIF_ITALIC}}", include_bytes!("../../assets/report/fonts/instrument-serif-latin-400-italic.woff2")),
    ("{{FONT_SANS}}", include_bytes!("../../assets/report/fonts/geist-latin-wght-normal.woff2")),
    ("{{FONT_MONO}}", include_bytes!("../../assets/report/fonts/geist-mono-latin-wght-normal.woff2")),
];
/// How far back the page's history looks when the report wasn't asked for
/// another reach (`--since DAYS`).
pub use super::HISTORY_DAYS;

fn render(bundle: &J) -> String {
    // JSON escaping alone does not protect an HTML script element's end tag.
    let payload = bundle.dumps().replace('&', "\\u0026").replace('<', "\\u003c").replace('>', "\\u003e");
    let mut html = TEMPLATE.replacen(TOKEN, &payload, 1);
    for (token, bytes) in FONTS {
        html = html.replacen(token, &base64(bytes), 1);
    }
    html
}

/// Standard base64 with padding, for the `data:` URLs the fonts ride in.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// What the cache remembers across scans, for the page's patched and
/// history sections: the exposures (those this scan doesn't list: it shows
/// its own findings under At risk), the fixes and the scans. Null without
/// a history.
fn history_json(report: &Report) -> J {
    let Some(h) = &report.history else { return J::Null };
    let listed: std::collections::HashSet<String> =
        report.outcome.findings.iter().map(crate::history::key_of).collect();
    let key = |e: &crate::history::Exposure| format!("{}|{}|{}|{}", e.kind, e.component, e.location, e.vuln_id);
    let open = h.exposures.iter().filter(|e| e.resolved_at.is_none()).count();
    let kept = h.exposures.iter().filter(|e| e.resolved_at.is_some() || !listed.contains(&key(e)));
    obj([
        ("since_days", J::Int(h.since_days)),
        ("open", J::Int(open as i64)),
        ("exposures", J::Arr(kept.map(|e| J::from(&e.to_json())).collect())),
        ("fixes", J::Arr(h.fixes.iter().map(|f| J::from(&f.to_json())).collect())),
        ("scans", J::Arr(h.scans.iter().map(|s| J::from(&s.to_json())).collect())),
    ])
}

/// The page for `report`.
pub fn page(report: &Report) -> String {
    render(&bundle(report))
}

/// What a scan ran with, as the page's Scope section shows it; kept with
/// each scan in the cache so a report renders it later.
pub fn scope_json(opts: &Options) -> J {
    let paths = opts
        .paths
        .as_ref()
        .map(|ps| ps.iter().map(|p| p.to_string_lossy().into_owned().into()).collect())
        .unwrap_or_default();
    let suspect = opts.policy.suspect_policy();
    let policy_path =
        |p: &Option<PathBuf>| p.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| "bundled".into());
    let strings = |xs: Vec<String>| J::Arr(xs.into_iter().map(J::from).collect());
    obj([
        ("machine", opts.machine.into()),
        ("offline", opts.offline.into()),
        ("licenses", opts.licenses.into()),
        ("posture", (opts.machine && !opts.no_posture).into()),
        ("personal_files", (opts.machine && !opts.no_personal_files).into()),
        ("posture_exclusions", strings(opts.policy.posture_skip())),
        ("suspect_exemptions", obj([("ids", strings(suspect.ids)), ("paths", strings(suspect.paths))])),
        (
            "policy_files",
            obj([
                ("gitleaks", policy_path(&opts.policy.gitleaks_config).into()),
                ("licenses", policy_path(&opts.policy.licenses).into()),
                ("install_scripts", policy_path(&opts.policy.install_scripts).into()),
                ("repo_hooks", policy_path(&opts.policy.repo_hooks).into()),
                ("posture", policy_path(&opts.policy.posture).into()),
                ("suspect", policy_path(&opts.policy.suspect).into()),
            ]),
        ),
        ("paths", J::Arr(paths)),
    ])
}

/// Everything the viewer renders: the scan (the `scan --json` envelope,
/// unchanged), its scope, the update plan (one step per command, the
/// findings it covers by index), and what the cache remembers.
fn bundle(report: &Report) -> J {
    let plan: Vec<J> = crate::remediation::steps(&report.outcome.findings)
        .iter()
        .map(|s| {
            obj([
                ("command", s.cmd.as_str().into()),
                ("mode", s.mode().into()),
                ("findings", J::Arr(s.findings.iter().map(|i| J::Int(*i as i64)).collect())),
            ])
        })
        .collect();
    let scan = &report.scan.row;
    obj([
        (
            "runs",
            J::Arr(vec![obj([
                ("title", "Security scan".into()),
                ("file", "wpantry scan".into()),
                ("report", super::json::envelope(&report.outcome)),
            ])]),
        ),
        ("generated_at", J::Int((crate::utils::os::now() * 1000.0) as i64)),
        ("phase", report.phase().into()),
        ("scan_id", J::Int(report.outcome.scan_id)),
        ("host", scan.host.as_str().into()),
        ("user", scan.user.as_str().into()),
        ("plan", J::Arr(plan)),
        ("history", history_json(report)),
        ("scope", J::from(&report.scan.options)),
    ])
}

#[cfg(test)]
#[path = "html_tests.rs"]
mod tests;
