//! Optional, self-contained report. Stage next to the destination so errors
//! leave any previous report intact; never follow the destination's symlink.
use crate::checks::{Options, Outcome};
use crate::db::Cache;
use crate::error::Result;
use crate::history;
use crate::utils::json::{J, obj};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
/// How far back the history sections look, as `wpantry report` does.
const HISTORY_DAYS: f64 = 90.0;

pub struct Output {
    destination: PathBuf,
    staging: PathBuf,
    file: File,
}

impl Output {
    pub fn new(destination: &Path) -> io::Result<Self> {
        if destination.is_dir() {
            return Err(io::Error::other("HTML output must be a file, not a directory"));
        }
        let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let staging = parent.join(format!(".wpantry-report-{}-{nonce}.tmp", std::process::id()));
        let mut open = OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        let file = open
            .open(&staging)
            .map_err(|e| io::Error::new(e.kind(), format!("HTML output {}: {e}", destination.display())))?;
        Ok(Self { destination: destination.to_path_buf(), staging, file })
    }

    fn write(mut self, text: &str) -> io::Result<()> {
        self.file.write_all(text.as_bytes())?;
        self.file.flush()?;
        std::fs::rename(&self.staging, &self.destination)?;
        eprintln!("HTML report written to {}", self.destination.display());
        Ok(())
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.staging);
    }
}

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

/// What the cache remembers across scans, for the report's patched and
/// history sections: the exposures, the fixes `wpantry fix` ran and the scans
/// of the last [`HISTORY_DAYS`], plus the host and user of this scan. Null
/// when the cache can't be read: the report still describes the scan.
fn history_json(report: &Outcome) -> (J, String, String) {
    let Ok(cache) = Cache::open(None) else { return (J::Null, String::new(), String::new()) };
    let scan_id = report.scan_id;
    // The open exposures this scan lists are its findings, shown under At
    // risk; the log carries the rest: resolved ones, and open ones of
    // another scope. A machine scan can list tens of thousands.
    let listed: std::collections::HashSet<String> = report.findings.iter().map(history::key_of).collect();
    let key = |e: &history::Exposure| format!("{}|{}|{}|{}", e.kind, e.component, e.location, e.vuln_id);
    let since = crate::utils::os::now() - HISTORY_DAYS * crate::db::DAY;
    let out = match (history::exposures(&cache, since), history::fixes(&cache, since), history::scans(&cache, since)) {
        (Ok(exposures), Ok(fixes), Ok(scans)) => {
            let this = scans.iter().find(|s| s.id == scan_id);
            let (host, user) = this.map(|s| (s.host.clone(), s.user.clone())).unwrap_or_default();
            let open = exposures.iter().filter(|e| e.resolved_at.is_none()).count();
            let kept = exposures.iter().filter(|e| e.resolved_at.is_some() || !listed.contains(&key(e)));
            let h = obj([
                ("since_days", J::Int(HISTORY_DAYS as i64)),
                ("open", J::Int(open as i64)),
                ("exposures", J::Arr(kept.map(|e| J::from(&e.to_json())).collect())),
                ("fixes", J::Arr(fixes.iter().map(|f| J::from(&f.to_json())).collect())),
                ("scans", J::Arr(scans.iter().map(|s| J::from(&s.to_json())).collect())),
            ]);
            (h, host, user)
        }
        _ => (J::Null, String::new(), String::new()),
    };
    let _ = cache.close();
    out
}

pub fn finish(output: Option<Output>, report: &Outcome, opts: &Options, phase: &str) -> Result<()> {
    let Some(output) = output else { return Ok(()) };
    let (history, host, user) = history_json(report);
    output.write(&render(&bundle(report, opts, phase, history, &host, &user)))?;
    Ok(())
}

/// Everything the viewer renders: the scan (the `scan --json` envelope,
/// unchanged), its scope, the update plan (one step per command, the
/// findings it covers by index), and what the cache remembers.
fn bundle(report: &Outcome, opts: &Options, phase: &str, history: J, host: &str, user: &str) -> J {
    let paths = opts
        .paths
        .as_ref()
        .map(|ps| ps.iter().map(|p| p.to_string_lossy().into_owned().into()).collect())
        .unwrap_or_default();
    let suspect = opts.policy.suspect_policy();
    let policy_path =
        |p: &Option<PathBuf>| p.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| "bundled".into());
    let strings = |xs: Vec<String>| J::Arr(xs.into_iter().map(J::from).collect());
    let plan: Vec<J> = crate::remediation::steps(&report.findings)
        .iter()
        .map(|s| {
            obj([
                ("command", s.cmd.as_str().into()),
                ("mode", s.mode().into()),
                ("findings", J::Arr(s.findings.iter().map(|i| J::Int(*i as i64)).collect())),
            ])
        })
        .collect();
    obj([
        (
            "runs",
            J::Arr(vec![obj([
                ("title", "Security scan".into()),
                ("file", "wpantry scan".into()),
                ("report", super::json::envelope(report)),
            ])]),
        ),
        ("generated_at", J::Int((crate::utils::os::now() * 1000.0) as i64)),
        ("phase", phase.into()),
        ("scan_id", J::Int(report.scan_id)),
        ("host", host.into()),
        ("user", user.into()),
        ("plan", J::Arr(plan)),
        ("history", history),
        (
            "scope",
            obj([
                ("machine", opts.machine.into()),
                ("offline", opts.offline.into()),
                ("licenses", opts.licenses.into()),
                ("posture", (opts.machine && !opts.no_posture).into()),
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
            ]),
        ),
    ])
}

#[cfg(test)]
#[path = "html_tests.rs"]
mod tests;
