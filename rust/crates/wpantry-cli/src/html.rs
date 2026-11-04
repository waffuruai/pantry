//! Optional, self-contained report. Stage next to the destination so errors
//! leave any previous report intact; never follow the destination's symlink.
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use wpantry::check::{Options, Outcome};
use wpantry::db::Cache;
use wpantry::error::Result;
use wpantry::history;
use wpantry::utils::json::{J, obj};

const TEMPLATE: &str = include_str!("../assets/report.html");
const TOKEN: &str = "{{PANTRY_BUNDLE}}";
/// The brand faces (SIL OFL, `assets/fonts/`), embedded so a report opens
/// offline without fetching a font.
const FONTS: [(&str, &[u8]); 4] = [
    ("{{FONT_SERIF}}", include_bytes!("../assets/fonts/instrument-serif-latin-400-normal.woff2")),
    ("{{FONT_SERIF_ITALIC}}", include_bytes!("../assets/fonts/instrument-serif-latin-400-italic.woff2")),
    ("{{FONT_SANS}}", include_bytes!("../assets/fonts/geist-latin-wght-normal.woff2")),
    ("{{FONT_MONO}}", include_bytes!("../assets/fonts/geist-mono-latin-wght-normal.woff2")),
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
    let since = wpantry::utils::os::now() - HISTORY_DAYS * wpantry::db::DAY;
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
    let plan: Vec<J> = super::report::steps(&report.findings)
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
                ("report", super::envelope(report)),
            ])]),
        ),
        ("generated_at", J::Int((wpantry::utils::os::now() * 1000.0) as i64)),
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
mod tests {
    use super::*;
    use wpantry::finding::Finding;

    #[test]
    fn hostile_text_stays_json_data() {
        assert_eq!(TEMPLATE.matches(TOKEN).count(), 1);
        let hostile = "</script><img src=x onerror=alert(1)>&\"'\u{2028}";
        let html = render(&obj([("note", hostile.into())]));
        let payload = html
            .split("<script id=\"pantry-bundle\" type=\"application/json\">")
            .nth(1)
            .unwrap()
            .split("</script>")
            .next()
            .unwrap();
        assert!(!payload.contains(['<', '>', '&']));
        let parsed = wpantry::utils::json::parse(payload.as_bytes(), usize::MAX).unwrap();
        assert_eq!(parsed["note"], hostile);
        assert!(!html.contains(TOKEN));
    }

    #[test]
    fn fonts_are_embedded_and_no_token_is_left() {
        let html = render(&obj([]));
        assert!(!html.contains("{{"), "a template token survived");
        assert_eq!(html.matches("data:font/woff2;base64,").count(), FONTS.len());
        assert!(!html.contains("http://") && !html.contains("https://fonts."), "nothing is fetched");
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    /// Every opened element is closed, in order, outside the script and
    /// style elements (the viewer's own output is checked by
    /// tests/html/test-viewer.cjs).
    #[test]
    fn template_is_well_formed() {
        let html = render(&obj([]));
        assert_eq!(well_formed(&strip(&strip(&html, "script"), "style")), None);
        assert_eq!(well_formed("<div><p>x</div>"), Some("mismatch: </div> closes p".into()));
        assert_eq!(well_formed("<div><br><img src=x>ok</div>"), None);
    }

    fn strip(html: &str, raw: &str) -> String {
        let (open, close) = (format!("<{raw}"), format!("</{raw}>"));
        let mut out = String::new();
        let mut rest = html;
        while let Some(start) = rest.find(&open) {
            let end = rest[start..].find(&close).map(|e| start + e + close.len()).expect("closed");
            out.push_str(&rest[..start]);
            rest = &rest[end..];
        }
        out.push_str(rest);
        out
    }

    /// None when every element closes in order; the first problem otherwise.
    fn well_formed(html: &str) -> Option<String> {
        const VOID: &[&str] =
            &["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"];
        let mut stack: Vec<String> = Vec::new();
        let mut rest = html;
        while let Some(lt) = rest.find('<') {
            let after = &rest[lt + 1..];
            if after.starts_with("!--") {
                let end = after.find("-->").map(|e| e + 3).unwrap_or(after.len());
                rest = &after[end..];
                continue;
            }
            let gt = after.find('>')?;
            let tag = &after[..gt];
            rest = &after[gt + 1..];
            if tag.starts_with('!') {
                continue;
            }
            let (closing, body) = match tag.strip_prefix('/') {
                Some(b) => (true, b),
                None => (false, tag),
            };
            let name: String =
                body.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-').collect::<String>().to_lowercase();
            if name.is_empty() {
                return Some(format!("stray tag <{tag}>"));
            }
            if closing {
                match stack.pop() {
                    Some(open) if open == name => {}
                    Some(open) => return Some(format!("mismatch: </{name}> closes {open}")),
                    None => return Some(format!("</{name}> closes nothing")),
                }
            } else if !VOID.contains(&name.as_str()) && !body.trim_end().ends_with('/') {
                stack.push(name);
            }
        }
        if rest.contains('>') {
            return Some("stray >".into());
        }
        if stack.is_empty() { None } else { Some(format!("unclosed {}", stack.join(", "))) }
    }

    fn fixture() -> Outcome {
        let f = |kind: &str, component: &str, id: &str, status: &str, fix_cmd: &str, auto: bool| Finding {
            kind: kind.into(),
            component: component.into(),
            version: "1.0".into(),
            location: format!("/w/{component}"),
            vuln_id: id.into(),
            status: status.into(),
            fix_cmd: fix_cmd.into(),
            fix_auto: auto,
            ..Default::default()
        };
        Outcome {
            scan_id: 7,
            findings: vec![
                f("brew", "openssl", "CVE-2026-1", "fail", "brew upgrade openssl", true),
                f("brew", "curl", "CVE-2026-2", "fail", "brew upgrade curl", true),
                f(
                    "posture",
                    "Firewall",
                    "POSTURE-FIREWALL",
                    "fail",
                    "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                    false,
                ),
                f("extension", "evil.ext", "MALICIOUS", "fail", "Remove the extension evil.ext", false),
                f("app", "Slack", "OUTDATED", "warn", "Update Slack from the vendor", false),
                f("unchecked", "CISA KEV", "UNCHECKED", "warn", "", false),
                f("project", "zip", "CVE-2026-3", "warn", "", false),
            ],
            counts: vec![("git repos".into(), 3), ("apps".into(), 40)],
            unfixed: 2,
            unknown_licenses: 0,
        }
    }

    /// The plan the viewer lists is wpantry's own: each non-auto fix as a
    /// manual (fail) or optional (warn) step with the findings it covers,
    /// the unattended ones as auto; gaps and fixless advisories take no step.
    #[test]
    fn bundle_carries_the_scan_its_plan_and_its_history() {
        let scan = fixture();
        let b = bundle(&scan, &Options::default(), "scan", J::Null, "mac", "eric");
        let text = b.dumps();
        let v = wpantry::utils::json::parse(text.as_bytes(), usize::MAX).unwrap();
        assert_eq!(v["runs"][0]["report"]["findings"].as_array().unwrap().len(), scan.findings.len());
        assert_eq!(
            (v["host"].as_str(), v["user"].as_str(), v["scan_id"].as_i64()),
            (Some("mac"), Some("eric"), Some(7))
        );
        assert!(v["history"].is_null());
        let plan = v["plan"].as_array().unwrap();
        let step = |cmd: &str| {
            plan.iter().find(|s| s["command"] == cmd).unwrap_or_else(|| panic!("no step for {cmd}: {text}"))
        };
        for f in scan.findings.iter().filter(|f| !f.fix_cmd.is_empty()) {
            let s = step(&f.fix_cmd);
            let expected = if f.fix_auto {
                "auto"
            } else if f.status == "fail" {
                "manual"
            } else {
                "optional"
            };
            assert_eq!(s["mode"], expected, "{}", f.fix_cmd);
            let i = scan.findings.iter().position(|x| x == f).unwrap() as i64;
            assert!(s["findings"].as_array().unwrap().iter().any(|n| n.as_i64() == Some(i)), "{}", f.fix_cmd);
        }
        assert_eq!(plan.len(), 5, "one step per command, none for the gap or the fixless advisory: {text}");
        // Failures come first, as the terminal plan orders them.
        let modes: Vec<&str> = plan.iter().map(|s| s["mode"].as_str().unwrap()).collect();
        assert_eq!(modes, ["auto", "auto", "manual", "manual", "optional"]);
        // The rendered page is still well formed with a real bundle in it.
        let html = render(&b);
        assert_eq!(well_formed(&strip(&strip(&html, "script"), "style")), None);
    }

    #[test]
    fn staging_preserves_previous_report_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!("pantry-html-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("report.html");
        std::fs::write(&dest, "previous").unwrap();
        let output = Output::new(&dest).unwrap();
        let staged = output.staging.clone();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "previous");
        drop(output);
        assert!(!staged.exists());
        Output::new(&dest).unwrap().write("next").unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "next");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o600);
        }
        #[cfg(unix)]
        {
            let link = dir.join("link.html");
            std::os::unix::fs::symlink(&dest, &link).unwrap();
            Output::new(&link).unwrap().write("separate").unwrap();
            assert_eq!(std::fs::read_to_string(&dest).unwrap(), "next");
            assert_eq!(std::fs::read_to_string(&link).unwrap(), "separate");
            assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        }
        assert!(Output::new(&dir).is_err());
        assert!(Output::new(&dir.join("missing/report.html")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
