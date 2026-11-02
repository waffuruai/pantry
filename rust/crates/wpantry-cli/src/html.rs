//! Optional, self-contained report. Stage next to the destination so errors
//! leave any previous report intact; never follow the destination's symlink.
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use wpantry::check::{Options, Outcome};
use wpantry::error::Result;
use wpantry::json::{J, obj};

const TEMPLATE: &str = include_str!("../assets/report.html");
const TOKEN: &str = "{{PANTRY_BUNDLE}}";

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
    TEMPLATE.replacen(TOKEN, &payload, 1)
}

pub fn finish(output: Option<Output>, report: &Outcome, opts: &Options, phase: &str) -> Result<()> {
    let Some(output) = output else { return Ok(()) };
    let paths = opts
        .paths
        .as_ref()
        .map(|ps| ps.iter().map(|p| p.to_string_lossy().into_owned().into()).collect())
        .unwrap_or_default();
    let suspect = opts.policy.suspect_policy();
    let policy_path =
        |p: &Option<PathBuf>| p.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| "bundled".into());
    let strings = |xs: Vec<String>| J::Arr(xs.into_iter().map(J::from).collect());
    let bundle = obj([
        (
            "runs",
            J::Arr(vec![obj([
                ("title", "Security scan".into()),
                ("file", "wpantry check".into()),
                ("report", super::envelope(report)),
            ])]),
        ),
        ("generated_at", J::Int((wpantry::system::now() * 1000.0) as i64)),
        ("phase", phase.into()),
        ("scan_id", J::Int(report.scan_id)),
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
    ]);
    output.write(&render(&bundle))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let parsed = wpantry::json::parse(payload.as_bytes(), usize::MAX).unwrap();
        assert_eq!(parsed["note"], hostile);
        assert!(!html.contains(TOKEN));
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
