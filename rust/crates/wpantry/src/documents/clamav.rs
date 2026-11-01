//! ClamAV over a list of files, when it is installed: `clamdscan` with the
//! daemon's file descriptors passed, else `clamscan`, with a file list and
//! a ten-minute cap. The signature hits come back by path.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

/// More files than this go unscanned: the list is capped where it is written.
const MAX_FILES: usize = 5000;
const TIMEOUT: Duration = Duration::from_secs(600);
/// clamscan's exit codes: 0 clean, 1 infected, 2 error.
const EXIT_ERROR: i32 = 2;

/// `clamscan` (or `clamdscan`) over these files, when installed: the
/// infected ones with their signature names. `None` when no scanner is
/// installed; `Err` text when it couldn't run.
pub fn clamav(files: &[PathBuf]) -> Option<Result<Vec<(PathBuf, String)>, String>> {
    let (bin, daemon) = match (crate::system::which("clamdscan"), crate::system::which("clamscan")) {
        (Some(d), _) => (d, true),
        (None, Some(s)) => (s, false),
        (None, None) => return None,
    };
    if files.is_empty() {
        return Some(Ok(Vec::new()));
    }
    let list = match crate::system::TempDir::new("clamav") {
        Ok(d) => d,
        Err(e) => return Some(Err(e.to_string())),
    };
    let list_file = list.path().join("files.txt");
    let text: String = files.iter().take(MAX_FILES).map(|p| format!("{}\n", p.display())).collect();
    if let Err(e) = std::fs::write(&list_file, text) {
        return Some(Err(e.to_string()));
    }
    let mut argv: Vec<&OsStr> = vec![bin.as_os_str(), OsStr::new("--infected"), OsStr::new("--no-summary")];
    if daemon {
        argv.push(OsStr::new("--fdpass"));
    } else {
        argv.push(OsStr::new("--stdout"));
    }
    argv.push(OsStr::new("--file-list"));
    argv.push(list_file.as_os_str());
    let out = match crate::system::exec(&argv, &[], TIMEOUT) {
        Ok(o) => o,
        Err(e) => return Some(Err(e.to_string())),
    };
    if out.code == Some(EXIT_ERROR) {
        return Some(Err(format!("{} exited 2: {}", bin.display(), out.stderr.lines().next().unwrap_or("").trim())));
    }
    Some(Ok(hits(&out.stdout)))
}

/// The `<path>: <signature> FOUND` lines of clamscan's output, as (path,
/// signature); everything else it prints is left alone.
fn hits(stdout: &str) -> Vec<(PathBuf, String)> {
    let mut hits = Vec::new();
    for line in stdout.lines() {
        if let Some(rest) = line.strip_suffix(" FOUND")
            && let Some((path, sig)) = rest.rsplit_once(": ")
        {
            hits.push((PathBuf::from(path), sig.to_string()));
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_found_lines_and_nothing_else() {
        let out = "/tmp/a.pdf: Pdf.Exploit.CVE_2010_0188-1 FOUND\n\
                   /tmp/b.docx: OK\n\
                   /tmp/dir: with: colons.doc: Doc.Dropper.Agent-123 FOUND\n\
                   LibClamAV Warning: something\n\
                   /tmp/c.png: Can't open file ERROR\n";
        assert_eq!(
            hits(out),
            [
                (PathBuf::from("/tmp/a.pdf"), "Pdf.Exploit.CVE_2010_0188-1".to_string()),
                (PathBuf::from("/tmp/dir: with: colons.doc"), "Doc.Dropper.Agent-123".to_string()),
            ]
        );
        assert!(hits("").is_empty());
    }

    #[test]
    fn nothing_to_scan_runs_nothing() {
        // With no scanner installed the answer is None; with one, no files is
        // no hits. Either way no process is started.
        match clamav(&[]) {
            None => {}
            Some(Ok(hits)) => assert!(hits.is_empty()),
            Some(Err(e)) => panic!("an empty list should not run the scanner: {e}"),
        }
    }
}
