//! ClamAV over a list of files, when it is installed: `clamdscan` with the
//! daemon's file descriptors passed, else `clamscan`, with a file list and
//! a ten-minute cap. The signature hits come back by path.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
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
    let (bin, daemon) = scanner()?;
    Some(clamav_with(&bin, daemon, files))
}

/// The installed scanner: `clamdscan` (daemon: true), else `clamscan`.
fn scanner() -> Option<(PathBuf, bool)> {
    match (crate::system::which("clamdscan"), crate::system::which("clamscan")) {
        (Some(d), _) => Some((d, true)),
        (None, Some(s)) => Some((s, false)),
        (None, None) => None,
    }
}

/// `bin` (clamdscan when `daemon`) over `files`: the infected ones with
/// their signature names; `Err` text when it couldn't run.
fn clamav_with(bin: &Path, daemon: bool, files: &[PathBuf]) -> Result<Vec<(PathBuf, String)>, String> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let list = match crate::system::TempDir::new("clamav") {
        Ok(d) => d,
        Err(e) => return Err(e.to_string()),
    };
    let list_file = list.path().join("files.txt");
    let text: String = files.iter().take(MAX_FILES).map(|p| format!("{}\n", p.display())).collect();
    if let Err(e) = std::fs::write(&list_file, text) {
        return Err(e.to_string());
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
        Err(e) => return Err(e.to_string()),
    };
    if out.code == Some(EXIT_ERROR) {
        return Err(format!("{} exited 2: {}", bin.display(), out.stderr.lines().next().unwrap_or("").trim()));
    }
    Ok(hits(&out.stdout))
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
        assert_eq!(clamav_with(Path::new("/nonexistent/clamscan"), false, &[]), Ok(Vec::new()));
    }

    /// An executable script standing in for the scanner.
    #[cfg(unix)]
    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// The scanner gets the file list and the daemon flag, and its FOUND
    /// lines come back as hits (exit 1 is "infected", not an error).
    #[cfg(unix)]
    #[test]
    fn a_recorded_scan_reports_its_hits() {
        let d = crate::system::TempDir::new("clamav-run").unwrap();
        let argv = d.path().join("argv.txt");
        let body = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{}\"\nfor a in \"$@\"; do list=\"$a\"; done\n\
             while read -r f; do echo \"$f: Eicar-Test-Signature FOUND\"; done < \"$list\"\nexit 1\n",
            argv.display()
        );
        let bin = script(d.path(), "clamscan", &body);
        let files = [PathBuf::from("/tmp/a.pdf"), PathBuf::from("/tmp/b: c.docx")];
        let hits = clamav_with(&bin, false, &files).unwrap();
        assert_eq!(
            hits,
            [
                (PathBuf::from("/tmp/a.pdf"), "Eicar-Test-Signature".to_string()),
                (PathBuf::from("/tmp/b: c.docx"), "Eicar-Test-Signature".to_string())
            ]
        );
        let args = std::fs::read_to_string(&argv).unwrap();
        let args: Vec<&str> = args.lines().collect();
        assert_eq!(&args[..4], ["--infected", "--no-summary", "--stdout", "--file-list"], "{args:?}");
        assert!(args[4].ends_with("files.txt"));
        // clamdscan passes the file descriptors to the daemon instead.
        assert_eq!(clamav_with(&bin, true, &files).unwrap().len(), 2);
        let args = std::fs::read_to_string(&argv).unwrap();
        assert!(args.contains("--fdpass\n") && !args.contains("--stdout\n"), "{args}");
        // More files than the cap: the list is cut where it is written.
        let count = script(
            d.path(),
            "count",
            "#!/bin/sh\nfor a in \"$@\"; do list=\"$a\"; done\necho \"capped: $(wc -l < \"$list\" | tr -d ' ') FOUND\"\n",
        );
        let many: Vec<PathBuf> = (0..MAX_FILES + 7).map(|i| PathBuf::from(format!("/f/{i}"))).collect();
        assert_eq!(clamav_with(&count, false, &many).unwrap(), [(PathBuf::from("capped"), MAX_FILES.to_string())]);
    }

    /// Exit 2 is the scanner failing (its first stderr line says why); a
    /// scanner that can't start is an error too. Neither is "clean".
    #[cfg(unix)]
    #[test]
    fn a_scanner_that_fails_or_cannot_start_is_an_error() {
        let d = crate::system::TempDir::new("clamav-err").unwrap();
        let bin =
            script(d.path(), "clamscan", "#!/bin/sh\necho \"ERROR: Can't open database\" >&2\necho more >&2\nexit 2\n");
        let files = [PathBuf::from("/tmp/a.pdf")];
        let err = clamav_with(&bin, false, &files).unwrap_err();
        assert_eq!(err, format!("{} exited 2: ERROR: Can't open database", bin.display()));
        let err = clamav_with(Path::new("/nonexistent/clamscan"), false, &files).unwrap_err();
        assert!(err.starts_with("/nonexistent/clamscan: "), "{err}");
    }
}
