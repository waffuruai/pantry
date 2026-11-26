//! The executable a registered job runs, read back from the job's own
//! definition: the plist's first `ProgramArguments` string, the service's
//! `ExecStart` word, the cron line's command word or the task's `Command`.
//! It undoes the quoting `plist`, `unit`, `cron_line` and
//! `windows::definition` apply, so a job another copy of `wpantry` (or the
//! launcher beside the scanner) registered reports that program, not this binary.
//!
//! ```ignore
//! let text = plist(Path::new("/opt/Pantry tools/wpantry"), None, Every::Day, 9, 30, &paths());
//! assert_eq!(read(Backend::Launchd, &text), Some(PathBuf::from("/opt/Pantry tools/wpantry")));
//! ```

use super::Backend;
use std::path::PathBuf;

/// The program in `text`: the plist (launchd), `wpantry.service` (systemd,
/// not the timer), the crontab line (cron) or the task XML (Windows).
/// `None` when the definition has no program this reader understands.
pub(super) fn read(backend: Backend, text: &str) -> Option<PathBuf> {
    let program = match backend {
        Backend::Launchd => launchd(text),
        Backend::Systemd => systemd(text),
        Backend::Cron => cron(text),
        Backend::Windows => windows(text),
    }?;
    (!program.is_empty()).then(|| PathBuf::from(program))
}

/// The reverse of `xml_escape`, plus the two entities Task Scheduler may
/// write itself. `&amp;` goes last so `&amp;lt;` stays `&lt;`.
fn xml_unescape(text: &str) -> String {
    text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

fn launchd(text: &str) -> Option<String> {
    let (_, rest) = text.split_once("<key>ProgramArguments</key>")?;
    let (array, _) = rest.trim_start().strip_prefix("<array>")?.split_once("</array>")?;
    let (_, first) = array.split_once("<string>")?;
    Some(xml_unescape(first.split_once("</string>")?.0))
}

/// `ExecStart=` as `unit` writes it: a bare word, or one in double quotes
/// with `\\`, `\"`, `\n` and `\r` escaped; `%%` and `$$` for `%` and `$`.
fn systemd(text: &str) -> Option<String> {
    let line = text.lines().find_map(|line| line.strip_prefix("ExecStart="))?;
    let word = match line.strip_prefix('"') {
        Some(quoted) => {
            let mut word = String::new();
            let mut chars = quoted.chars();
            loop {
                match chars.next()? {
                    '"' => break,
                    '\\' => word.push(match chars.next()? {
                        'n' => '\n',
                        'r' => '\r',
                        other => other,
                    }),
                    other => word.push(other),
                }
            }
            word
        }
        None => line.split_whitespace().next()?.to_owned(),
    };
    Some(word.replace("%%", "%").replace("$$", "$"))
}

/// The word after `nice -n 10 ` on our cron line: `cron_word` leaves it bare
/// or single-quotes it (`'\''` for a quote), and writes `%` as `\%`.
fn cron(text: &str) -> Option<String> {
    let (_, rest) = text.split_once(" nice -n 10 ")?;
    let rest = rest.replace(r"\%", "%");
    let mut word = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => loop {
                match chars.next()? {
                    '\'' => break,
                    other => word.push(other),
                }
            },
            '\\' => word.push(chars.next()?),
            c if c.is_whitespace() => break,
            c => word.push(c),
        }
    }
    Some(word)
}

/// The task's `<Command>`: the scanner, or the windowless launcher beside it.
fn windows(text: &str) -> Option<String> {
    let (_, rest) = text.split_once("<Command>")?;
    Some(xml_unescape(rest.split_once("</Command>")?.0.trim()))
}
