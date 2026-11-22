//! Per-user, least-privilege Windows Task Scheduler job.

use super::{Every, Run, xml_escape};
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    time::Duration,
};
use wpantry::error::{Error, Result};
use wpantry::utils::{process::Output, temp::TempDir};

fn call(run: Run, args: &[&OsStr]) -> Result<Output> {
    let command = std::iter::once(OsStr::new("schtasks.exe")).chain(args.iter().copied()).collect::<Vec<_>>();
    run(&command, Duration::from_secs(30))
}

fn user_sid(run: Run) -> Result<String> {
    let out = run(&["whoami.exe", "/user", "/fo", "csv", "/nh"].map(OsStr::new), Duration::from_secs(10))?;
    out.stdout
        .split('"')
        .find(|word| {
            word.trim_start_matches("S-1-")
                .split('-')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                && word.starts_with("S-1-")
        })
        .filter(|_| out.code == Some(0))
        .map(str::to_owned)
        .ok_or_else(|| Error::Failed("Could not read the current Windows user's SID.".into()))
}

fn task(sid: &str) -> String {
    format!("Waffuru-Pantry-{sid}")
}

fn checked(out: Output) -> Result<String> {
    if out.code != Some(0) {
        return Err(Error::Failed(format!("Windows Task Scheduler: {}", out.stderr.trim())));
    }
    Ok(out.stdout)
}

fn query_task(name: &str, run: Run) -> Result<Option<String>> {
    let out = call(run, &["/query", "/tn", name, "/xml"].map(OsStr::new))?;
    if out.code == Some(0) {
        // Task Scheduler may print UTF-16. Only ASCII XML tags and the
        // schedule description are read here.
        return Ok(Some(out.stdout.replace('\0', "")));
    }
    let listing = checked(call(run, &["/query", "/fo", "csv", "/nh"].map(OsStr::new))?)?;
    if listing.replace('\0', "").contains(name) {
        return checked(out).map(Some);
    }
    Ok(None)
}

pub(super) fn query(run: Run) -> Result<Option<String>> {
    query_task(&task(&user_sid(run)?), run)
}

pub(super) fn disabled(text: &str) -> bool {
    text.split_once("<Settings>")
        .and_then(|(_, settings)| settings.split_once("</Settings>"))
        .is_some_and(|(settings, _)| settings.contains("<Enabled>false</Enabled>"))
}

/// The desktop launcher the task runs instead of the scanner, when one sits
/// beside it. `wpantry.exe` is a console program, so Task Scheduler opens a
/// console window for it on every run. `wpantry-desktop.exe` is a windowless
/// program; with `--scheduled-run` it starts the scanner's `schedule run`
/// with no console window and exits with its code. A CLI-only install has no
/// launcher and keeps running the scanner directly.
///
/// ```ignore
/// // C:\Users\me\AppData\Local\Pantry\wpantry.exe
/// launcher(program) == Some(r"C:\Users\me\AppData\Local\Pantry\wpantry-desktop.exe".into())
/// ```
pub(super) fn launcher(program: &Path) -> Option<PathBuf> {
    let real = program.canonicalize().unwrap_or_else(|_| program.to_path_buf());
    [program, real.as_path()]
        .into_iter()
        .filter_map(|path| Some(path.parent()?.join("wpantry-desktop.exe")))
        .find(|path| path.is_file())
}

pub(super) fn install(program: &Path, every: Every, at: (u32, u32), run: Run) -> Result<()> {
    let sid = user_sid(run)?;
    let name = task(&sid);
    let tmp = TempDir::new("windows-schedule")?;
    let xml = tmp.path().join("task.xml");
    // schtasks reads an XML file as UTF-16LE. Keep the textual dry run UTF-8.
    let launcher = launcher(program);
    let definition =
        definition(program, launcher.as_deref(), every, at, &sid).replace("encoding=\"UTF-8\"", "encoding=\"UTF-16\"");
    let encoded =
        std::iter::once(0xfeff).chain(definition.encode_utf16()).flat_map(u16::to_le_bytes).collect::<Vec<_>>();
    std::fs::write(&xml, encoded)?;
    let mut args = ["/create", "/tn", &name, "/xml", "", "/f"].map(OsStr::new);
    args[4] = xml.as_os_str();
    checked(call(run, &args)?)?;
    Ok(())
}

pub(super) fn uninstall(run: Run) -> Result<bool> {
    let name = task(&user_sid(run)?);
    if query_task(&name, run)?.is_none() {
        return Ok(false);
    }
    checked(call(run, &["/delete", "/tn", &name, "/f"].map(OsStr::new))?)?;
    Ok(true)
}

/// The task XML. With a `launcher` the task runs it with `--scheduled-run`
/// (no console window), else the scanner with `schedule run`.
pub(super) fn definition(
    program: &Path,
    launcher: Option<&Path>,
    every: Every,
    (hour, minute): (u32, u32),
    sid: &str,
) -> String {
    let start_hour = if every == Every::Hour { 0 } else { hour };
    let daily = "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>";
    let (repetition, schedule) = match every {
        Every::Hour => ("<Repetition><Interval>PT1H</Interval><Duration>P1D</Duration></Repetition>", daily.into()),
        Every::Day => ("", daily.into()),
        Every::Week => (
            "",
            "<ScheduleByWeek><WeeksInterval>1</WeeksInterval><DaysOfWeek><Monday/></DaysOfWeek></ScheduleByWeek>"
                .into(),
        ),
        _ => {
            let months = match every {
                Every::Month => {
                    "<January/><February/><March/><April/><May/><June/><July/><August/><September/><October/><November/><December/>"
                }
                Every::Quarter => "<January/><April/><July/><October/>",
                _ => "<January/>",
            };
            (
                "",
                format!(
                    "<ScheduleByMonth><DaysOfMonth><Day>1</Day></DaysOfMonth><Months>{months}</Months></ScheduleByMonth>"
                ),
            )
        }
    };
    let (command, arguments) = match launcher {
        Some(launcher) => (launcher, "--scheduled-run"),
        None => (program, "schedule run"),
    };
    let path = xml_escape(&wpantry::utils::files::strip_verbatim(&command.to_string_lossy()));
    let every = every.name();
    let user = if sid.is_empty() { String::new() } else { format!("<UserId>{sid}</UserId>") };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Pantry scan {every} {hour:02}:{minute:02}</Description></RegistrationInfo>
  <Triggers><CalendarTrigger>{repetition}<StartBoundary>2024-01-01T{start_hour:02}:{minute:02}:00</StartBoundary>
    <Enabled>true</Enabled>{schedule}</CalendarTrigger></Triggers>
  <Principals><Principal id="User">{user}<LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT4H</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="User"><Exec><Command>{path}</Command><Arguments>{arguments}</Arguments></Exec></Actions>
</Task>
"#
    )
}
