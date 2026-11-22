//! Stand-ins for system tools (macOS and Linux only), and POSIX quoting for
//! the fix commands the suite stores in the cache.

/// A stand-in launchctl that remembers whether the job is loaded, in a file
/// beside it: bootstrap loads it, bootout unloads it, and print fails once
/// it is gone, as the real one does. A `.bootout-fails` file beside it makes
/// bootout fail. It never reaches the real user's jobs.
#[cfg(unix)]
pub const LAUNCHCTL: &str = r#"#!/bin/sh
state="$(dirname "$0")/.launchd-job"
case "$1" in
  bootstrap) echo loaded > "$state" ;;
  bootout) [ -e "$(dirname "$0")/.bootout-fails" ] && { echo "Boot-out failed: 5: Input/output error" >&2; exit 5; }
           echo gone > "$state" ;;
  print) grep -qx loaded "$state" 2>/dev/null || exit 113 ;;
esac
exit 0
"#;

#[cfg(unix)]
pub fn write_script(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod a stand-in");
}

/// Stand-ins that record their arguments in `log`. Dialog tools and
/// schedulers must never reach the real desktop or the real user's jobs.
#[cfg(unix)]
pub fn fake_tools(folder: &std::path::Path, names: &[&str], log: &std::path::Path) {
    std::fs::create_dir(folder).expect("create the tools folder");
    for name in names {
        let record = format!(
            "printf \"%s\\n\" \"{name} $*\" >> {}\n",
            quote(&log.display().to_string())
        );
        let body = if *name == "launchctl" {
            LAUNCHCTL.replacen("#!/bin/sh\n", &format!("#!/bin/sh\n{record}"), 1)
        } else {
            format!("#!/bin/sh\n{record}exit 0\n")
        };
        write_script(&folder.join(name), &body);
    }
}

/// One word for a POSIX shell, as Python's `shlex.quote`: bare when it is
/// only safe characters, else single-quoted.
pub fn quote(word: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "@%+=:,./-_".contains(c);
    if !word.is_empty() && word.chars().all(safe) {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\"'\"'"))
    }
}

/// Words joined for a POSIX shell, as `shlex.join`.
pub fn join(words: &[&str]) -> String {
    words.iter().map(|w| quote(w)).collect::<Vec<_>>().join(" ")
}

/// The fix command that creates `path`: the stand-in's `__touch`, which the
/// real scanner runs like any automatic fix.
pub fn touch_command(path: &std::path::Path) -> String {
    let standin = crate::harness::standin();
    join(&[
        &standin.display().to_string(),
        "__touch",
        &path.display().to_string(),
    ])
}

pub fn quote_rejects_known_bad() {
    // Known-bad case: a path with a space or a quote must not split.
    assert_eq!(quote("plain/path-1.0"), "plain/path-1.0");
    assert_eq!(quote("patch ran"), "'patch ran'");
    assert_eq!(quote("it's"), "'it'\"'\"'s'");
    assert_eq!(quote(""), "''");
}
