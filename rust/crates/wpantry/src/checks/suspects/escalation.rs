//! Privilege escalation and persistence: a download piped into a shell,
//! setuid bits, sudoers, ssh keys, launch daemons and agents, cron jobs,
//! services, run keys and scheduled tasks, SIP and Gatekeeper off, and
//! plain `sudo`. A shell script that uses sudo is an installer and warns;
//! an npm script, a node or Python file that runs commands, or installed
//! code doing the same fails. A file that runs nothing (website copy that
//! says "run sudo …", a string table) is prose: it cannot escalate, so it
//! isn't read for this at all.

use super::{Context, Kind, Suspect, line_of, push, test_path};

/// The ways a download is piped into a shell.
const DOWNLOADS: &[&str] = &["curl ", "wget "];
/// What the pipe may feed, as the start of the command after `|`.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "sudo sh", "sudo bash", "python", "python3", "node", "perl"];

/// (needle, what it does, strong): a strong one fails wherever the context
/// is strong; a weak one fails only in a manifest.
const ESCALATIONS: &[(&str, &str, bool)] = &[
    ("with administrator privileges", "asks for an admin password through AppleScript", true),
    ("chmod u+s", "sets the setuid bit", true),
    ("chmod +s", "sets the setuid bit", true),
    ("chmod 4755", "sets the setuid bit", true),
    ("/etc/sudoers", "edits sudoers", true),
    ("authorized_keys", "adds an ssh key", true),
    ("/Library/LaunchDaemons", "installs a launch daemon", true),
    ("csrutil disable", "turns off System Integrity Protection", true),
    ("spctl --master-disable", "turns off Gatekeeper", true),
    ("xattr -d com.apple.quarantine", "strips the quarantine flag from a download", true),
    ("Library/LaunchAgents", "installs a launch agent", false),
    ("crontab -", "installs a cron job", false),
    ("systemctl enable", "installs a service", false),
    ("/etc/systemd/system", "installs a service", false),
    ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "installs a Windows run key", true),
    ("schtasks /create", "installs a scheduled task", true),
    ("sudo ", "uses sudo", false),
];

/// Whether the file runs commands at all (a script, not prose in a string).
fn runs_commands(text: &str, ctx: Context) -> bool {
    match ctx {
        Context::Shell | Context::Manifest => true,
        Context::Web => [
            "child_process",
            "execSync(",
            "spawnSync(",
            "spawn(",
            "execFile(",
            "exec(",
            "Deno.run(",
            "Deno.Command(",
            "Bun.spawn(",
            "Bun.$",
        ]
        .iter()
        .any(|s| text.contains(s)),
        Context::Python => [
            "subprocess",
            concat!("os.sys", "tem("),
            concat!("os.po", "pen("),
            "commands.getoutput(",
            "pty.spawn(",
            concat!("sys", "tem("),
            "backtick",
            "`",
        ]
        .iter()
        .any(|s| text.contains(s)),
        // Spelled in pieces so this file, which is Rust, doesn't contain them.
        Context::Native => [
            concat!("sys", "tem("),
            concat!("po", "pen("),
            concat!("exe", "cv"),
            concat!("exe", "cl"),
            concat!("posix_", "spawn"),
            concat!("Command", "::new("),
            concat!("std::", "process"),
            concat!("Process", "Builder"),
            concat!("Runtime.getRuntime()", ".exec("),
            concat!("Process", ".Start("),
            concat!("NS", "Task"),
            concat!("exec.", "Command("),
            concat!("os/", "exec"),
        ]
        .iter()
        .any(|s| text.contains(s)),
        _ => false,
    }
}

pub(super) fn scan(file: &str, text: &str, ctx: Context, kind: Kind, out: &mut Vec<Suspect>) {
    let scripted = runs_commands(text, ctx);
    if !matches!(ctx, Context::Shell | Context::Python | Context::Web | Context::Manifest | Context::Native)
        || !(scripted || kind == Kind::Installed)
    {
        return;
    }
    let strong_ctx = ctx == Context::Manifest || (scripted && ctx != Context::Shell) || kind == Kind::Installed;
    let soft = test_path(file) || ctx == Context::Shell;
    let found = DOWNLOADS
        .iter()
        .find_map(|needle| {
            pipe_to_shell(text, needle)
                .map(|l| (l, format!("pipes a download into a shell (`{}… | sh`)", needle.trim()), strong_ctx))
        })
        .or_else(|| {
            ESCALATIONS.iter().find(|(needle, _, _)| text.contains(needle)).map(|(needle, what, strong)| {
                (
                    line_of(text, needle),
                    format!("{what} (`{}`)", needle.trim()),
                    strong_ctx && (*strong || ctx == Context::Manifest),
                )
            })
        });
    if let Some((line, note, hard)) = found {
        push(out, file, "SUSPECT-PRIV-ESCALATION", line, note, hard && !soft);
    }
}

/// `curl …| sh` and friends: the needle, then a pipe into a shell on the same line.
fn pipe_to_shell(text: &str, needle: &str) -> Option<usize> {
    for (n, line) in text.lines().enumerate() {
        if let Some(i) = line.find(needle) {
            let rest = &line[i..];
            if let Some(p) = rest.find('|') {
                let after = rest[p + 1..].trim_start();
                if SHELLS.iter().any(|s| {
                    after.starts_with(s)
                        && after[s.len()..].chars().next().is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
                }) {
                    return Some(n + 1);
                }
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "escalation_tests.rs"]
mod tests;
