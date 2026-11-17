//! The stopgaps `wpantry fix` runs: changes wpantry makes itself, as root
//! where they must be, never by a scan. `wpantry fix ID` (alias `mitigate`)
//! applies the fixes the last scan found for one advisory that may run
//! unattended (a version bump), prints the ones that need a person, and
//! runs the stopgap here when wpantry has one.
//!
//! - `ca-trust` (`DISTRUSTED-CA`): distrust the leaked eMudhra roots in the
//!   system trust store until the OS's ca-certificates update ships
//!   ([`super::ca_trust`]).
//! - `extension-cooldown` (`POSTURE-EXTENSION-COOLDOWN`): every VS
//!   Code-family editor waits before installing a newly published
//!   extension version ([`super::editors`]).
//! - CVE-2026-98432: a change a host can make while the vendor's fix is
//!   still pending.
//!
//! CVE-2026-98432 is the Linux kernel's IPv4 TCP use-after-free (CVSS 9.8),
//! reached through TCP segments that carry IP options, which almost nothing
//! legitimate sends. An nftables rule drops inbound IPv4 TCP whose header
//! is longer than 20 bytes (`ip hdrlength > 5`) before conntrack sees it, a
//! systemd unit reloads it at boot, MPTCP (the public proof of concept's
//! path, and what Go 1.24+ servers listen with) is turned off through
//! sysctl.d, and the services still holding an MPTCP listener are named for
//! a restart: the sysctl only stops new sockets. None of it replaces the
//! kernel update; `Mode::Remove` takes it away once that has landed.
//!
//! Every read and every root write goes through [`Host`], so the tests
//! run the whole thing against a recorded machine.

use crate::checks::machine::linux;
use crate::error::{Error, Result};
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

/// How the stopgap reads and changes the machine.
pub trait Host: Sync {
    /// stdout and stderr of `argv` run as the current user; "" when it
    /// can't run.
    fn read(&self, argv: &[&str]) -> String;
    /// Run `argv` as root (directly when we are, else through sudo on the
    /// terminal, where it prompts); Ok when it exited 0.
    fn root(&self, argv: &[&str]) -> Result<()>;
    /// Write `content` to `path` as root, mode 0644.
    fn write_root(&self, path: &str, content: &str) -> Result<()>;
}

/// The real machine.
pub struct Real;

impl Host for Real {
    fn read(&self, argv: &[&str]) -> String {
        let argv: Vec<&OsStr> = argv.iter().map(OsStr::new).collect();
        crate::utils::process::run(&argv, Duration::from_secs(15))
    }

    fn root(&self, argv: &[&str]) -> Result<()> {
        let shown = argv.join(" ");
        let mut cmd = if self.read(&["id", "-u"]).trim() == "0" {
            let mut c = std::process::Command::new(argv[0]);
            c.args(&argv[1..]);
            c
        } else {
            let mut c = std::process::Command::new("sudo");
            c.args(argv);
            c
        };
        // stdout is not captured: sudo's prompt and nft's errors show on the terminal.
        let status = cmd.status().map_err(|e| Error::Failed(format!("{shown}: {e}")))?;
        if status.success() { Ok(()) } else { Err(Error::Failed(format!("{shown} failed ({status})"))) }
    }

    fn write_root(&self, path: &str, content: &str) -> Result<()> {
        let tmp = std::env::temp_dir().join(format!("wpantry-{}-{}", std::process::id(), name_of(path)));
        std::fs::write(&tmp, content)?;
        let out = self.root(&["install", "-m", "0644", &tmp.to_string_lossy(), path]);
        let _ = std::fs::remove_file(&tmp);
        out
    }
}

fn name_of(path: &str) -> String {
    Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Print what would change; change nothing.
    DryRun,
    Apply,
    /// Take the stopgap away again (the real fix is installed).
    Remove,
}

/// What a stopgap run came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Done {
    /// Changed (or, on a dry run, would change) the machine.
    Applied,
    /// Nothing to change: the fix is in, the stopgap is already in place,
    /// or (on remove) nothing was installed.
    Nothing(String),
    /// This host isn't the kind the stopgap is for.
    NotHere(String),
    /// The person said no (or nobody could answer).
    Declined,
}

/// Asked once, with what is about to be written, before anything changes.
pub type Confirm<'a> = &'a dyn Fn(&str) -> bool;
/// Gets the status lines.
pub type Say<'a> = &'a mut dyn FnMut(&str);

/// What a stopgap may be told: the bundle `ca-trust` rewrites instead of
/// the system store (`--bundle`), and the hours `extension-cooldown` sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub bundle: Option<std::path::PathBuf>,
    pub hours: u32,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { bundle: None, hours: super::editors::COOLDOWN_HOURS }
    }
}

/// A fix wpantry makes itself, by the finding it is for.
pub struct Stopgap {
    /// The finding's `vuln_id` (an advisory, or wpantry's own marker).
    pub id: &'static str,
    /// What to type: `wpantry fix <name>` (the id works too).
    pub name: &'static str,
    /// One line for the help and the report.
    pub what: &'static str,
    /// Run by `wpantry fix` only when the last scan found `id`; otherwise
    /// it checks the host itself.
    pub when_found: bool,
    pub run: fn(&dyn Host, &Settings, Mode, Confirm, Say) -> Result<Done>,
}

pub const STOPGAPS: &[Stopgap] = &[
    Stopgap {
        id: "DISTRUSTED-CA",
        name: "ca-trust",
        what: "distrust the leaked eMudhra roots in the system trust store (sudo asks to install the result) until the OS's ca-certificates update ships",
        when_found: true,
        run: ca_trust,
    },
    Stopgap {
        id: "POSTURE-EXTENSION-COOLDOWN",
        name: "extension-cooldown",
        what: "make every VS Code-family editor wait before installing a newly published extension version (extensions.installCooldownHours)",
        when_found: true,
        run: extension_cooldown,
    },
    Stopgap {
        id: "CVE-2026-98432",
        name: "cve-2026-98432",
        what: "Linux: drop inbound IPv4 TCP with IP options (nftables, reloaded at boot), MPTCP off, the services still listening with MPTCP named for a restart",
        when_found: false,
        run: cve_2026_98432,
    },
];

/// The stopgap for an id or a name, any case.
pub fn stopgap(id: &str) -> Option<&'static Stopgap> {
    let id = id.trim();
    STOPGAPS.iter().find(|s| s.id.eq_ignore_ascii_case(id) || s.name.eq_ignore_ascii_case(id))
}

/// `ca-trust`: the leaked roots distrusted in the system trust store, or in
/// `--bundle`'s PEM file.
fn ca_trust(_: &dyn Host, s: &Settings, mode: Mode, confirm: Confirm, say: Say) -> Result<Done> {
    let store = super::ca_trust::store(s.bundle.as_deref())?;
    match mode {
        Mode::Remove => {
            Ok(Done::Nothing("nothing to undo: the OS's ca-certificates update distrusts the same roots".into()))
        }
        Mode::DryRun => {
            say(&format!("  would distrust the leaked eMudhra roots in {store}"));
            Ok(Done::Applied)
        }
        Mode::Apply => {
            if !confirm(&format!("Distrust the leaked eMudhra roots in {store}")) {
                return Ok(Done::Declined);
            }
            let lines = std::cell::RefCell::new(Vec::new());
            super::ca_trust::fix(s.bundle.as_deref(), &|l| lines.borrow_mut().push(l.to_string()))?;
            for l in lines.into_inner() {
                say(&l);
            }
            Ok(Done::Applied)
        }
    }
}

/// `extension-cooldown`: the cooldown set in every editor's settings.json.
fn extension_cooldown(_: &dyn Host, s: &Settings, mode: Mode, confirm: Confirm, say: Say) -> Result<Done> {
    let editors = crate::checks::machine::any::dev_settings::editor_settings();
    if editors.is_empty() {
        return Ok(Done::NotHere("no VS Code-family editor is installed".into()));
    }
    let short = super::editors::needing(s.hours)?;
    if short.is_empty() {
        return Ok(Done::Nothing(format!("every editor already waits {} hours", s.hours)));
    }
    match mode {
        Mode::Remove => Ok(Done::Nothing("nothing to undo: the setting is the editor's own".into())),
        Mode::DryRun => {
            for (name, file) in &short {
                say(&format!(
                    "  would set extensions.installCooldownHours to {} in {name} ({})",
                    s.hours,
                    file.display()
                ));
            }
            Ok(Done::Applied)
        }
        Mode::Apply => {
            if !confirm(&format!(
                "Set the extension install cooldown to {} hours in {} editor(s)",
                s.hours,
                short.len()
            )) {
                return Ok(Done::Declined);
            }
            for c in super::editors::set_extension_cooldown(s.hours)? {
                say(&format!("  ✓ {c}"));
            }
            say(
                "  Extensions wait that long after a version is published before it installs here (restart the editor).",
            );
            Ok(Done::Applied)
        }
    }
}

const CVE: &str = "CVE-2026-98432";
const TABLE: &str = "cve_2026_98432";
const RULE_FILE: &str = "/etc/nftables-cve-2026-98432.nft";
const UNIT: &str = "cve-2026-98432-stopgap.service";
const UNIT_FILE: &str = "/etc/systemd/system/cve-2026-98432-stopgap.service";
const SYSCTL_FILE: &str = "/etc/sysctl.d/90-no-mptcp.conf";
const MPTCP_FILE: &str = "/proc/sys/net/mptcp/enabled";

/// The rule file: add-then-delete makes `nft -f` idempotent.
fn rules() -> String {
    format!(
        "table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{\n  chain pre {{\n    type filter hook prerouting priority raw - 10; policy accept;\n    ip hdrlength > 5 meta l4proto tcp counter drop comment \"{CVE} stopgap: TCP with IP options\"\n  }}\n}}\n"
    )
}

/// The unit that reloads the rule at boot, before the network comes up.
fn unit() -> String {
    format!(
        "[Unit]\nDescription={CVE} stopgap: drop inbound IPv4 TCP with IP options (nftables)\nDocumentation=https://osv.dev/vulnerability/{CVE}\nDefaultDependencies=no\nBefore=network-pre.target\nWants=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f {RULE_FILE}\nExecStop=/usr/sbin/nft delete table inet {TABLE}\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

/// The programs still holding an MPTCP listening socket, as lines for the
/// report, and the restart commands (never run: a restart interrupts the
/// service, and which ones may be is the operator's call).
fn listeners(host: &dyn Host, say: Say) {
    let r = |argv: &[&str]| host.read(argv);
    let Some(found) = linux::mptcp_listeners(&r) else {
        say(
            "  ⚠ listeners: can't see which programs listen with MPTCP without root (sudo ss -tlnpi | grep -B1 tcp-ulp-mptcp)",
        );
        return;
    };
    if found.is_empty() {
        say("  ✓ listeners: no program holds an MPTCP listening socket");
        return;
    }
    let mut units: Vec<String> = Vec::new();
    let mut by_hand: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for l in &found {
        if l.owners.is_empty() {
            say(&format!("  ⚠ listener: a process on {} (owner needs root: sudo ss -tlnpi)", l.local));
            continue;
        }
        for (name, pid) in &l.owners {
            if seen.contains(pid) {
                continue;
            }
            seen.push(pid.clone());
            match linux::unit_of(&r, pid) {
                Some(u) => {
                    say(&format!("  ⚠ listener: {name} pid {pid} ({u}) on {}", l.local));
                    if !units.contains(&u) {
                        units.push(u);
                    }
                }
                None => {
                    say(&format!("  ⚠ listener: {name} pid {pid} (not a systemd service) on {}", l.local));
                    by_hand.push(format!("{name} pid {pid}"));
                }
            }
        }
    }
    say(
        "  → net.mptcp.enabled=0 only stops new MPTCP sockets; a program that already listens keeps its until restarted. Not run for you:",
    );
    if !units.is_empty() {
        say(&format!("    sudo systemctl restart {}", units.join(" ")));
    }
    for p in by_hand {
        say(&format!("    restart {p} by hand"));
    }
    if units.is_empty() && seen.is_empty() {
        say("    restart each (sudo ss -tlnpi names them)");
    }
}

/// The CVE-2026-98432 stopgap: see the module doc.
fn cve_2026_98432(host: &dyn Host, _: &Settings, mode: Mode, confirm: Confirm, say: Say) -> Result<Done> {
    let os = host.read(&["uname", "-s"]);
    if os.trim() != "Linux" {
        let os = os.trim();
        return Ok(Done::NotHere(format!(
            "a Linux kernel bug; nothing to do on {}",
            if os.is_empty() { "this host" } else { os }
        )));
    }
    let r = |argv: &[&str]| host.read(argv);
    let kernel = linux::kernel_cve_2026_98432(&r);
    let fixed = kernel.as_ref().is_some_and(|(_, fixed, _)| *fixed);
    match &kernel {
        Some((raw, true, _)) => say(&format!("  ✓ kernel {raw} has the {CVE} fix")),
        Some((raw, false, true)) => say(&format!(
            "  ⚠ kernel {raw}: a distro kernel in the affected series; check the vendor's advisory for a backport"
        )),
        Some((raw, false, false)) => say(&format!("  ✗ kernel {raw} is in {CVE}'s affected range")),
        None => say("  ? kernel: uname gave no version"),
    }
    let rule = linux::drops_ip_options(&r);
    match rule {
        Some(true) => say(&format!("  ✓ rule: inbound TCP with IP options is dropped (nft table inet {TABLE})")),
        Some(false) if fixed => say("  · rule: not in the ruleset (the kernel doesn't need it)"),
        Some(false) => say("  ✗ rule: not in the ruleset"),
        None => say(&format!("  ⚠ rule: can't read the ruleset without root (sudo nft list table inet {TABLE})")),
    }
    let mptcp = host.read(&["cat", MPTCP_FILE]);
    let mptcp_built = !mptcp.trim().is_empty();
    match mptcp.trim() {
        "1" => say("  ⚠ mptcp: enabled (net.mptcp.enabled=1); the proof of concept uses it"),
        "0" => say("  ✓ mptcp: off"),
        _ => say("  ✓ mptcp: not built in"),
    }
    if mptcp_built {
        listeners(host, say);
    }

    let unit_there = host.read(&["systemctl", "cat", UNIT]).contains("[Unit]");
    let sysctl_there = host.read(&["cat", SYSCTL_FILE]).contains("mptcp");
    match mode {
        Mode::Remove => {
            if rule != Some(true) && !unit_there && !sysctl_there {
                return Ok(Done::Nothing("the stopgap isn't installed; nothing to remove".into()));
            }
            say(&format!("  → remove: {RULE_FILE} and the nft table, {UNIT_FILE}, {SYSCTL_FILE} (as root)"));
            if !confirm("remove the stopgap") {
                return Ok(Done::Declined);
            }
            if unit_there {
                // stopping the unit runs its ExecStop, which deletes the table itself
                let _ = host.root(&["systemctl", "disable", "--now", UNIT]);
                host.root(&["rm", "-f", UNIT_FILE])?;
                host.root(&["systemctl", "daemon-reload"])?;
            }
            host.root(&["rm", "-f", RULE_FILE])?;
            // so the table is deleted here only when it is still there (checked again after the stop)
            if rule == Some(true) && (!unit_there || linux::drops_ip_options(&r) == Some(true)) {
                host.root(&["nft", "delete", "table", "inet", TABLE])?;
            }
            if sysctl_there {
                host.root(&["rm", "-f", SYSCTL_FILE])?;
                let _ = host.root(&["sysctl", "-q", "-w", "net.mptcp.enabled=1"]);
            }
            say(&format!("  ✓ removed; the kernel is exposed to {CVE} again unless it has the fix"));
            Ok(Done::Applied)
        }
        Mode::DryRun | Mode::Apply => {
            if fixed && rule == Some(true) {
                return Ok(Done::Nothing("the kernel has the fix and the stopgap is still in place: wpantry fix CVE-2026-98432 --undo takes it away".into()));
            }
            if fixed {
                return Ok(Done::Nothing("the kernel has the fix; the stopgap isn't needed".into()));
            }
            if rule == Some(true) && unit_there && (!mptcp_built || mptcp.trim() == "0") {
                return Ok(Done::Nothing(format!(
                    "the stopgap is already in place. Update the kernel when the fix ships, then: wpantry fix {CVE} --undo"
                )));
            }
            let verb = if mode == Mode::DryRun { "would write" } else { "will write" };
            say(&format!("  → {verb} {RULE_FILE}:"));
            for l in rules().lines() {
                say(&format!("      {l}"));
            }
            say(&format!("  → {verb} {UNIT_FILE} and: systemctl daemon-reload && systemctl enable --now {UNIT}"));
            if mptcp_built {
                say(&format!("  → {verb} {SYSCTL_FILE} (net.mptcp.enabled = 0) and: sysctl -w net.mptcp.enabled=0"));
            }
            if mode == Mode::DryRun {
                say("  dry run; nothing changed");
                return Ok(Done::Applied);
            }
            // Asked first: a stopgap nobody said yes to (`--no-input` without
            // `--yes`) is skipped, so a host without nft is not a failure.
            if !confirm("apply the stopgap (as root)") {
                return Ok(Done::Declined);
            }
            if host.read(&["nft", "--version"]).trim().is_empty() {
                return Err(Error::Missing(
                    "nft (install nftables: sudo apt install nftables, or sudo dnf install nftables)".into(),
                ));
            }
            host.write_root(RULE_FILE, &rules())?;
            host.root(&["nft", "-f", RULE_FILE])?;
            say(&format!("  ✓ rule loaded: nft list table inet {TABLE}"));
            if host.read(&["systemctl", "--version"]).trim().is_empty() {
                say(&format!(
                    "  ⚠ no systemd: add 'nft -f {RULE_FILE}' to your own network start so the rule comes back at boot"
                ));
            } else {
                host.write_root(UNIT_FILE, &unit())?;
                host.root(&["systemctl", "daemon-reload"])?;
                // --now runs the same nft -f (idempotent), so the unit shows active and --undo has something to stop.
                host.root(&["systemctl", "enable", "--quiet", "--now", UNIT])?;
                say(&format!("  ✓ {UNIT} enabled and active: the rule comes back at boot"));
            }
            if mptcp_built {
                host.write_root(SYSCTL_FILE, "net.mptcp.enabled = 0\n")?;
                host.root(&["sysctl", "-q", "-w", "net.mptcp.enabled=0"])?;
                say(&format!("  ✓ MPTCP off ({SYSCTL_FILE})"));
            }
            say(&format!("  stopgap in place. Update the kernel when the fix ships, then: wpantry fix {CVE} --undo"));
            Ok(Done::Applied)
        }
    }
}

#[cfg(test)]
#[path = "mitigate_tests.rs"]
mod tests;
