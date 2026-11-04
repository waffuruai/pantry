//! `wpantry mitigate <ID>`: what this host can do about one advisory. The
//! CLI applies the fixes the last scan found for it that may run
//! unattended (a version bump), prints the ones that need a person, and
//! runs the stopgap here when wpantry has one: a change a host can make
//! while the vendor's fix is still pending, written as root, never by a
//! scan. The first is CVE-2026-98432's: the Linux kernel's IPv4 TCP
//! use-after-free (CVSS 9.8), reached through TCP segments that carry IP
//! options, which almost nothing legitimate sends. An nftables rule drops
//! inbound IPv4 TCP whose header is longer than 20 bytes (`ip hdrlength >
//! 5`) before conntrack sees it, a systemd unit reloads it at boot, MPTCP
//! (the public proof of concept's path, and what Go 1.24+ servers listen
//! with) is turned off through sysctl.d, and the services still holding an
//! MPTCP listener are named for a restart: the sysctl only stops new
//! sockets. None of it replaces the kernel update; `Mode::Remove` takes
//! it away once that has landed.
//!
//! Every read and every root write goes through [`Host`], so the tests
//! run the whole thing against a recorded machine.

use crate::error::{Error, Result};
use crate::posture::linux;
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

/// A stopgap wpantry can install, by advisory id.
pub struct Stopgap {
    pub id: &'static str,
    /// One line for the help and the report.
    pub what: &'static str,
    pub run: fn(&dyn Host, Mode, Confirm, Say) -> Result<Done>,
}

pub const STOPGAPS: &[Stopgap] = &[Stopgap {
    id: "CVE-2026-98432",
    what: "Linux: drop inbound IPv4 TCP with IP options (nftables, reloaded at boot), MPTCP off, the services still listening with MPTCP named for a restart",
    run: cve_2026_98432,
}];

/// The stopgap for an advisory id, any case.
pub fn stopgap(id: &str) -> Option<&'static Stopgap> {
    STOPGAPS.iter().find(|s| s.id.eq_ignore_ascii_case(id.trim()))
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
fn cve_2026_98432(host: &dyn Host, mode: Mode, confirm: Confirm, say: Say) -> Result<Done> {
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
                return Ok(Done::Nothing("the kernel has the fix and the stopgap is still in place: wpantry mitigate CVE-2026-98432 --undo takes it away".into()));
            }
            if fixed {
                return Ok(Done::Nothing("the kernel has the fix; the stopgap isn't needed".into()));
            }
            if rule == Some(true) && unit_there && (!mptcp_built || mptcp.trim() == "0") {
                return Ok(Done::Nothing(format!(
                    "the stopgap is already in place. Update the kernel when the fix ships, then: wpantry mitigate {CVE} --undo"
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
            if host.read(&["nft", "--version"]).trim().is_empty() {
                return Err(Error::Missing(
                    "nft (install nftables: sudo apt install nftables, or sudo dnf install nftables)".into(),
                ));
            }
            if !confirm("apply the stopgap (as root)") {
                return Ok(Done::Declined);
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
            say(&format!(
                "  stopgap in place. Update the kernel when the fix ships, then: wpantry mitigate {CVE} --undo"
            ));
            Ok(Done::Applied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A recorded machine: reads answered by the first matching key, root
    /// writes recorded. A key listed in `once` answers only until a root
    /// command has run (the unit's stop deleting the table).
    struct Fake {
        answers: Vec<(&'static str, &'static str)>,
        root: Mutex<Vec<String>>,
        fail: Option<&'static str>,
        once: &'static [&'static str],
    }

    impl Fake {
        fn new(answers: &[(&'static str, &'static str)]) -> Fake {
            Fake { answers: answers.to_vec(), root: Mutex::new(Vec::new()), fail: None, once: &[] }
        }
        fn did(&self) -> Vec<String> {
            self.root.lock().unwrap().clone()
        }
    }

    impl Host for Fake {
        fn read(&self, argv: &[&str]) -> String {
            let joined = argv.join(" ");
            let acted = !self.root.lock().unwrap().is_empty();
            self.answers
                .iter()
                .find(|(k, _)| joined.contains(k) && !(acted && self.once.contains(k)))
                .map(|(_, v)| v.to_string())
                .unwrap_or_default()
        }
        fn root(&self, argv: &[&str]) -> Result<()> {
            let joined = argv.join(" ");
            self.root.lock().unwrap().push(joined.clone());
            match self.fail {
                Some(f) if joined.contains(f) => Err(Error::Failed(format!("{joined} failed"))),
                _ => Ok(()),
            }
        }
        fn write_root(&self, path: &str, content: &str) -> Result<()> {
            self.root.lock().unwrap().push(format!("write {path}: {}", content.lines().next().unwrap_or("")));
            Ok(())
        }
    }

    fn run(host: &Fake, mode: Mode, yes: bool) -> (Done, Vec<String>) {
        let mut lines = Vec::new();
        let done =
            (stopgap("cve-2026-98432").unwrap().run)(host, mode, &|_| yes, &mut |l| lines.push(l.to_string())).unwrap();
        (done, lines)
    }

    const SS_K3S: &str = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\nLISTEN 0      4096         *:6443             *:*     users:((\"k3s-server\",pid=392498,fd=17))\n\t cubic cwnd:10 tcp-ulp-mptcp\nLISTEN 0      4096         *:4317             *:*     users:((\"alloy\",pid=198948,fd=9))\n\t cubic cwnd:10 tcp-ulp-mptcp\n";

    const EXPOSED: &[(&str, &str)] = &[
        ("uname -s", "Linux\n"),
        ("uname -r", "6.8.0-45-generic\n"),
        ("id -u", "0\n"),
        ("nft --version", "nftables v1.0.9\n"),
        ("nft list ruleset", "table inet filter {\n}\n"),
        ("systemctl --version", "systemd 255\n"),
        ("mptcp/enabled", "1\n"),
        ("ss -tlnpi", SS_K3S),
        ("/proc/392498/cgroup", "0::/system.slice/k3s.service\n"),
        ("/proc/198948/cgroup", "0::/system.slice/alloy.service\n"),
    ];

    #[test]
    fn a_dry_run_prints_the_plan_and_the_restarts_and_changes_nothing() {
        let host = Fake::new(EXPOSED);
        let (done, lines) = run(&host, Mode::DryRun, false);
        assert_eq!(done, Done::Applied);
        let text = lines.join("\n");
        assert!(text.contains("⚠ kernel 6.8.0-45-generic: a distro kernel"), "{text}");
        assert!(text.contains("✗ rule: not in the ruleset"), "{text}");
        assert!(text.contains("⚠ mptcp: enabled"), "{text}");
        assert!(text.contains("⚠ listener: k3s-server pid 392498 (k3s.service) on *:6443"), "{text}");
        assert!(text.contains("sudo systemctl restart k3s.service alloy.service"), "{text}");
        assert!(text.contains("would write /etc/nftables-cve-2026-98432.nft"), "{text}");
        assert!(text.contains("ip hdrlength > 5 meta l4proto tcp counter drop"), "{text}");
        assert!(text.contains("would write /etc/systemd/system/cve-2026-98432-stopgap.service"), "{text}");
        assert!(text.contains("would write /etc/sysctl.d/90-no-mptcp.conf"), "{text}");
        assert!(text.contains("dry run; nothing changed"), "{text}");
        assert!(host.did().is_empty(), "{:?}", host.did());
    }

    #[test]
    fn apply_writes_the_rule_the_unit_and_the_sysctl_after_a_yes() {
        let host = Fake::new(EXPOSED);
        let (done, _) = run(&host, Mode::Apply, false);
        assert_eq!(done, Done::Declined);
        assert!(host.did().is_empty());
        let (done, lines) = run(&host, Mode::Apply, true);
        assert_eq!(done, Done::Applied);
        assert_eq!(
            host.did(),
            [
                "write /etc/nftables-cve-2026-98432.nft: table inet cve_2026_98432",
                "nft -f /etc/nftables-cve-2026-98432.nft",
                "write /etc/systemd/system/cve-2026-98432-stopgap.service: [Unit]",
                "systemctl daemon-reload",
                "systemctl enable --quiet --now cve-2026-98432-stopgap.service",
                "write /etc/sysctl.d/90-no-mptcp.conf: net.mptcp.enabled = 0",
                "sysctl -q -w net.mptcp.enabled=0",
            ]
        );
        let text = lines.join("\n");
        assert!(text.contains("✓ MPTCP off"), "{text}");
        assert!(text.contains("Not run for you:\n    sudo systemctl restart k3s.service alloy.service"), "{text}");
        assert!(text.contains("--undo"), "{text}");
        // a failed step is an error, and nothing after it runs
        let mut failing = Fake::new(EXPOSED);
        failing.fail = Some("nft -f");
        let err = (stopgap(CVE).unwrap().run)(&failing, Mode::Apply, &|_| true, &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("nft -f"), "{err}");
        assert_eq!(failing.did().len(), 2);
    }

    #[test]
    fn a_fixed_kernel_needs_nothing_and_other_hosts_are_not_here() {
        let fixed = Fake::new(&[
            ("uname -s", "Linux\n"),
            ("uname -r", "6.12.113\n"),
            ("id -u", "0\n"),
            ("nft list ruleset", ""),
        ]);
        let (done, lines) = run(&fixed, Mode::DryRun, false);
        assert!(matches!(done, Done::Nothing(ref why) if why.contains("has the fix")), "{done:?}");
        assert!(lines.iter().any(|l| l.contains("✓ kernel 6.12.113 has the")), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("· rule: not in the ruleset (the kernel doesn't need it)")),
            "{lines:?}"
        );
        // fixed but the stopgap is still there: say how to take it away
        let stale = Fake::new(&[
            ("uname -s", "Linux\n"),
            ("uname -r", "6.12.113\n"),
            ("id -u", "0\n"),
            (
                "nft list ruleset",
                "table inet cve_2026_98432 {\n\tchain pre {\n\t\tip hdrlength > 5 meta l4proto tcp counter packets 0 bytes 0 drop\n\t}\n}\n",
            ),
        ]);
        let (done, _) = run(&stale, Mode::Apply, true);
        assert!(matches!(done, Done::Nothing(ref why) if why.contains("--undo")), "{done:?}");
        assert!(stale.did().is_empty());
        let mac = Fake::new(&[("uname -s", "Darwin\n")]);
        let (done, _) = run(&mac, Mode::Apply, true);
        assert_eq!(done, Done::NotHere("a Linux kernel bug; nothing to do on Darwin".into()));
        assert!(mac.did().is_empty());
        // an exposed kernel with no root and no sudo: the ruleset and the listeners are reported as unreadable
        let user = Fake::new(&[
            ("uname -s", "Linux\n"),
            ("uname -r", "6.8.0-45-generic\n"),
            ("id -u", "1000\n"),
            ("mptcp/enabled", "0\n"),
            ("modprobe -n mptcp_diag", "modprobe: FATAL: Module mptcp_diag not found\n"),
        ]);
        let (_, lines) = run(&user, Mode::DryRun, false);
        assert!(lines.iter().any(|l| l.contains("⚠ rule: can't read the ruleset without root")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("⚠ listeners: can't see")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("distro kernel")), "{lines:?}");
    }

    #[test]
    fn an_installed_stopgap_is_reported_not_rewritten() {
        let installed = Fake::new(&[
            ("uname -s", "Linux\n"),
            ("uname -r", "6.8.0-45-generic\n"),
            ("id -u", "0\n"),
            (
                "nft list ruleset",
                "table inet cve_2026_98432 {\n\tchain pre {\n\t\tip hdrlength > 5 meta l4proto tcp counter packets 0 bytes 0 drop\n\t}\n}\n",
            ),
            ("systemctl cat", "[Unit]\nDescription=…\n"),
            ("mptcp/enabled", "0\n"),
            ("ss -tlnpi", "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"),
        ]);
        let (done, _) = run(&installed, Mode::Apply, true);
        assert!(matches!(done, Done::Nothing(ref why) if why.contains("already in place")), "{done:?}");
        assert!(installed.did().is_empty());
        // MPTCP turned back on since: the sysctl is written again
        let reenabled = Fake::new(&[
            ("uname -s", "Linux\n"),
            ("uname -r", "6.8.0-45-generic\n"),
            ("id -u", "0\n"),
            ("nft --version", "nftables v1.0.9\n"),
            (
                "nft list ruleset",
                "table inet cve_2026_98432 {\n\tchain pre {\n\t\tip hdrlength > 5 meta l4proto tcp counter packets 0 bytes 0 drop\n\t}\n}\n",
            ),
            ("systemctl cat", "[Unit]\nDescription=…\n"),
            ("systemctl --version", "systemd 255\n"),
            ("mptcp/enabled", "1\n"),
            ("ss -tlnpi", "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"),
        ]);
        let (done, _) = run(&reenabled, Mode::Apply, true);
        assert_eq!(done, Done::Applied);
        assert!(reenabled.did().iter().any(|c| c == "sysctl -q -w net.mptcp.enabled=0"), "{:?}", reenabled.did());
    }

    #[test]
    fn remove_takes_the_stopgap_away_and_is_a_no_op_without_it() {
        let installed = Fake::new(&[
            ("uname -s", "Linux\n"),
            ("uname -r", "6.8.0-45-generic\n"),
            ("id -u", "0\n"),
            (
                "nft list ruleset",
                "table inet cve_2026_98432 {\n\tchain pre {\n\t\tip hdrlength > 5 meta l4proto tcp counter packets 0 bytes 0 drop\n\t}\n}\n",
            ),
            ("systemctl cat", "[Unit]\nDescription=…\n"),
            ("/etc/sysctl.d/90-no-mptcp.conf", "net.mptcp.enabled = 0\n"),
            ("mptcp/enabled", "0\n"),
            ("ss -tlnpi", "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"),
        ]);
        let (done, lines) = run(&installed, Mode::Remove, true);
        assert_eq!(done, Done::Applied);
        assert_eq!(
            installed.did(),
            [
                "systemctl disable --now cve-2026-98432-stopgap.service",
                "rm -f /etc/systemd/system/cve-2026-98432-stopgap.service",
                "systemctl daemon-reload",
                "rm -f /etc/nftables-cve-2026-98432.nft",
                "nft delete table inet cve_2026_98432",
                "rm -f /etc/sysctl.d/90-no-mptcp.conf",
                "sysctl -q -w net.mptcp.enabled=1",
            ]
        );
        assert!(lines.iter().any(|l| l.contains("✓ listeners: no program holds")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("✓ removed")), "{lines:?}");
        // the unit's ExecStop already deleted the table: no second delete, which would fail
        let mut stopped = Fake::new(&[
            ("uname -s", "Linux\n"),
            ("uname -r", "6.8.0-45-generic\n"),
            ("id -u", "0\n"),
            (
                "nft list ruleset",
                "table inet cve_2026_98432 {\n\tchain pre {\n\t\tip hdrlength > 5 meta l4proto tcp counter packets 0 bytes 0 drop\n\t}\n}\n",
            ),
            ("systemctl cat", "[Unit]\nDescription=…\n"),
            ("mptcp/enabled", "0\n"),
        ]);
        stopped.once = &["nft list ruleset"];
        let (done, _) = run(&stopped, Mode::Remove, true);
        assert_eq!(done, Done::Applied);
        assert!(!stopped.did().iter().any(|c| c.starts_with("nft delete")), "{:?}", stopped.did());
        let bare = Fake::new(&[
            ("uname -s", "Linux\n"),
            ("uname -r", "6.8.0-45-generic\n"),
            ("id -u", "0\n"),
            ("nft list ruleset", ""),
        ]);
        let (done, _) = run(&bare, Mode::Remove, true);
        assert!(matches!(done, Done::Nothing(ref why) if why.contains("nothing to remove")), "{done:?}");
        assert!(bare.did().is_empty());
    }

    #[test]
    fn the_registry_and_the_files() {
        assert_eq!(stopgap("cve-2026-98432").unwrap().id, "CVE-2026-98432");
        assert!(stopgap("CVE-2024-3094").is_none());
        assert!(rules().contains("delete table inet cve_2026_98432"), "idempotent reload");
        assert!(unit().contains("Before=network-pre.target"));
        assert_eq!(name_of("/etc/sysctl.d/90-no-mptcp.conf"), "90-no-mptcp.conf");
    }
}
