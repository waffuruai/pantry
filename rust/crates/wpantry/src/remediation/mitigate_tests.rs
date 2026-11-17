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
    let done = (stopgap("cve-2026-98432").unwrap().run)(host, &Settings::default(), mode, &|_| yes, &mut |l| {
        lines.push(l.to_string())
    })
    .unwrap();
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
    let err =
        (stopgap(CVE).unwrap().run)(&failing, &Settings::default(), Mode::Apply, &|_| true, &mut |_| {}).unwrap_err();
    assert!(err.to_string().contains("nft -f"), "{err}");
    assert_eq!(failing.did().len(), 2);
}

#[test]
fn a_host_without_nft_is_skipped_unless_asked_and_then_named() {
    let no_nft: Vec<_> = EXPOSED.iter().copied().filter(|(k, _)| *k != "nft --version").collect();
    let host = Fake::new(&no_nft);
    // `wpantry fix --no-input` without --yes: skipped, not failed
    let (done, _) = run(&host, Mode::Apply, false);
    assert_eq!(done, Done::Declined);
    // with a yes the missing tool is the error, and nothing is written
    let err =
        (stopgap(CVE).unwrap().run)(&host, &Settings::default(), Mode::Apply, &|_| true, &mut |_| {}).unwrap_err();
    assert!(err.to_string().contains("install nftables"), "{err}");
    assert!(host.did().is_empty(), "{:?}", host.did());
}

#[test]
fn a_fixed_kernel_needs_nothing_and_other_hosts_are_not_here() {
    let fixed =
        Fake::new(&[("uname -s", "Linux\n"), ("uname -r", "6.12.113\n"), ("id -u", "0\n"), ("nft list ruleset", "")]);
    let (done, lines) = run(&fixed, Mode::DryRun, false);
    assert!(matches!(done, Done::Nothing(ref why) if why.contains("has the fix")), "{done:?}");
    assert!(lines.iter().any(|l| l.contains("✓ kernel 6.12.113 has the")), "{lines:?}");
    assert!(lines.iter().any(|l| l.contains("· rule: not in the ruleset (the kernel doesn't need it)")), "{lines:?}");
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
    assert_eq!(stopgap("CA-TRUST").unwrap().id, "DISTRUSTED-CA", "by name, any case");
    assert_eq!(stopgap("posture-extension-cooldown").unwrap().name, "extension-cooldown", "by finding id");
    assert!(stopgap("ca-trust").unwrap().when_found && !stopgap(CVE).unwrap().when_found);
    assert!(stopgap("CVE-2024-3094").is_none());
    assert!(rules().contains("delete table inet cve_2026_98432"), "idempotent reload");
    assert!(unit().contains("Before=network-pre.target"));
    assert_eq!(name_of("/etc/sysctl.d/90-no-mptcp.conf"), "90-no-mptcp.conf");
}
