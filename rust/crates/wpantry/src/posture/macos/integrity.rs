//! What keeps the system itself trustworthy: Gatekeeper, System Integrity
//! Protection, the boot policy, and Lockdown Mode.

use super::super::{Check, Outcome, Runner, Severity, admin, flag};
use super::read;

fn gatekeeper(r: Runner) -> Outcome {
    let out = r(&["spctl", "--status"]);
    let line = out.lines().find(|l| l.contains("assessments")).unwrap_or("").trim();
    if line.contains("assessments enabled") {
        Outcome::pass(line)
    } else if line.contains("assessments disabled") {
        Outcome::fail(line)
    } else {
        Outcome::unknown("spctl gave no answer")
    }
}

fn sip(r: Runner) -> Outcome {
    let out = r(&["csrutil", "status"]);
    let line = out.lines().next().unwrap_or("").trim();
    if line.contains("status: enabled") {
        Outcome::pass(line)
    } else if line.contains("status: disabled") || line.contains("status: unknown") {
        Outcome::fail(line)
    } else {
        Outcome::unknown("csrutil gave no answer")
    }
}

/// The boot security policy: Full Security boots only the current, signed
/// macOS. `bputil -d` reads it as root; `system_profiler` shows it to
/// anyone on Apple silicon and T2 Macs.
fn secure_boot(r: Runner) -> Outcome {
    let policy = r(&["bputil", "-d"]);
    let mode = policy
        .lines()
        .find(|l| l.trim_start().starts_with("Security Mode"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.split_whitespace().next().unwrap_or("").to_string())
        .or_else(|| {
            r(&["system_profiler", "SPiBridgeDataType"])
                .lines()
                .find_map(|l| l.trim().strip_prefix("Secure Boot:"))
                .map(|v| v.trim().trim_end_matches(" Security").to_string())
        });
    match mode.as_deref() {
        Some("Full") => Outcome::pass("Secure Boot: Full Security"),
        Some(m @ ("Reduced" | "Medium")) => Outcome::manual(format!(
            "Secure Boot: {m} Security, which allows third-party kernel extensions or older macOS; keep it only for a kext you need"
        )),
        Some(m @ ("Permissive" | "No")) => Outcome::fail(format!("Secure Boot: {m} Security")),
        Some(m) if !m.is_empty() => Outcome::unknown(format!("Secure Boot reads {m}")),
        _ => Outcome::unknown(
            "neither bputil -d (root) nor system_profiler shows a boot policy (an Intel Mac without a T2 has none)",
        ),
    }
}

fn lockdown(r: Runner) -> Outcome {
    match flag(&read(r, ".GlobalPreferences", "LDMGlobalEnabled")) {
        Some(true) => Outcome::pass("Lockdown Mode is on"),
        _ => Outcome::manual("Lockdown Mode is off (for people at risk of targeted attacks)"),
    }
}

pub(super) const GATEKEEPER: Check = Check {
    id: "POSTURE-GATEKEEPER",
    cis: "2.6.5",
    title: "Gatekeeper",
    severity: Severity::High,
    probe: gatekeeper,
    fix: admin("System Settings → Privacy & Security → Allow applications from: App Store & Known Developers"),
    explain: "Unsigned and unnotarized apps are blocked from running",
};

pub(super) const SIP: Check = Check {
    id: "POSTURE-SIP",
    cis: "5.1.1",
    title: "System Integrity Protection",
    severity: Severity::Critical,
    probe: sip,
    fix: admin("Restart into Recovery (hold the power button), open Terminal, run: csrutil enable"),
    explain: "System files and processes are protected from root",
};

pub(super) const SECURE_BOOT: Check = Check {
    id: "POSTURE-SECURE-BOOT",
    cis: "",
    title: "Secure Boot at Full Security",
    severity: Severity::High,
    probe: secure_boot,
    fix: admin("Restart into Recovery, open Startup Security Utility and choose Full Security"),
    explain: "Only the current, Apple-signed macOS boots, without third-party kernel extensions",
};

pub(super) const LOCKDOWN: Check = Check {
    id: "POSTURE-LOCKDOWN",
    cis: "2.6.7",
    title: "Lockdown Mode (advisory)",
    severity: Severity::Low,
    probe: lockdown,
    fix: None,
    explain: "For people who may be targeted: System Settings → Privacy & Security → Lockdown Mode",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::Status;
    use crate::posture::testing::machine;

    #[test]
    fn reduced_security_is_a_choice_not_a_failure() {
        // Reduced Security is a choice some kexts need: a warning, not a failure.
        let reduced = secure_boot(&machine(&[("SPiBridgeDataType", "        Secure Boot: Reduced Security\n")]));
        assert_eq!(reduced.status, Status::Manual);
    }
}
