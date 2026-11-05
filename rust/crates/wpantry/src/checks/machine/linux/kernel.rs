//! The running kernel against CVE-2026-98432, and the stopgap that drops
//! inbound TCP with IP options.

use crate::checks::machine::settings::{Check, Outcome, Runner, Severity, admin};

/// A kernel version as (major, minor, patch).
type Kernel = (u64, u64, u64);

/// `uname -r` as (major, minor, patch); distro suffixes are dropped.
fn kernel_version(r: Runner) -> Option<(u64, u64, u64, String)> {
    let raw = r(&["uname", "-r"]).trim().to_string();
    let core: String = raw.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let (a, b, c) = (it.next()??, it.next()??, it.next().flatten().unwrap_or(0));
    Some((a, b, c, raw))
}

/// Whether a kernel version lies in any of the (introduced, fixed) ranges.
fn in_ranges(v: Kernel, ranges: &[(Kernel, Kernel)]) -> bool {
    ranges.iter().any(|(lo, hi)| v >= *lo && v < *hi)
}

/// CVE-2026-98432 (CVSS 9.8): an IPv4 TCP use-after-free since 4.4, fixed
/// in the stable series below (OSV, 2026-10-30). Distro kernels carry
/// backports under their own numbering, so a distro kernel is judged by
/// the mitigation, with a note to check the vendor's advisory.
const CVE_2026_98432_FIXED: &[(Kernel, Kernel)] = &[
    ((4, 4, 0), (5, 10, 272)),
    ((5, 11, 0), (5, 15, 223)),
    ((5, 16, 0), (6, 1, 190)),
    ((6, 2, 0), (6, 6, 159)),
    ((6, 7, 0), (6, 12, 113)),
    ((6, 13, 0), (6, 18, 56)),
    ((6, 19, 0), (7, 2, 10)),
];

/// Whether a rule drops inbound TCP with IP options. `nft list ruleset` and `iptables -S` need root
/// and print nothing without it (so does an empty ruleset), so the read happens as root, or through
/// `sudo -n` (which fails rather than prompts); `None` when neither is available.
pub fn drops_ip_options(r: Runner) -> Option<bool> {
    let root = r(&["id", "-u"]).trim() == "0";
    let (nft, ipt) = if root {
        (r(&["nft", "list", "ruleset"]), r(&["iptables", "-S"]))
    } else if r(&["sudo", "-n", "id", "-u"]).trim() == "0" {
        (r(&["sudo", "-n", "nft", "list", "ruleset"]), r(&["sudo", "-n", "iptables", "-S"]))
    } else {
        return None;
    };
    let nft_rule = nft.contains("hdrlength > 5") && nft.contains("drop");
    let ipt_rule = ipt.contains("ipv4options") && ipt.contains("DROP");
    Some(nft_rule || ipt_rule)
}

/// The running kernel against CVE-2026-98432: its version string, whether
/// an upstream kernel of that version has the fix, and whether it is a
/// distro kernel (a backport under its own numbering: check the vendor's
/// advisory). None when uname gave nothing.
pub fn kernel_cve_2026_98432(r: Runner) -> Option<(String, bool, bool)> {
    let (a, b, c, raw) = kernel_version(r)?;
    let distro = raw.contains('-') && !raw.ends_with("-generic-upstream");
    Some((raw, !in_ranges((a, b, c), CVE_2026_98432_FIXED), distro))
}

fn tcp_ip_options(r: Runner) -> Outcome {
    let Some((raw, fixed, distro)) = kernel_cve_2026_98432(r) else {
        return Outcome::unknown("uname gave no kernel version");
    };
    if fixed {
        return Outcome::pass(if drops_ip_options(r) == Some(true) {
            format!(
                "kernel {raw} has the fix for CVE-2026-98432; the stopgap is still in place (wpantry mitigate CVE-2026-98432 --undo takes it away)"
            )
        } else {
            format!("kernel {raw} has the fix for CVE-2026-98432")
        });
    }
    match drops_ip_options(r) {
        Some(true) => {
            return Outcome::pass(format!(
                "kernel {raw}: inbound TCP with IP options is dropped (CVE-2026-98432 stopgap in place); update the kernel when the fix ships"
            ));
        }
        None => {
            return Outcome::manual(format!(
                "kernel {raw} is in CVE-2026-98432's affected range and the ruleset can't be read here (nft needs root): sudo nft list table inet cve_2026_98432, or wpantry mitigate CVE-2026-98432 --dry-run"
            ));
        }
        Some(false) => {}
    }
    if distro {
        Outcome::fail(format!(
            "kernel {raw} (a distro kernel: check the vendor's advisory for a backport) and no stopgap for CVE-2026-98432"
        ))
    } else {
        Outcome::fail(format!("kernel {raw} is in CVE-2026-98432's affected range and no stopgap is in place"))
    }
}

pub(super) const KERNEL_TCP_IP_OPTIONS: Check = Check {
    id: "POSTURE-KERNEL-TCP-IP-OPTIONS",
    cis: "",
    title: "Kernel patched for CVE-2026-98432, or inbound TCP with IP options dropped",
    severity: Severity::Critical,
    probe: tcp_ip_options,
    fix: admin(
        "Update the kernel when your distro ships the fix (upstream 5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56, 7.2.10); until then drop inbound TCP with IP options: sudo nft add table inet cve_2026_98432 && sudo nft 'add chain inet cve_2026_98432 pre { type filter hook prerouting priority raw - 10; policy accept; }' && sudo nft add rule inet cve_2026_98432 pre ip hdrlength gt 5 meta l4proto tcp counter drop  (wpantry mitigate CVE-2026-98432 persists it, turns MPTCP off and names the services to restart)",
    ),
    explain: "An unauthenticated remote root through a race in TCP's handshake; packets without IP options can't reach it",
};

#[cfg(test)]
#[path = "kernel_tests.rs"]
mod tests;
