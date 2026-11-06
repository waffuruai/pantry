//! The operating system: which one, its clock, and on Linux the distro
//! `/etc/os-release` names and how its packages are updated.

use super::process::which;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MACOS: bool = cfg!(target_os = "macos");

/// Seconds since the Unix epoch, as Python's `time.time()`.
pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// /etc/os-release as a map (empty off Linux).
pub fn os_release() -> BTreeMap<String, String> {
    std::fs::read_to_string("/etc/os-release").map(|t| parse_os_release(&t)).unwrap_or_default()
}

pub fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    out
}

fn release_ids(rel: &BTreeMap<String, String>) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for key in ["ID", "ID_LIKE"] {
        if let Some(v) = rel.get(key) {
            ids.extend(v.split_whitespace().map(str::to_string));
        }
    }
    ids
}

/// Which source checks this Linux distro's packages: "osv" (the package
/// database and the distro trackers in OSV), "dnf" (dnf's, or yum's, own
/// security advisories), "arch" (the Arch security tracker), or "".
pub fn os_family(rel: &BTreeMap<String, String>) -> &'static str {
    let ids = release_ids(rel);
    let any = |set: &[&str]| ids.iter().any(|i| set.contains(&i.as_str()));
    if any(&[
        "debian",
        "ubuntu",
        "alpine",
        "wolfi",
        "chainguard",
        "opensuse",
        "opensuse-tumbleweed",
        "opensuse-leap",
        "sles",
        "suse",
    ]) {
        "osv"
    } else if any(&["fedora", "rhel", "centos", "rocky", "almalinux", "ol", "amzn"]) {
        "dnf"
    } else if any(&["arch", "archlinux"]) {
        "arch"
    } else {
        ""
    }
}

/// How to update one OS package on this distro.
pub fn os_fix(rel: &BTreeMap<String, String>, name: &str) -> String {
    let ids = release_ids(rel);
    let any = |set: &[&str]| ids.iter().any(|i| set.contains(&i.as_str()));
    if any(&["debian", "ubuntu"]) {
        format!("sudo apt-get update && sudo apt-get install --only-upgrade {name}")
    } else if any(&["alpine", "wolfi", "chainguard"]) {
        format!("sudo apk upgrade {name}")
    } else if ids.iter().any(|i| i.contains("suse")) {
        format!("sudo zypper update {name}")
    } else if any(&["arch", "archlinux"]) {
        "sudo pacman -Syu".to_string() // Arch doesn't support partial upgrades
    } else {
        format!("sudo {} upgrade {name}", if which("dnf").is_some() { "dnf" } else { "yum" })
    }
}

/// Whether the OS update check covers files the OS package manager owns.
pub fn os_vouches() -> bool {
    MACOS || !os_family(&os_release()).is_empty()
}

#[cfg(test)]
#[path = "os_tests.rs"]
mod tests;
