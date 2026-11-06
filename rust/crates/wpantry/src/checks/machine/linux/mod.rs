//! Linux: the CIS Distribution Independent Linux items a user can read.
//! Files are read directly where a command would need root.
//!
//! One file per behaviour, each with its probes and their [`Check`]s:
//! [`encryption`] (LUKS), [`firewall`], [`updates`], [`ssh`],
//! [`accounts`] (automatic login, sudo), [`integrity`] (AppArmor or
//! SELinux, PATH), [`kernel`] (CVE-2026-98432), [`mptcp`], [`dns`],
//! [`time`] and [`persistence`]. This file is the index: the checks in
//! report order, and what reading `/etc` takes.

use super::settings::Check;
use std::path::Path;

mod accounts;
mod dns;
mod encryption;
mod firewall;
mod integrity;
mod kernel;
mod mptcp;
pub mod persistence;
mod ssh;
mod time;
mod updates;

pub use kernel::{drops_ip_options, kernel_cve_2026_98432};
pub use mptcp::{MptcpListener, mptcp_listeners, unit_of};

/// The system configuration directory; tests read a copy.
pub(super) const ETC: &str = "/etc";

pub(super) fn text(p: &Path) -> String {
    crate::utils::files::read_capped(p, 1 << 20).unwrap_or_default()
}

/// The checks, in the order the report lists them.
pub static CHECKS: &[Check] = &[
    encryption::DISK_ENCRYPTION,
    firewall::FIREWALL,
    updates::AUTO_UPDATES,
    ssh::SSH_ROOT,
    ssh::SSH_PASSWORDS,
    accounts::AUTO_LOGIN,
    integrity::MAC,
    accounts::SUDO_NOPASSWD,
    integrity::PATH_WRITABLE,
    kernel::KERNEL_TCP_IP_OPTIONS,
    mptcp::MPTCP,
    dns::DNS_ENCRYPTED,
    time::TIME_SYNC,
];

#[cfg(test)]
mod tests;
