//! wscanner: inventory this machine and its git repos, check only what is
//! installed or locked against OSV.dev, CISA KEV and endoflife.date, and
//! cache the answers in a local SQLite database shared with the Python
//! implementation.
//!
//! The library has no global state and never prints: progress goes through
//! the `log` callback a [`check::Scan`] is given, and the CLI owns stdout,
//! stderr and exit codes. Modules map onto `python/wscanner/` one to one, so
//! a parity diff can be traced to a file. The stable surface is the CLI
//! contract (`specs/cli-contract.md`), not this crate's API.

pub mod check;
pub mod check_machine;
pub mod check_supply;
pub mod compare;
pub mod db;
pub mod distros;
pub mod error;
pub mod feeds;
pub mod harnesses;
pub mod json;
pub mod leaks;
pub mod lockfiles;
pub mod malicious;
pub mod net;
pub mod osdb;
pub mod osv;
pub mod repos;
pub mod sha256;
pub mod system;
pub mod tools;
pub mod versions;

pub use error::Error;

/// The implementation's version (the Python one is the same, 0.1.0).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Which implementation this is, in every JSON envelope.
pub const IMPL: &str = "rust";
/// The CLI contract's JSON schema (`specs/cli-contract.md`).
pub const SCHEMA: i64 = 1;

/// The agent skill `wscanner skill` prints. It lives with the Python
/// implementation until that is removed (phase 3), so both print the same.
pub const SKILL: &str = include_str!("../../../../python/skill/wscanner/SKILL.md");

/// The bundled policy files, the defaults `--gitleaks-config`, `--licenses`
/// and `--install-scripts` replace. Shared with the Python implementation.
pub mod defaults {
    pub const GITLEAKS: &str = include_str!("../../../../python/wscanner/defaults/gitleaks.toml");
    pub const LICENSES: &str = include_str!("../../../../python/wscanner/defaults/licenses.txt");
    pub const INSTALL_SCRIPTS: &str = include_str!("../../../../python/wscanner/defaults/install-scripts.txt");
}
