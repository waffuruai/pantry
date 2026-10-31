//! wpantry: inventory this machine and its git repos, check only what is
//! installed or locked against OSV.dev, CISA KEV and endoflife.date, and
//! cache the answers in a local SQLite database whose schema the CLI contract
//! fixes.
//!
//! The library has no global state and never prints: progress goes through
//! the `log` callback a [`check::Scan`] is given, and the CLI owns stdout,
//! stderr and exit codes. The stable surface is the CLI
//! contract (`specs/cli-contract.md`), not this crate's API.

pub mod apps;
pub mod breach;
pub mod catalog;
pub mod catrust;
pub mod check;
pub mod check_machine;
pub mod check_supply;
pub mod compare;
pub mod db;
pub mod distros;
pub mod editors;
pub mod error;
pub mod external;
pub mod feeds;
pub mod harnesses;
pub mod images;
pub mod json;
pub mod leaks;
pub mod licenses;
pub mod lockfiles;
pub mod malicious;
pub mod net;
pub mod osdb;
pub mod osv;
pub mod packages;
pub mod plist;
pub mod posture;
pub mod re;
pub mod repos;
pub mod scanners;
pub mod sha256;
pub mod system;
pub mod tools;
pub mod versions;

pub use error::Error;

/// The implementation's version, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Which implementation this is, in every JSON envelope.
pub const IMPL: &str = "rust";
/// The CLI contract's JSON schema (`specs/cli-contract.md`).
pub const SCHEMA: i64 = 1;

/// The agent skill `wpantry skill` prints, in the crate so the published
/// crate carries it; it describes this binary.
pub const SKILL: &str = include_str!("../assets/SKILL.md");

/// The bundled policy files, the defaults `--gitleaks-config`, `--licenses`
/// and `--install-scripts` replace.
pub mod defaults {
    pub const GITLEAKS: &str = include_str!("../assets/defaults/gitleaks.toml");
    pub const LICENSES: &str = include_str!("../assets/defaults/licenses.txt");
    pub const INSTALL_SCRIPTS: &str = include_str!("../assets/defaults/install-scripts.txt");
    pub const POSTURE: &str = include_str!("../assets/defaults/posture.txt");
}
