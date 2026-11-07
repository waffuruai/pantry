//! wpantry: inventory this machine and its git repos, check only what is
//! installed or locked against OSV.dev, CISA KEV and endoflife.date, and
//! cache the answers in a local SQLite database whose schema the CLI contract
//! fixes.
//!
//! The library has no global state and never prints: progress goes through
//! the `log` callback a [`checks::Scan`] is given, and the CLI owns stdout,
//! stderr and exit codes. The stable surface is the CLI
//! contract (`specs/cli-contract.md`), not this crate's API.

pub mod checks;
pub mod component;
pub mod db;
pub mod error;
pub mod external;
pub mod finding;
pub mod history;
pub mod remediation;
pub mod reporters;
pub mod selfinstall;
pub mod sources;
pub mod sync;
pub mod utils;
pub mod watch;

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

/// The bundled policy and data files (TOML), the defaults the policy
/// options (`--licenses`, `--install-scripts`, …) replace.
pub mod defaults {
    pub const LICENSES: &str = include_str!("../assets/defaults/licenses.toml");
    pub const INSTALL_SCRIPTS: &str = include_str!("../assets/defaults/install-scripts.toml");
    pub const REPO_HOOKS: &str = include_str!("../assets/defaults/repo-hooks.toml");
    pub const POSTURE: &str = include_str!("../assets/defaults/posture.toml");
    pub const MITIGATIONS: &str = include_str!("../assets/defaults/mitigations.toml");
    pub const SUSPECT: &str = include_str!("../assets/defaults/suspect.toml");
    pub const HOOKS: &str = include_str!("../assets/defaults/hooks.toml");
    pub const POPULAR: &str = include_str!("../assets/defaults/popular.toml");
    pub const WEAK_PASSWORDS: &str = include_str!("../assets/defaults/weak-passwords.toml");
    pub const BAIT: &str = include_str!("../assets/defaults/bait.toml");
    pub const SOURCES: &str = include_str!("../assets/defaults/sources.toml");
}
