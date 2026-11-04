//! What a scan finds to check: the [`Component`] every finder returns, and
//! the [`Status`] line it reports progress on.

use std::collections::BTreeMap;

/// Where a scan says what it is doing right now ("Reading ~/app/Cargo.lock"):
/// transient progress for a human, never part of the report. Called from
/// worker threads too, hence `Sync`.
pub type Status<'a> = &'a (dyn Fn(&str) + Sync);

/// A [`Status`] that shows nothing.
pub fn quiet(_: &str) {}

/// Something installed or locked that can be checked.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Component {
    /// runtime, compiler, manager, pkgmgr, tool, datastore, harness, package, app, project, os, mcp, …
    pub kind: String,
    pub name: String,
    pub version: String,
    pub path: String,
    /// (ecosystem, package, version as OSV knows it)
    pub osv: Option<(String, String, String)>,
    /// (endoflife.date product, cycle)
    pub eol: Option<(String, String)>,
    /// The command (or step) that updates it; "{safe}" is the fixed version.
    pub fix: String,
    /// `wpantry fix` may run `fix` unattended.
    pub auto: bool,
    pub extra: BTreeMap<String, String>,
    /// How a locked dependency is depended on: `runtime`, `dev`, `optional`,
    /// or "" when the lockfile doesn't say (and for everything that isn't a
    /// locked dependency).
    pub scope: String,
    /// A project's own dependency (true) or one pulled in by another
    /// (false); None when unknown.
    pub direct: Option<bool>,
}

impl Component {
    pub fn new(kind: &str, name: &str, version: &str, path: &str) -> Component {
        Component {
            kind: kind.into(),
            name: name.into(),
            version: version.into(),
            path: path.into(),
            ..Default::default()
        }
    }
}
