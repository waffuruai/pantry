//! Following a scan while it runs: the steps it takes, in order, what it is
//! reading now and the findings each step makes, for a caller that runs the
//! scanner as a child process (the CLI's `scan --events`). A [`Watch`] sees
//! them as they happen; [`steps`] says up front which steps a scan with
//! these options takes. Nothing here writes anywhere: the CLI does.
//!
//! ```
//! use wpantry::checks::{Options, watch};
//! let opts = Options { machine: false, no_malware: true, ..Default::default() };
//! let ids: Vec<&str> = watch::steps(&opts).iter().map(|s| s.id).collect();
//! assert_eq!(ids.first(), Some(&"sources"));
//! assert!(!ids.contains(&"machine") && !ids.contains(&"malware"));
//! ```

use crate::checks::Options;
use crate::finding::Finding;
use std::path::Path;

/// One step of a scan: a stable id for programs and a short title for people.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub id: &'static str,
    pub title: &'static str,
}

/// Whether [`Watch::at`] names a file being read or a folder being looked in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    File,
    Dir,
}

impl At {
    pub fn name(self) -> &'static str {
        match self {
            At::File => "file",
            At::Dir => "dir",
        }
    }
}

/// What a caller is told while a scan runs. Every method does nothing by
/// default. [`Watch::step`] and [`Watch::finding`] are called on the scan's
/// own thread; [`Watch::at`] also from the threads that read files, often
/// (once per file read), so it must be cheap.
pub trait Watch: Sync {
    /// A step begins (the one before it, if any, has ended): one of
    /// [`steps`]'s ids, in that order.
    fn step(&self, _id: &str) {}
    /// The scan is reading this file, or looking in this folder, now.
    fn at(&self, _path: &Path, _what: At) {}
    /// How many repos (or folders scanned as one project) are in scope.
    fn repos(&self, _n: usize) {}
    /// A folder walk listed `n` more files (from the walking threads).
    fn listed(&self, _n: usize) {}
    /// A finding the current step has made. Provisional: an ignore file
    /// can still leave it out and the rating step can change its severity.
    fn finding(&self, _f: &Finding) {}
}

/// A [`Watch`] that is told nothing: a scan's default.
pub struct Quiet;

impl Watch for Quiet {}

/// The step ids and titles, in the order a scan takes them.
pub const SOURCES: Step = Step { id: "sources", title: "Getting advisory data" };
pub const REPOS: Step = Step { id: "repos", title: "Finding repos" };
pub const MACHINE: Step = Step { id: "machine", title: "Looking at this computer" };
pub const DEPENDENCIES: Step = Step { id: "dependencies", title: "Checking dependencies" };
pub const SECRETS: Step = Step { id: "secrets", title: "Looking for secrets in git history" };
pub const REPO_FILES: Step = Step { id: "repo-files", title: "Reading the repos' files" };
pub const IMAGES: Step = Step { id: "images", title: "Checking container images" };
pub const EXTENSIONS: Step = Step { id: "extensions", title: "Checking MCP servers and extensions" };
pub const MALICIOUS: Step = Step { id: "malicious", title: "Checking package names against known malicious packages" };
pub const BREACH: Step = Step { id: "breach", title: "Checking email addresses against breaches" };
pub const MALWARE: Step = Step { id: "malware", title: "Scanning for malware" };
pub const FILE_SECRETS: Step = Step { id: "file-secrets", title: "Looking for secrets in files" };
pub const RATING: Step = Step { id: "rating", title: "Rating and saving the findings" };

/// The steps a scan with `opts` takes, in order: the machine and breach
/// steps only on a machine scan, malware unless `--no-malware`, the
/// secrets in files only with `--deep`.
pub fn steps(opts: &Options) -> Vec<Step> {
    let mut out = vec![SOURCES, REPOS];
    if opts.machine {
        out.push(MACHINE);
    }
    out.extend([DEPENDENCIES, SECRETS, REPO_FILES, IMAGES, EXTENSIONS, MALICIOUS]);
    if opts.machine {
        out.push(BREACH);
    }
    if !opts.no_malware {
        out.push(MALWARE);
    }
    if opts.deep {
        out.push(FILE_SECRETS);
    }
    out.push(RATING);
    out
}

#[cfg(test)]
#[path = "watch_tests.rs"]
mod tests;
