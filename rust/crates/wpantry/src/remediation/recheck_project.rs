//! The narrow re-check of a package found inside a project: the one place
//! the finding came from, read again alone, with the reader the scan used
//! for that place. Nothing is run (no package manager, no interpreter), no
//! project is written, and no network is asked.
//!
//! * a project dependency (kind `project`, location a lockfile or manifest):
//!   the file is read by [`lockfiles::extract_noting`], the function the scan
//!   reads it with, from the repository root the scan used (the nearest
//!   folder above it holding `.git`);
//! * a Python package installed in a virtual environment (kind `package`,
//!   component `pip:NAME`, location the environment's `python`): the
//!   environment's own `site-packages` metadata, read by
//!   [`packages::installed`] as the scan reads it, never by running Python.
//!
//! What the package's version there is now is judged against the advisory's
//! cached record, with the range matching the scan's findings use
//! ([`osv::affected_range`]):
//!
//! * `gone`: the package is no longer in the place (`removed`), or every
//!   version there is outside every affected range of the record (`fixed`);
//! * `still_present`: some version there is in an affected range, or the
//!   record is a known-malicious one (any version of it is bad);
//! * `unknown`: the file is not there (`unreachable`) or cannot be read
//!   (`unreadable`); the format has no narrow read (`unsupported`); the
//!   record is not cached (`uncached`); the version or the record's ranges
//!   cannot be compared (`uncomparable`); the place could not be read whole
//!   enough to say a package is missing from it (`unreadable`). Never `gone`.
//!
//! Which places are read, and which still answer `unsupported`, is listed in
//! specs/cli-contract.md. A run reads each place once, however many ids
//! name it ([`Memo`]), and loads each advisory record once.

use super::recheck::Verdict;
use crate::checks::ecosystems::{self, pypi, versions};
use crate::checks::lockfiles;
use crate::checks::machine::packages;
use crate::db::Cache;
use crate::error::Result;
use crate::sources::osv;
use crate::utils::json::{arr_at, str_at};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A package a place holds: (OSV ecosystem, name, version).
type Item = (String, String, String);

/// What reading a place found. `doubt` says why a package missing from
/// `found` may still be there (something in the place could not be read).
struct Read {
    found: Vec<Item>,
    doubt: Option<String>,
}

type Place = std::result::Result<Read, Verdict>;

/// What one run has already read: each place once, each record once.
#[derive(Default)]
pub(super) struct Memo {
    places: HashMap<String, Place>,
    records: Records,
}

#[cfg(test)]
thread_local! {
    /// How many places were read, for the test that a shared place is read once.
    static OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_opens() {
    OPENS.with(|c| c.set(0));
}

#[cfg(test)]
pub(super) fn opens() -> usize {
    OPENS.with(|c| c.get())
}

fn opened() {
    #[cfg(test)]
    OPENS.with(|c| c.set(c.get() + 1));
}

/// Whether a finding of this kind, component and location is one this
/// module re-checks.
pub(super) fn applies(kind: &str, component: &str, location: &str) -> bool {
    match kind {
        "project" => {
            let path = Path::new(location);
            path.is_absolute()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| lockfiles::supported(n) || lockfiles::csproj::is_context_file(n))
        }
        "package" => component.starts_with("pip:"),
        _ => false,
    }
}

/// The verdict for one finding of a project package or an installed Python
/// package: see the module's doc.
pub(super) fn judge(
    memo: &mut Memo,
    cache: &Cache,
    (kind, component, location, vuln_id): (&str, &str, &str, &str),
) -> Result<Verdict> {
    let Memo { places, records } = memo;
    let place = places.entry(format!("{kind}|{location}")).or_insert_with(|| {
        opened();
        if kind == "project" { read_lockfile(location) } else { read_environment(location) }
    });
    let read = match place {
        Ok(read) => &*read,
        Err(verdict) => return Ok(verdict.clone()),
    };
    let want = component.strip_prefix("pip:").unwrap_or(component);
    let mine: Vec<&Item> = read
        .found
        .iter()
        .filter(
            |(eco, name, _)| {
                if eco == "PyPI" { pypi::normalize(name) == pypi::normalize(want) } else { name == want }
            },
        )
        .collect();
    if mine.is_empty() {
        return Ok(match &read.doubt {
            Some(why) => {
                Verdict::unknown("unreadable", format!("{want} is not in what could be read of {location}: {why}."))
            }
            None => Verdict::gone("removed", format!("{want} is no longer in {location}.")),
        });
    }
    let recs = records.of(cache, vuln_id)?;
    if recs.is_empty() {
        return Ok(Verdict::unknown(
            "uncached",
            format!("The record of {vuln_id} is not cached, so {want} in {location} can't be judged."),
        ));
    }
    let mut unclear = None;
    for item in &mine {
        match judge_item(recs, item, vuln_id) {
            Judged::Affected => {
                return Ok(Verdict::still(
                    "affected",
                    format!("{want} {} in {location} is still affected by {vuln_id}.", item.2),
                ));
            }
            Judged::Outside => {}
            Judged::Unclear(why) => unclear = unclear.or(Some(why)),
        }
    }
    if let Some(why) = unclear {
        return Ok(Verdict::unknown("uncomparable", why));
    }
    let shown: Vec<&str> = mine.iter().map(|i| i.2.as_str()).collect();
    Ok(Verdict::gone(
        "fixed",
        format!("{want} {} in {location} is outside every affected range of {vuln_id}.", shown.join(", ")),
    ))
}

enum Judged {
    Affected,
    Outside,
    Unclear(String),
}

/// One version of a package against the cached records of one advisory.
fn judge_item(recs: &[Value], item: &Item, id: &str) -> Judged {
    // A known-malicious package is bad at any version, as the scan treats it.
    if recs.iter().any(crate::checks::is_malicious) {
        return Judged::Affected;
    }
    let (eco, name, version) = item;
    if versions::numbers(version).is_empty() {
        return Judged::Unclear(format!("{name} {version} has no version number to compare."));
    }
    let mut asked = vec![item.clone()];
    asked.extend(osv::also(item));
    // In a SEMVER or ECOSYSTEM range, or named in the record's list of
    // affected versions (`affected_range` reads that list as exact): affected.
    let hit = recs.iter().any(|rec| {
        asked
            .iter()
            .any(|(e, p, v)| !osv::affected_range(rec, e, p, v, |a, b| ecosystems::order(e).cmp(a, b)).is_empty())
    });
    if hit {
        return Judged::Affected;
    }
    // Not in a range: only as good as the record's own ranges. A record
    // that doesn't name the package, or names it by commits only, says
    // nothing about this version.
    let naming: Vec<&Value> = recs
        .iter()
        .filter(|rec| arr_at(rec, "affected").iter().any(|a| asked.iter().any(|(e, p, _)| osv::matches(a, e, p))))
        .collect();
    if naming.is_empty() {
        return Judged::Unclear(format!(
            "{id} does not name {name} in the cached record, so {eco} {version} can't be judged."
        ));
    }
    if naming.iter().all(|rec| comparable(rec, &asked)) {
        Judged::Outside
    } else {
        Judged::Unclear(format!("{id} lists no version ranges for {name} that can be compared with {version}."))
    }
}

/// Whether the record gives this package SEMVER or ECOSYSTEM ranges. A
/// list of versions says which are affected, never which are not (a record
/// with GIT ranges lists the tags it could resolve), and ranges of commits
/// can't be compared with a version: neither makes a version outside.
fn comparable(rec: &Value, asked: &[Item]) -> bool {
    arr_at(rec, "affected")
        .iter()
        .filter(|a| asked.iter().any(|(e, p, _)| osv::matches(a, e, p)))
        .any(|a| arr_at(a, "ranges").iter().any(|r| matches!(str_at(r, "type"), "SEMVER" | "ECOSYSTEM")))
}

fn not_there(location: &str) -> Verdict {
    Verdict::unknown(
        "unreachable",
        format!("{location} is not there any more; only a scan can tell whether it was dropped."),
    )
}

fn unreadable(location: &str, why: impl std::fmt::Display) -> Verdict {
    Verdict::unknown("unreadable", format!("{location} can't be read: {why}."))
}

/// The folder the scan read `file` from: the nearest one above it holding
/// `.git`, else its own.
fn repo_root(file: &Path) -> PathBuf {
    let parent = file.parent().unwrap_or(Path::new("."));
    parent.ancestors().find(|a| a.join(".git").exists()).unwrap_or(parent).to_path_buf()
}

/// A lockfile or manifest, read by the scan's own reader for it.
fn read_lockfile(location: &str) -> Place {
    let path = Path::new(location);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if lockfiles::csproj::is_context_file(name) {
        return Err(Verdict::unknown(
            "unsupported",
            format!(
                "{location} declares packages for every project that imports it; only a scan reads them through those projects."
            ),
        ));
    }
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => return Err(unreadable(location, "it is not a file")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(not_there(location)),
        Err(e) => return Err(unreadable(location, e)),
    }
    match lockfiles::extract_noting(path, &repo_root(path)) {
        Ok(Some(x)) => Ok(Read {
            found: x.packages.into_iter().map(|p| (p.ecosystem, p.name, p.version)).collect(),
            doubt: (!x.unchecked.is_empty())
                .then(|| format!("{} dependencies in it are not pinned exactly", x.unchecked.len())),
        }),
        Ok(None) => Err(Verdict::unknown(
            "unsupported",
            format!("{location} is a kind of file with no narrow read; only a scan checks it."),
        )),
        Err(e) => Err(unreadable(location, e)),
    }
}

/// The packages installed in the virtual environment `python` belongs to,
/// from its own `site-packages` metadata.
fn read_environment(location: &str) -> Place {
    let python = Path::new(location);
    if std::fs::symlink_metadata(python).is_err() {
        return Err(not_there(location));
    }
    let bin = python.parent();
    let config =
        [bin, bin.and_then(Path::parent)].into_iter().flatten().map(|d| d.join("pyvenv.cfg")).find(|c| c.is_file());
    let Some(config) = config else {
        return Err(Verdict::unknown(
            "unsupported",
            format!(
                "{location} is not in a virtual environment, so its packages can't be read without running it; only a scan reads them."
            ),
        ));
    };
    let venv = config.parent().unwrap_or(Path::new("."));
    let system = std::fs::read_to_string(&config).is_ok_and(|text| {
        text.lines().any(|l| {
            l.split_once('=').is_some_and(|(k, v)| {
                k.trim().eq_ignore_ascii_case("include-system-site-packages") && v.trim().eq_ignore_ascii_case("true")
            })
        })
    });
    let mut sites: Vec<String> = Vec::new();
    for lib in ["lib", "lib64"] {
        let Ok(rd) = std::fs::read_dir(venv.join(lib)) else { continue };
        let mut dirs: Vec<PathBuf> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("python"))
            .map(|e| e.path().join("site-packages"))
            .collect();
        dirs.sort();
        sites.extend(dirs.into_iter().filter(|d| d.is_dir()).map(|d| d.to_string_lossy().into_owned()));
    }
    let windows = venv.join("Lib").join("site-packages");
    if windows.is_dir() {
        sites.push(windows.to_string_lossy().into_owned());
    }
    if sites.is_empty() {
        return Err(unreadable(location, "its environment has no site-packages"));
    }
    let (found, gaps) = packages::installed(&sites);
    let mut doubt = Vec::new();
    if system {
        doubt.push("the environment also reads the system's packages, which a narrow read does not open".to_string());
    }
    if !gaps.is_empty() {
        doubt.push(format!("{} installed packages have metadata that can't be read", gaps.len()));
    }
    Ok(Read {
        found: found.into_iter().map(|(n, v)| ("PyPI".to_string(), n, v)).collect(),
        doubt: (!doubt.is_empty()).then(|| doubt.join("; ")),
    })
}

/// The cached OSV records of each advisory id asked about: the record of
/// that id and any that lists it as an alias, found through one index of the
/// cache's ids and aliases, built when first needed.
#[derive(Default)]
struct Records {
    index: Option<HashMap<String, Vec<String>>>,
    loaded: HashMap<String, Vec<Value>>,
}

impl Records {
    fn of(&mut self, cache: &Cache, id: &str) -> Result<&[Value]> {
        if !self.loaded.contains_key(id) {
            if self.index.is_none() {
                let mut index: HashMap<String, Vec<String>> = HashMap::new();
                let mut stmt = cache.conn.prepare("SELECT id, aliases FROM vulns")?;
                let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))?;
                for row in rows {
                    let (rid, aliases) = row?;
                    for key in aliases.as_deref().unwrap_or("").split_whitespace().chain(std::iter::once(rid.as_str()))
                    {
                        let ids = index.entry(key.to_string()).or_default();
                        if !ids.contains(&rid) {
                            ids.push(rid.clone());
                        }
                    }
                }
                self.index = Some(index);
            }
            let ids = self.index.as_ref().and_then(|i| i.get(id)).cloned().unwrap_or_default();
            let mut recs = Vec::new();
            for rid in ids {
                recs.extend(cache.vuln(&rid)?);
            }
            self.loaded.insert(id.to_string(), recs);
        }
        Ok(&self.loaded[id])
    }
}
