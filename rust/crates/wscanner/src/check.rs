//! The scan: gather the inventory, ask each source only about what is here,
//! and turn the answers into findings. Areas live in `check_machine` and
//! `check_supply`; the CLI prints the findings and the update plan.
//!
//! A finding fails when it applies to something on this machine or in a
//! scanned repo and a released version fixes it, when the component is past
//! end of life, or when it's a known malicious package (whose fix is
//! removing it). Everything else that applies is a warning. A source that
//! can't be reached is reported "not checked", never clean. Nothing that
//! isn't installed is reported.

use crate::compare::Comparator;
use crate::db::{Cache, severity_of};
use crate::error::{Error, Result};
use crate::json::{J, obj, str_at};
use crate::net::Net;
use crate::osv::{self, Item};
use crate::repos::{self, Repo};
use crate::system::{Component, Status};
use crate::{check_machine, check_supply, feeds, versions};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const REMOVE: &str = "Remove {} now, then rotate any credentials this machine holds";

/// One thing that applies (`specs/cli-contract.md#finding`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Finding {
    pub kind: String,
    pub component: String,
    pub version: String,
    pub location: String,
    pub vuln_id: String,
    /// fail | warn
    pub status: String,
    pub fixed: String,
    pub kev: bool,
    pub severity: String,
    pub note: String,
    pub fix_cmd: String,
    pub fix_auto: bool,
}

impl Finding {
    /// A finding about a component: its kind, name, version and path.
    pub fn of(c: &Component) -> Finding {
        Finding {
            kind: c.kind.clone(),
            component: c.name.clone(),
            version: c.version.clone(),
            location: c.path.clone(),
            ..Default::default()
        }
    }

    pub fn to_json(&self) -> J {
        obj([
            ("kind", self.kind.as_str().into()),
            ("component", self.component.as_str().into()),
            ("version", self.version.as_str().into()),
            ("location", self.location.as_str().into()),
            ("vuln_id", self.vuln_id.as_str().into()),
            ("status", self.status.as_str().into()),
            ("fixed", self.fixed.as_str().into()),
            ("kev", self.kev.into()),
            ("severity", self.severity.as_str().into()),
            ("note", self.note.as_str().into()),
            ("fix_cmd", self.fix_cmd.as_str().into()),
            ("fix_auto", self.fix_auto.into()),
        ])
    }
}

/// The policy files a scan reads; the bundled defaults unless the caller
/// passes its own (`--gitleaks-config`, `--licenses`, `--install-scripts`).
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub gitleaks_config: Option<PathBuf>,
    pub licenses: Option<PathBuf>,
    pub install_scripts: Option<PathBuf>,
}

impl Policy {
    pub fn install_scripts(&self) -> Vec<String> {
        listed(self.install_scripts.as_deref(), crate::defaults::INSTALL_SCRIPTS)
    }

    pub fn licenses(&self) -> Vec<String> {
        listed(self.licenses.as_deref(), crate::defaults::LICENSES)
    }

    /// The gitleaks config file: the given one, or the bundled one written
    /// beside the cache (rewritten only when it differs, so its fingerprint
    /// holds).
    pub fn gitleaks_config(&self, cache: &Cache) -> Result<PathBuf> {
        if let Some(p) = &self.gitleaks_config {
            return Ok(p.clone());
        }
        let dir = cache.file().parent().map(Path::to_path_buf).unwrap_or_default().join("defaults");
        let file = dir.join("gitleaks.toml");
        if std::fs::read_to_string(&file).ok().as_deref() != Some(crate::defaults::GITLEAKS) {
            std::fs::create_dir_all(&dir)?;
            std::fs::write(&file, crate::defaults::GITLEAKS)?;
        }
        Ok(file)
    }
}

/// Entries of a one-per-line list file (comments start with #); `bundled`
/// when no file is given, nothing when it can't be read.
pub fn listed(path: Option<&Path>, bundled: &str) -> Vec<String> {
    let text = match path {
        Some(p) => std::fs::read_to_string(p).unwrap_or_default(),
        None => bundled.to_string(),
    };
    text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).map(|l| l.trim().to_string()).collect()
}

/// The id a report shows: a CVE alias when there is one.
pub fn display_id(rec: &Value) -> String {
    let id = str_at(rec, "id");
    std::iter::once(id.to_string())
        .chain(crate::json::strs_at(rec, "aliases"))
        .find(|a| a.starts_with("CVE-"))
        .unwrap_or_else(|| id.to_string())
}

pub fn is_kev(rec: &Value, kev: &HashSet<String>) -> bool {
    osv::ids_of(rec).iter().any(|a| kev.contains(a))
}

/// OpenSSF malicious-package reports (MAL-…).
pub fn is_malicious(rec: &Value) -> bool {
    osv::ids_of(rec).iter().any(|i| i.starts_with("MAL-"))
}

pub fn fill(cmd: &str, safe: &str) -> String {
    cmd.replace("{safe}", if safe.is_empty() { "latest" } else { safe })
}

/// What a scan covers and how.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Limit the repo checks to these directories (None: every git repo under $HOME).
    pub paths: Option<Vec<PathBuf>>,
    /// Run the machine inventory, not only the repo checks.
    pub machine: bool,
    pub policy: Policy,
    /// Check dependency licenses against the allowlist (`--licenses`); off
    /// by default, it's noisy.
    pub licenses: bool,
    pub refresh: bool,
    pub offline: bool,
    /// Whether the scan may ask the user something (the breach consent);
    /// the question goes to [`Scan::with_ask`]'s answerer.
    pub ask: bool,
}

/// What a finished scan found.
#[derive(Debug, Default)]
pub struct Outcome {
    pub findings: Vec<Finding>,
    /// What was checked and how many, in the order first counted.
    pub counts: Vec<(String, i64)>,
    pub unfixed: i64,
    pub unknown_licenses: i64,
}

/// One scan.
pub struct Scan<'a> {
    pub opts: Options,
    pub cache: Cache,
    pub net: &'a dyn Net,
    /// Progress for a human (the report's stdout; nothing under --json).
    pub log: &'a dyn Fn(&str),
    /// One-line notes that always go to stderr.
    pub note: &'a dyn Fn(&str),
    /// What the scan is doing right now (see [`Scan::with_status`]).
    pub status: Status<'a>,
    /// Asks the user a yes/no question (see [`Scan::with_ask`]).
    pub asker: Option<crate::breach::Ask<'a>>,
    pub home: PathBuf,
    pub repos: Vec<Repo>,
    pub findings: Vec<Finding>,
    pub counts: Vec<(String, i64)>,
    pub unfixed: i64,
    pub unknown_licenses: i64,
    pub kev: HashSet<String>,
}

impl<'a> Scan<'a> {
    pub fn new(
        opts: Options,
        cache: Cache,
        net: &'a dyn Net,
        log: &'a dyn Fn(&str),
        note: &'a dyn Fn(&str),
    ) -> Scan<'a> {
        Scan {
            opts,
            cache,
            net,
            log,
            note,
            status: &crate::system::quiet,
            asker: None,
            home: crate::system::home(),
            repos: Vec::new(),
            findings: Vec::new(),
            counts: Vec::new(),
            unfixed: 0,
            unknown_licenses: 0,
            kev: HashSet::new(),
        }
    }

    /// Report each step, directory and file as the scan reaches it (the
    /// CLI's progress line). Off by default.
    pub fn with_status(mut self, status: Status<'a>) -> Scan<'a> {
        self.status = status;
        self
    }

    /// How to ask the user a yes/no question (the breach check's consent),
    /// when `opts.ask` allows asking at all.
    pub fn with_ask(mut self, ask: crate::breach::Ask<'a>) -> Scan<'a> {
        self.asker = Some(ask);
        self
    }

    /// Say what the scan is doing now.
    pub fn status(&self, what: &str) {
        (self.status)(what);
    }

    // helpers ---------------------------------------------------------------

    pub fn add(&mut self, f: Finding) {
        self.findings.push(f);
    }

    /// A source we couldn't reach: say so, rather than report it clean.
    pub fn unchecked(&mut self, what: &str, why: &str) {
        if self.findings.iter().any(|f| f.kind == "unchecked" && f.component == what) {
            return;
        }
        let first = why.lines().next().unwrap_or("");
        let note = if why.is_empty() { "unavailable".to_string() } else { first.chars().take(160).collect() };
        self.add(Finding {
            kind: "unchecked".into(),
            component: what.into(),
            vuln_id: "UNCHECKED".into(),
            status: "warn".into(),
            note,
            ..Default::default()
        });
    }

    /// `r`'s value, or `default` with the source reported unchecked; only
    /// an internal error (the cache, the filesystem) passes through.
    pub fn guard<T>(&mut self, what: &str, r: Result<T>, default: T) -> Result<T> {
        match r {
            Ok(v) => Ok(v),
            Err(e) if e.is_source() => {
                self.unchecked(what, &e.to_string());
                Ok(default)
            }
            Err(e) => Err(e),
        }
    }

    pub fn count(&mut self, what: &str, n: i64) {
        if what.is_empty() || n == 0 {
            return;
        }
        match self.counts.iter_mut().find(|(k, _)| k == what) {
            Some((_, have)) => *have += n,
            None => self.counts.push((what.to_string(), n)),
        }
    }

    /// OSV answers for (ecosystem, package, version) items; any it can't
    /// answer are reported unchecked.
    pub fn lookup(&mut self, items: &[Item], what: &str) -> Result<HashMap<Item, Vec<Value>>> {
        let (log, status) = (self.log, self.status);
        if !items.is_empty() {
            status(&format!("Checking {} {what}", items.len()));
        }
        let answers = osv::lookup(&self.cache, self.net, items, self.opts.refresh, self.opts.offline, log, status)?;
        if items.iter().any(|it| !answers.contains_key(it)) {
            self.unchecked(what, "OSV unreachable and not cached");
        }
        Ok(answers)
    }

    // the scan --------------------------------------------------------------

    pub fn run(mut self) -> Result<Outcome> {
        self.status("Fetching CISA's known-exploited list");
        let kev = feeds::kev(&self.cache, self.net, self.opts.offline);
        self.kev = self.guard("CISA KEV (exploited-in-the-wild marks)", kev, HashSet::new())?;
        let (log, note, status) = (self.log, self.note, self.status);
        self.repos = repos::scope(self.opts.paths.as_deref(), &self.home, log, note, status);
        let git = self.repos.iter().filter(|(_, r)| repos::is_git(r)).count() as i64;
        self.count("git repos", git);
        let found: Vec<Component> = if self.opts.machine { check_machine::run(&mut self)? } else { Vec::new() };
        check_supply::run(&mut self, &found)?;
        self.status("Saving the findings");
        self.cache.replace_findings(&self.findings)?;
        self.cache.close()?;
        Ok(Outcome {
            findings: self.findings,
            counts: self.counts,
            unfixed: self.unfixed,
            unknown_licenses: self.unknown_licenses,
        })
    }

    // shared by the areas ---------------------------------------------------

    /// Findings for one component from its OSV records; returns whether any
    /// failed. `groups` bundles records that are aliases of one
    /// vulnerability; otherwise each record is its own, deduplicated by CVE
    /// id. `newer` (upstream repos) maps later release tags to the
    /// advisories OSV still reports for them.
    pub fn advisories(
        &mut self,
        c: &Component,
        recs: &[Value],
        newer: Option<&BTreeMap<String, Vec<String>>>,
        status: &str,
        groups: Option<Vec<Vec<Value>>>,
    ) -> bool {
        let (eco, pkg, qver) = c.osv.clone().unwrap_or_default();
        let order = Comparator::for_ecosystem(&eco);
        let groups = groups.unwrap_or_else(|| recs.iter().map(|r| vec![r.clone()]).collect());
        let mut failing = false;
        let mut seen = HashSet::new();
        for group in groups.iter().filter(|g| !g.is_empty()) {
            let main = group.iter().find(|r| display_id(r).starts_with("CVE-")).unwrap_or(&group[0]);
            if !seen.insert(display_id(main)) {
                continue; // the same CVE from two databases
            }
            if let Some(bad) = group.iter().find(|r| is_malicious(r)) {
                failing = true;
                let who = c.osv.as_ref().map(|o| o.1.as_str()).unwrap_or(&c.name);
                let summary = str_at(bad, "summary");
                self.add(Finding {
                    vuln_id: str_at(bad, "id").into(),
                    status: "fail".into(),
                    kev: true,
                    severity: "MALICIOUS".into(),
                    note: if summary.is_empty() { "known malicious package".into() } else { summary.into() },
                    fix_cmd: REMOVE.replace("{}", who),
                    ..Finding::of(c)
                });
                continue;
            }
            let fixes: Vec<String> = group.iter().flat_map(|r| osv::fixed_versions(r, &eco, &pkg, newer)).collect();
            if fixes.is_empty() {
                self.unfixed += 1;
                continue;
            }
            let safe = versions::pick_safe_by(&qver, &fixes, |a, b| order.cmp(a, b)).unwrap_or_else(|| {
                let mut all = fixes.clone();
                all.sort_by(|a, b| order.cmp(a, b));
                all.pop().unwrap_or_default()
            });
            failing = failing || status == "fail";
            let kev = group.iter().any(|r| is_kev(r, &self.kev));
            self.add(Finding {
                vuln_id: display_id(main),
                status: status.into(),
                fixed: safe.clone(),
                kev,
                severity: severity_of(main),
                note: str_at(main, "summary").into(),
                fix_cmd: fill(&c.fix, &safe),
                fix_auto: c.auto,
                ..Finding::of(c)
            });
        }
        failing
    }

    /// End-of-life (fails) and behind-the-latest-release (warns) findings
    /// for a component endoflife.date knows.
    pub fn eol(&mut self, c: &Component, failing: bool) -> Result<()> {
        let Some((product, cycle)) = c.eol.clone() else { return Ok(()) };
        let r = feeds::eol(&self.cache, self.net, &product, &cycle, self.opts.offline);
        let Some(res) = self.guard(&format!("end of life for {product}"), r, None)? else { return Ok(()) };
        if let Some(ended) = &res.ended {
            let first = res.supported.first().cloned().unwrap_or_default();
            let shown: Vec<&str> = res.supported.iter().take(4).map(String::as_str).collect();
            self.add(Finding {
                vuln_id: "EOL".into(),
                status: "fail".into(),
                fix_cmd: fill(&c.fix, &first),
                note: format!("{product} {cycle} reached end of life on {ended}; supported: {}", shown.join(", ")),
                ..Finding::of(c)
            });
        } else if !res.latest.is_empty() && !failing && !versions::same_or_newer(&c.version, &res.latest) {
            self.add(Finding {
                vuln_id: "OUTDATED".into(),
                status: "warn".into(),
                fixed: res.latest.clone(),
                fix_cmd: fill(&c.fix, &res.latest),
                fix_auto: c.auto,
                note: format!("behind {}, the latest {product} {cycle} release", res.latest),
                ..Finding::of(c)
            });
        }
        Ok(())
    }
}

/// Wraps an I/O error reading one input as a source failure: the input is
/// reported unchecked rather than ending the scan.
pub fn as_source(e: Error) -> Error {
    match e {
        Error::Io(io) => Error::Invalid(io.to_string()),
        e => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Fake;
    use serde_json::json;

    fn scan<'a>(net: &'a Fake, dir: &crate::system::TempDir) -> Scan<'a> {
        let cache = Cache::open(Some(&dir.path().join("w.db"))).unwrap();
        Scan::new(Options::default(), cache, net, &|_| {}, &|_| {})
    }

    #[test]
    fn malicious_needs_no_fix_to_fail() {
        assert!(is_malicious(&json!({"id": "MAL-2026-1"})));
        assert!(is_malicious(&json!({"id": "GHSA-x", "aliases": ["MAL-2026-2"]})));
        assert!(!is_malicious(&json!({"id": "GHSA-x", "aliases": ["CVE-2026-1"]})));
    }

    #[test]
    fn advisories_pick_the_closest_fix_and_dedupe_cves() {
        let net = Fake::offline();
        let dir = crate::system::TempDir::new("check").unwrap();
        let mut s = scan(&net, &dir);
        s.kev.insert("CVE-2026-9".into());
        let mut c = Component::new("project", "rustls", "0.23.10", "/w/Cargo.lock");
        c.osv = Some(("crates.io".into(), "rustls".into(), "0.23.10".into()));
        c.fix = "cargo update -p rustls --precise {safe}".into();
        let fixed = |f: &str| json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": f}]}]);
        let recs = vec![
            json!({"id": "GHSA-1", "aliases": ["CVE-2026-9"], "summary": "bad", "database_specific": {"severity": "HIGH"},
                   "affected": [{"package": {"ecosystem": "crates.io", "name": "rustls"}, "ranges": fixed("0.23.18")}]}),
            json!({"id": "RUSTSEC-1", "aliases": ["CVE-2026-9"],
                   "affected": [{"package": {"ecosystem": "crates.io", "name": "rustls"}, "ranges": fixed("0.23.18")}]}),
            json!({"id": "GHSA-2", "affected": [{"package": {"ecosystem": "crates.io", "name": "rustls"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}),
            json!({"id": "MAL-1", "summary": "", "affected": []}),
        ];
        assert!(s.advisories(&c, &recs, None, "fail", Some(osv::group_by_alias(&recs))));
        assert_eq!(s.unfixed, 1);
        assert_eq!(s.findings.len(), 2);
        let f = &s.findings[0];
        assert_eq!(
            (f.vuln_id.as_str(), f.fixed.as_str(), f.kev, f.severity.as_str()),
            ("CVE-2026-9", "0.23.18", true, "HIGH")
        );
        assert_eq!(f.fix_cmd, "cargo update -p rustls --precise 0.23.18");
        let m = &s.findings[1];
        assert_eq!(
            (m.vuln_id.as_str(), m.severity.as_str(), m.note.as_str()),
            ("MAL-1", "MALICIOUS", "known malicious package")
        );
        assert_eq!(m.fix_cmd, "Remove rustls now, then rotate any credentials this machine holds");
    }

    #[test]
    fn unchecked_is_reported_once() {
        let net = Fake::offline();
        let dir = crate::system::TempDir::new("check").unwrap();
        let mut s = scan(&net, &dir);
        let r: Result<i32> = Err(Error::Offline("a: down\nmore".into()));
        assert_eq!(s.guard("feed", r, 7).unwrap(), 7);
        s.unchecked("feed", "again");
        assert_eq!(s.findings.len(), 1);
        assert_eq!((s.findings[0].note.as_str(), s.findings[0].status.as_str()), ("a: down", "warn"));
        let internal: Result<i32> = Err(Error::Io(std::io::Error::other("disk")));
        assert!(s.guard("x", internal, 0).is_err(), "internal errors pass through");
    }

    #[test]
    fn listed_files_and_bundled_defaults() {
        assert!(listed(None, crate::defaults::INSTALL_SCRIPTS).contains(&"esbuild".to_string()));
        assert!(listed(Some(Path::new("/nonexistent")), "x").is_empty());
    }
}
