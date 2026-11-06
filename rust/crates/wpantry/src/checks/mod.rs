//! The scan: gather the inventory, ask each source only about what is here,
//! and turn the answers into findings. Areas live in [`machine`] and
//! [`supply_chain`]; the CLI prints the findings and the update plan.
//!
//! A finding fails when it applies to something on this machine or in a
//! scanned repo and a released version fixes it, when the component is past
//! end of life, or when it's a known malicious package (whose fix is
//! removing it). Everything else that applies is a warning. A source that
//! can't be reached is reported "not checked", never clean. Nothing that
//! isn't installed is reported.

pub mod documents;
pub mod ecosystems;
pub mod email;
pub mod files;
pub mod hidden;
pub mod lockfiles;
pub mod machine;
pub mod malware;
pub mod severity;
pub mod supply_chain;
pub mod suspects;

use crate::component::Component;
use crate::component::Status;
use crate::db::{Cache, severity_of};
use crate::error::{Error, Result};
use crate::finding::Finding;
use crate::sources::endoflife;
use crate::sources::kev;
use crate::sources::osv::{self, Item};
use crate::utils::json::str_at;
use crate::utils::net::Net;
use ecosystems::versions;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use supply_chain::repos::{self, Repo};

pub const REMOVE: &str = "Remove {} now, then rotate any credentials this machine holds";

/// The policy files a scan reads; the bundled defaults unless the caller
/// passes its own (`--gitleaks-config`, `--licenses`, `--install-scripts`,
/// `--repo-hooks`, `--posture-policy`, `--suspect-policy`, `--hooks-policy`).
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub gitleaks_config: Option<PathBuf>,
    pub licenses: Option<PathBuf>,
    pub install_scripts: Option<PathBuf>,
    /// Indicators of hijacked repos (`--repo-hooks`); the bundled list by default.
    pub repo_hooks: Option<PathBuf>,
    /// Posture checks to skip (`--posture-policy`); the bundled, empty list by default.
    pub posture: Option<PathBuf>,
    /// Suspicious-code exemptions (`--suspect-policy`): ids and paths that
    /// only warn; the bundled, empty list by default.
    pub suspect: Option<PathBuf>,
    /// Repo hooks a person has read and accepted (`--hooks-policy`); the
    /// bundled, empty list by default.
    pub hooks: Option<PathBuf>,
}

impl Policy {
    pub fn install_scripts(&self) -> Vec<String> {
        listed(self.install_scripts.as_deref(), crate::defaults::INSTALL_SCRIPTS, "allow")
    }

    pub fn licenses(&self) -> Vec<String> {
        listed(self.licenses.as_deref(), crate::defaults::LICENSES, "allow")
    }

    pub fn suspect_policy(&self) -> crate::checks::suspects::Policy {
        crate::checks::suspects::Policy::parse(&match &self.suspect {
            Some(p) => std::fs::read_to_string(p).unwrap_or_default(),
            None => crate::defaults::SUSPECT.to_string(),
        })
    }

    /// The accepted repo hooks (see `hooks::Accepted`).
    pub fn hooks_policy(&self) -> crate::checks::supply_chain::hooks::Accepted {
        crate::checks::supply_chain::hooks::Accepted::parse(&match &self.hooks {
            Some(p) => std::fs::read_to_string(p).unwrap_or_default(),
            None => crate::defaults::HOOKS.to_string(),
        })
    }

    /// The repo-hook indicator list's text (see `hooks::Indicators::parse`).
    pub fn repo_hooks(&self) -> String {
        match &self.repo_hooks {
            Some(p) => std::fs::read_to_string(p).unwrap_or_default(),
            None => crate::defaults::REPO_HOOKS.to_string(),
        }
    }

    pub fn posture_skip(&self) -> Vec<String> {
        listed(self.posture.as_deref(), crate::defaults::POSTURE, "skip")
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

/// The list `key` of a policy file (TOML), or of `bundled` when no file is
/// given; nothing when it can't be read (the CLI checks a file before the
/// scan: [`policy_error`]).
pub fn listed(path: Option<&Path>, bundled: &str, key: &str) -> Vec<String> {
    let text = match path {
        Some(p) => std::fs::read_to_string(p).unwrap_or_default(),
        None => bundled.to_string(),
    };
    crate::utils::toml::list(&text, "", key).unwrap_or_default().into_iter().map(|e| e.trim().to_string()).collect()
}

/// The user's own policy file `name` (`suspect.toml`, …) in the config
/// folder ([`crate::sources::file::config_dir`]), when there is one: used
/// when its option isn't given.
pub fn user_policy(name: &str) -> Option<PathBuf> {
    Some(crate::sources::file::config_dir().join(name)).filter(|p| p.is_file())
}

/// Why a policy file can't be used, or None: it must be TOML (a list from
/// before, one entry a line, isn't).
pub fn policy_error(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string()).ok()?;
    crate::utils::toml::parse(&text).err().map(|e| format!("not a TOML policy file ({e})"))
}

/// The id a report shows: a CVE alias when there is one.
pub fn display_id(rec: &Value) -> String {
    let id = str_at(rec, "id");
    std::iter::once(id.to_string())
        .chain(crate::utils::json::strs_at(rec, "aliases"))
        .find(|a| a.starts_with("CVE-"))
        .unwrap_or_else(|| id.to_string())
}

/// The step for an advisory with no fix released, from the bundled
/// mitigations (`[mitigations]`, by id).
pub fn mitigation(id: &str) -> Option<String> {
    mitigation_in(crate::defaults::MITIGATIONS, id)
}

pub fn mitigation_in(text: &str, id: &str) -> Option<String> {
    let tables = crate::utils::toml::parse(text).ok()?;
    let t = tables.iter().find(|t| t.name == "mitigations")?;
    t.entries
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(id))
        .and_then(|(_, v)| v.as_str())
        .map(|v| v.trim().to_string())
}

/// Severities worth a warning even with no fix to apply.
pub fn high_impact(severity: &str) -> bool {
    matches!(severity, "CRITICAL" | "HIGH")
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

/// The fix command and whether it may run unattended, for a version a feed
/// named: a version that isn't one plain token never reaches a command.
pub fn fix_with(c: &Component, safe: &str) -> (String, bool) {
    if safe.is_empty() || versions::is_safe_token(safe) {
        (fill(&c.fix, safe), c.auto)
    } else {
        ("Review the advisory: the fix version it names isn't a version, so no command is offered".to_string(), false)
    }
}

/// What a scan covers and how.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Limit the repo checks to these directories (None: every git repo under $HOME).
    pub paths: Option<Vec<PathBuf>>,
    /// Run the machine inventory, not only the repo checks.
    pub machine: bool,
    /// Skip the machine's security settings (`--no-posture`); they run
    /// with the machine inventory otherwise.
    pub no_posture: bool,
    pub policy: Policy,
    /// Check dependency licenses against the allowlist (`--licenses`); off
    /// by default, it's noisy.
    pub licenses: bool,
    pub refresh: bool,
    pub offline: bool,
    /// How many CPU-bound scans (gitleaks) run at once (`--jobs`); None
    /// picks from the machine's cores.
    pub jobs: Option<usize>,
    /// Whether the scan may ask the user something (the breach consent);
    /// the question goes to [`Scan::with_ask`]'s answerer.
    pub ask: bool,
    /// Skip the malware scan (`--no-malware`).
    pub no_malware: bool,
    /// The malware scan reads all of `~` with every system's rules (`--deep`).
    pub deep: bool,
    /// Never look up a flagged file's hash online (`--no-online-hash`).
    pub no_online_hash: bool,
    /// The user's sources file for this run (`--sources FILE`); None reads
    /// `~/.config/wpantry/sources.toml` when it exists.
    pub sources: Option<PathBuf>,
}

/// What a finished scan found.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// This scan's row in the cache's `scans` table.
    pub scan_id: i64,
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
    pub asker: Option<crate::checks::email::Ask<'a>>,
    pub home: PathBuf,
    pub repos: Vec<Repo>,
    pub findings: Vec<Finding>,
    pub counts: Vec<(String, i64)>,
    pub unfixed: i64,
    pub unknown_licenses: i64,
    pub kev: HashSet<String>,
    /// The files pass's findings ([`Scan::read_files`]).
    pub(crate) files: Option<files::Results>,
    /// The malware scan's rules, compiled before the files are read.
    pub(crate) malware: Option<malware::Prepared>,
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
            status: &crate::component::quiet,
            asker: None,
            home: crate::utils::files::home(),
            repos: Vec::new(),
            findings: Vec::new(),
            counts: Vec::new(),
            unfixed: 0,
            unknown_licenses: 0,
            kev: HashSet::new(),
            files: None,
            malware: None,
        }
    }

    /// The sources this run uses: the bundled ones, and the user's file's
    /// tiers and sources, each of the user's asked about once
    /// ([`crate::sources::user`]). One that can't be used is unchecked; the
    /// ones used are named in the counts.
    fn use_sources(&mut self) {
        use crate::sources::{file, user};
        let path = self.opts.sources.clone().unwrap_or_else(file::user_file);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => Some(t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && self.opts.sources.is_none() => None,
            Err(e) => {
                self.unchecked("your sources file", &format!("{}: {e}", path.display()));
                None
            }
        };
        if let Err(e) = file::configure(text.as_deref(), self.opts.deep) {
            self.unchecked("your sources file", &e.to_string());
        }
        let effective = file::effective();
        let ask = if self.opts.ask { self.asker } else { None };
        for s in effective.sources.iter().filter(|s| effective.user.contains(&s.id) && file::active(&s.id)) {
            match user::consent(&self.cache, ask, s) {
                Ok(Ok(())) => {
                    if let Some(h) = s.host() {
                        crate::utils::net::allow(&h);
                    }
                    self.count(&format!("user source {}", s.id), 1);
                }
                Ok(Err(why)) => {
                    file::turn_off(&s.id);
                    self.unchecked(&format!("the source {} (your sources file)", s.id), &why);
                }
                Err(e) => {
                    file::turn_off(&s.id);
                    self.unchecked(&format!("the source {} (your sources file)", s.id), &e.to_string());
                }
            }
        }
    }

    /// The content checks' findings (hidden text, suspect code, MPTCP,
    /// documents, malware): one files pass over every repo and, on a machine
    /// scan, the installed extensions and plugins, Downloads, Desktop and
    /// Documents, and the places malware lands, run the first time a check
    /// asks. The malware rules are compiled first, so they read the files
    /// with the rest.
    pub(crate) fn read_files(&mut self) -> &files::Results {
        if self.files.is_none() {
            if !self.opts.no_malware && self.malware.is_none() {
                self.malware = Some(malware::prepare(self));
            }
            self.status("Reading files");
            let jobs = self.file_jobs();
            let rules = self.malware.as_ref().map(|m| m.loaded.clone());
            self.files = Some(files::pass::run_cached(&jobs, Some(&self.cache), rules));
        }
        self.files.as_ref().expect("the files pass just ran")
    }

    fn file_jobs(&self) -> Vec<files::Job> {
        use files::{Check, Job};
        let mut jobs = Vec::new();
        for (_, root) in &self.repos {
            if repos::is_git(root) {
                jobs.push(Job::new(Check::Hidden, root, hidden::DEPTH));
                jobs.push(Job::new(Check::Suspects(suspects::Kind::Repo), root, suspects::DEPTH));
                jobs.push(Job::new(Check::Blobs, root, 0));
            }
            jobs.push(Job::new(Check::Mptcp, root, supply_chain::mptcp::DEPTH));
            jobs.push(Job::new(Check::Documents, root, 6));
        }
        if self.opts.machine {
            for (_, dir) in supply_chain::suspect_code::installed_code() {
                jobs.push(Job::new(Check::Suspects(suspects::Kind::Installed), &dir, suspects::DEPTH));
            }
            for dir in machine::downloads::dirs() {
                jobs.push(Job::new(Check::Documents, &dir, 1));
            }
        }
        if !self.opts.no_malware {
            let repos: Vec<PathBuf> = self.repos.iter().map(|(_, r)| r.clone()).collect();
            jobs.extend(malware::targets::jobs(&self.home, &repos, self.opts.machine, self.opts.deep));
        }
        jobs
    }

    /// Report each step, directory and file as the scan reaches it (the
    /// CLI's progress line). Off by default.
    pub fn with_status(mut self, status: Status<'a>) -> Scan<'a> {
        self.status = status;
        self
    }

    /// How to ask the user a yes/no question (the breach check's consent),
    /// when `opts.ask` allows asking at all.
    pub fn with_ask(mut self, ask: crate::checks::email::Ask<'a>) -> Scan<'a> {
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
    /// answer, and anything that makes the answers incomplete (stale, or an
    /// advisory OSV named but couldn't serve), are reported unchecked.
    pub fn lookup(&mut self, items: &[Item], what: &str) -> Result<HashMap<Item, Vec<Value>>> {
        let (log, status) = (self.log, self.status);
        if !items.is_empty() {
            status(&format!("Checking {} {what}", items.len()));
        }
        let answers = osv::lookup(&self.cache, self.net, items, self.opts.refresh, self.opts.offline, log, status)?;
        let mut why = answers.gaps;
        if items.iter().any(|it| !answers.found.contains_key(it)) {
            why.insert(0, "OSV unreachable and not cached".into());
        }
        if !why.is_empty() {
            self.unchecked(what, &why.join("; "));
        }
        Ok(answers.found)
    }

    // the scan --------------------------------------------------------------

    pub fn run(mut self) -> Result<Outcome> {
        let started_at = crate::utils::os::now();
        crate::utils::walk::forget_walks();
        self.use_sources();
        self.status("Fetching CISA's known-exploited list");
        let kev = kev::kev(&self.cache, self.net, self.opts.offline);
        self.kev = self.guard("CISA KEV (exploited-in-the-wild marks)", kev, HashSet::new())?;
        self.status("Fetching EPSS's exploit predictions");
        let epss = crate::sources::epss::refresh(&self.cache, self.net, self.opts.offline);
        self.guard("EPSS (exploit predictions)", epss, 0)?;
        let (log, note, status) = (self.log, self.note, self.status);
        self.repos = repos::scope(self.opts.paths.as_deref(), &self.home, log, note, status);
        let git = self.repos.iter().filter(|(_, r)| repos::is_git(r)).count() as i64;
        self.count("git repos", git);
        self.status("Listing the repos' files");
        crate::utils::walk::prewalk(&self.repos.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>());
        let found: Vec<Component> = if self.opts.machine { machine::run(&mut self)? } else { Vec::new() };
        supply_chain::run(&mut self, &found)?;
        if !self.opts.no_malware {
            crate::checks::malware::run(&mut self);
        }
        self.status("Rating the findings (CVSS for the CVEs without one: OSV, then CVE.org)");
        crate::checks::severity::enrich(&self.cache, self.net, self.opts.offline, &mut self.findings);
        self.status("Saving the findings");
        self.cache.replace_findings(&self.findings)?;
        let totals = (self.unfixed, self.unknown_licenses);
        let scan_id = crate::history::record_scan_totals(
            &self.cache,
            started_at,
            &self.findings,
            &self.counts,
            totals,
            &self.opts,
        )?;
        self.cache.close()?;
        Ok(Outcome {
            findings: self.findings,
            counts: self.counts,
            unfixed: self.unfixed,
            unknown_licenses: self.unknown_licenses,
            scan_id,
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
        let order = ecosystems::order(&eco);
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
            // Only a fix newer than what's installed repairs it. Fixes that are
            // all older end an earlier interval: the installed version's own
            // (reintroduced) interval has none, so it counts as unfixed rather
            // than recommending a downgrade. Each record names its own fix, and
            // only the highest of them repairs the group: a distro's first,
            // incomplete update and its CVE record are aliases with different
            // fixes (Ubuntu's USN-8477-1 for tar, then UBUNTU-CVE-2026-5704).
            let safe = group
                .iter()
                .filter_map(|r| {
                    let fixes = osv::fixed_versions(r, &eco, &pkg, newer);
                    versions::pick_safe_by(&qver, &fixes, |a, b| order.cmp(a, b))
                })
                .max_by(|a, b| order.cmp(a, b));
            let Some(safe) = safe else {
                self.unfixed += 1;
                // No released fix: still worth knowing when it is Critical,
                // High or exploited in the wild. A warning with the
                // mitigation, and `wpantry watch` asks again often.
                let severity = severity_of(main);
                let kev = group.iter().any(|r| is_kev(r, &self.kev));
                if high_impact(&severity) || kev {
                    let id = display_id(main);
                    let step = mitigation(&id).unwrap_or_else(|| {
                        "No fix released for this package yet: keep checking (wpantry watch, or an hourly schedule) and reduce exposure where you can".into()
                    });
                    self.add(Finding {
                        vuln_id: id,
                        status: "warn".into(),
                        kev,
                        severity,
                        note: format!(
                            "{} (no fix released for {} yet)",
                            str_at(main, "summary"),
                            if eco.is_empty() { "it" } else { &eco }
                        ),
                        fix_cmd: step,
                        ..Finding::of(c)
                    });
                }
                continue;
            };
            failing = failing || status == "fail";
            let kev = group.iter().any(|r| is_kev(r, &self.kev));
            // The range the installed version fell in, from whichever record
            // of the group names one.
            let affected_range = group
                .iter()
                .map(|r| osv::affected_range(r, &eco, &pkg, &qver, |a, b| order.cmp(a, b)))
                .find(|s| !s.is_empty())
                .unwrap_or_default();
            let (fix_cmd, fix_auto) = fix_with(c, &safe);
            self.add(Finding {
                vuln_id: display_id(main),
                status: status.into(),
                fixed: safe.clone(),
                kev,
                severity: severity_of(main),
                note: str_at(main, "summary").into(),
                fix_cmd,
                fix_auto,
                affected_range,
                ..Finding::of(c)
            });
        }
        failing
    }

    /// End-of-life (fails) and behind-the-latest-release (warns) findings
    /// for a component endoflife.date knows.
    pub fn eol(&mut self, c: &Component, failing: bool) -> Result<()> {
        let Some((product, cycle)) = c.eol.clone() else { return Ok(()) };
        let r = endoflife::eol(&self.cache, self.net, &product, &cycle, self.opts.offline);
        let Some(res) = self.guard(&format!("end of life for {product}"), r, None)? else { return Ok(()) };
        if let Some(ended) = &res.ended {
            let first = res.supported.first().cloned().unwrap_or_default();
            let shown: Vec<&str> = res.supported.iter().take(4).map(String::as_str).collect();
            let (fix_cmd, _) = fix_with(c, &first);
            self.add(Finding {
                vuln_id: "EOL".into(),
                status: "fail".into(),
                fix_cmd,
                note: format!("{product} {cycle} reached end of life on {ended}; supported: {}", shown.join(", ")),
                ..Finding::of(c)
            });
        } else if !res.latest.is_empty() && !failing && !versions::same_or_newer(&c.version, &res.latest) {
            let (fix_cmd, fix_auto) = fix_with(c, &res.latest);
            self.add(Finding {
                vuln_id: "OUTDATED".into(),
                status: "warn".into(),
                fixed: res.latest.clone(),
                fix_cmd,
                fix_auto,
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
mod tests;
