//! The pass: every content check over every root it is given, each file
//! stat once and read once, the checks' per-file steps side by side.

use super::{Contents, FileView, Read, Stat, When};
use crate::checks::documents::{self, Doc};
use crate::checks::hidden::{self, Hidden};
use crate::checks::malware::targets::{self, Scope};
use crate::checks::malware::yara::Loaded;
use crate::checks::supply_chain::mptcp::{self, Exposure};
use crate::checks::suspects::{self, Kind, Suspect};
use crate::db::Cache;
use crate::utils::parallel;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A root's walk: each directory and its files.
type Walk = Vec<(PathBuf, Vec<String>)>;

/// A check that reads file contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Check {
    Hidden,
    Suspects(Kind),
    Mptcp,
    Documents,
    Malware(Scope),
    /// The prebuilt binaries a repo's npm dependencies ship.
    Blobs,
}

/// One check over one root, `depth` levels down.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Job {
    pub check: Check,
    pub root: PathBuf,
    pub depth: usize,
}

impl Job {
    pub fn new(check: Check, root: &Path, depth: usize) -> Job {
        Job { check, root: root.to_path_buf(), depth }
    }
}

/// A check's findings for one root.
#[derive(Clone, Debug, PartialEq)]
pub enum Found {
    Hidden(Vec<Hidden>),
    Suspects(Vec<Suspect>),
    Mptcp(Vec<Exposure>),
    Documents(Vec<Doc>),
    /// The files the scan counts, each as it was read.
    Malware(Vec<(PathBuf, targets::Scanned)>),
    Blobs(Vec<Suspect>),
}

/// What a check reads of one root, and what it knows without reading.
enum Plan {
    Hidden(hidden::Plan),
    Suspects(suspects::Plan),
    Mptcp(mptcp::Plan),
    Documents(documents::Plan),
    Malware(targets::Plan),
    Blobs(suspects::blobs::Plan),
}

impl Plan {
    fn reads(&self) -> &[Read] {
        match self {
            Plan::Hidden(p) => &p.reads,
            Plan::Suspects(p) => &p.reads,
            Plan::Mptcp(p) => &p.reads,
            Plan::Documents(p) => &p.reads,
            Plan::Malware(p) => &p.reads,
            Plan::Blobs(p) => &p.reads,
        }
    }
}

/// One file's result for one check.
#[derive(Debug, PartialEq)]
pub(crate) enum Out {
    Hidden(Vec<Hidden>),
    Suspects(suspects::FileResult),
    Mptcp(Option<mptcp::Facts>),
    Documents(Vec<Doc>),
    Malware(targets::Scanned),
    Blob(Option<String>),
}

fn plan(job: &Job, walk: &[(PathBuf, Vec<String>)], stat: super::Stats) -> Plan {
    match job.check {
        Check::Hidden => Plan::Hidden(hidden::plan(&job.root, walk, stat)),
        Check::Suspects(kind) => Plan::Suspects(suspects::plan(&job.root, kind, walk, stat)),
        Check::Mptcp => Plan::Mptcp(mptcp::plan(&job.root, walk, stat)),
        Check::Documents => Plan::Documents(documents::plan(&job.root, walk, stat)),
        Check::Malware(scope) => Plan::Malware(targets::plan(scope, &job.root, walk, stat)),
        Check::Blobs => Plan::Blobs(suspects::blobs::plan(&job.root)),
    }
}

fn file(job: &Job, rules: Option<&Loaded>, read: &Read, c: &Contents) -> Out {
    match job.check {
        Check::Hidden => Out::Hidden(hidden::file(read, c)),
        Check::Suspects(kind) => Out::Suspects(suspects::file(kind, read, c)),
        Check::Mptcp => Out::Mptcp(mptcp::file(read, c)),
        Check::Documents => Out::Documents(documents::file(read, c)),
        Check::Malware(scope) => Out::Malware(targets::file(scope, rules, read, c)),
        Check::Blobs => Out::Blob(suspects::blobs::file(read, c)),
    }
}

fn finish(job: &Job, plan: &Plan, outs: &[Option<Out>]) -> Found {
    macro_rules! of {
        ($v:ident) => {
            outs.iter().map(|o| if let Some(Out::$v(x)) = o { Some(x) } else { None }).collect::<Vec<_>>()
        };
    }
    match plan {
        Plan::Hidden(p) => Found::Hidden(hidden::finish(&job.root, p, &of!(Hidden))),
        Plan::Suspects(p) => Found::Suspects(suspects::finish(p, &of!(Suspects))),
        Plan::Mptcp(p) => Found::Mptcp(mptcp::finish(p, &of!(Mptcp))),
        Plan::Documents(p) => Found::Documents(documents::finish(p, &of!(Documents))),
        Plan::Malware(p) => Found::Malware(targets::finish(p, &of!(Malware))),
        Plan::Blobs(p) => Found::Blobs(suspects::blobs::finish(p, &of!(Blob))),
    }
}

/// Every job's findings.
#[derive(Default)]
pub struct Results {
    found: HashMap<Job, Found>,
    /// The malware scan's rules, for a job run on demand.
    rules: Option<Arc<Loaded>>,
}

impl Results {
    /// `job`'s findings: from the pass, or (a job it wasn't given) run now.
    pub fn get(&self, job: &Job) -> Found {
        match self.found.get(job) {
            Some(f) => f.clone(),
            None => run_cached(std::slice::from_ref(job), None, self.rules.clone())
                .found
                .remove(job)
                .expect("the job just run"),
        }
    }

    pub fn hidden(&self, root: &Path) -> Vec<Hidden> {
        match self.get(&Job::new(Check::Hidden, root, hidden::DEPTH)) {
            Found::Hidden(v) => v,
            _ => unreachable!("a hidden-text job finds hidden text"),
        }
    }

    pub fn suspects(&self, root: &Path, kind: Kind) -> Vec<Suspect> {
        match self.get(&Job::new(Check::Suspects(kind), root, suspects::DEPTH)) {
            Found::Suspects(v) => v,
            _ => unreachable!("a suspect-code job finds suspect code"),
        }
    }

    pub fn mptcp(&self, root: &Path) -> Vec<Exposure> {
        match self.get(&Job::new(Check::Mptcp, root, mptcp::DEPTH)) {
            Found::Mptcp(v) => v,
            _ => unreachable!("an MPTCP job finds exposures"),
        }
    }

    pub fn documents(&self, root: &Path, depth: usize) -> Vec<Doc> {
        match self.get(&Job::new(Check::Documents, root, depth)) {
            Found::Documents(v) => v,
            _ => unreachable!("a documents job finds documents"),
        }
    }

    /// The binaries a repo's npm dependencies ship, before the policy.
    pub fn blobs(&self, root: &Path) -> Vec<Suspect> {
        match self.get(&Job::new(Check::Blobs, root, 0)) {
            Found::Blobs(v) => v,
            _ => unreachable!("a blobs job finds blobs"),
        }
    }

    /// A malware job's files, each as it was read.
    pub fn malware(&self, job: &Job) -> Vec<(PathBuf, targets::Scanned)> {
        match self.get(job) {
            Found::Malware(v) => v,
            _ => unreachable!("a malware job finds files"),
        }
    }
}

/// Run `jobs`: each root walked once (the walk is shared), each file
/// stat once and read once, at the largest cap any check asks of it,
/// every check's per-file step on it side by side, then each job's
/// findings from its files' results.
pub fn run(jobs: &[Job]) -> Results {
    run_cached(jobs, None, None)
}

/// [`run`], with each file's results kept in `cache` ([`super::cache`]) (a
/// file that hasn't changed since a check last read it isn't read again),
/// and the malware scan's `rules`.
pub fn run_cached(jobs: &[Job], cache: Option<&Cache>, rules: Option<Arc<Loaded>>) -> Results {
    let salt = rules.as_ref().map(|r| r.hash.clone()).unwrap_or_default();
    let started = crate::utils::os::now();
    let mut uniq: Vec<Job> = Vec::new();
    for j in jobs {
        if !uniq.contains(j) {
            uniq.push(j.clone());
        }
    }
    let jobs = uniq;
    let walks: Vec<Walk> = jobs.iter().map(|j| crate::utils::walk::walk(&j.root, j.depth)).collect();
    // One view per file, from each root's deepest walk (the others are
    // that walk cut short).
    let mut deepest: HashMap<&Path, usize> = HashMap::new();
    for (j, job) in jobs.iter().enumerate() {
        let d = deepest.entry(job.root.as_path()).or_insert(j);
        if jobs[*d].depth < job.depth {
            *d = j;
        }
    }
    let mut index: HashMap<PathBuf, usize> = HashMap::new();
    let mut views: Vec<FileView> = Vec::new();
    for (j, w) in walks.iter().enumerate() {
        if deepest.get(jobs[j].root.as_path()) != Some(&j) {
            continue;
        }
        for (dir, files) in w {
            for f in files {
                let p = dir.join(f);
                if let std::collections::hash_map::Entry::Vacant(e) = index.entry(p) {
                    views.push(FileView::new(e.key().clone()));
                    e.insert(views.len() - 1);
                }
            }
        }
    }
    parallel::par_map(&views, parallel::cores(), |v| v.stat());
    let plans: Vec<Plan> = {
        let stat = |p: &Path| -> Option<Stat> {
            match index.get(p) {
                Some(&i) => views[i].stat(),
                None => FileView::new(p.to_path_buf()).stat(),
            }
        };
        // Side by side: a plan stats nothing new, but names every file, and
        // the dependency check lists node_modules.
        let items: Vec<(&Job, &Walk)> = jobs.iter().zip(&walks).collect();
        parallel::par_map(&items, parallel::cores(), |(j, w)| plan(j, w, &stat))
    };
    // Each read's view, found once.
    let mut users: Vec<Vec<(usize, usize)>> = vec![Vec::new(); views.len()];
    let mut view_of: Vec<Vec<usize>> = Vec::with_capacity(plans.len());
    for (j, p) in plans.iter().enumerate() {
        let mut of = Vec::with_capacity(p.reads().len());
        for (r, read) in p.reads().iter().enumerate() {
            let i = *index.entry(read.path.clone()).or_insert_with(|| {
                views.push(FileView::new(read.path.clone()));
                users.push(Vec::new());
                views.len() - 1
            });
            users[i].push((j, r));
            of.push(i);
        }
        view_of.push(of);
    }
    drop(index);
    let mut outs: Vec<Vec<Option<Out>>> = plans.iter().map(|p| p.reads().iter().map(|_| None).collect()).collect();
    let stat_of = |j: usize, r: usize| views[view_of[j][r]].stat();
    let mut store = cache.map(|c| super::cache::Store::load(c, &jobs, &salt));
    let mut hits: HashMap<&Path, usize> = HashMap::new();
    if let Some(s) = &store {
        for (j, p) in plans.iter().enumerate() {
            for (r, read) in p.reads().iter().enumerate() {
                if let Some(st) = stat_of(j, r) {
                    outs[j][r] = s.get(&jobs[j], read, &st);
                    *hits.entry(jobs[j].root.as_path()).or_default() += usize::from(outs[j][r].is_some());
                }
            }
        }
    }
    for u in &mut users {
        u.retain(|&(j, r)| outs[j][r].is_none());
    }
    let todo: Vec<usize> = (0..views.len()).filter(|&i| !users[i].is_empty()).collect();
    let done: Vec<Vec<(usize, usize, Out)>> = parallel::par_map(&todo, parallel::cores(), |&i| {
        let v = &views[i];
        let reads: Vec<(usize, usize, &Read)> = users[i].iter().map(|&(j, r)| (j, r, &plans[j].reads()[r])).collect();
        let cap = |when| reads.iter().filter(|(_, _, r)| r.when == when).map(|(_, _, r)| r.cap).max().unwrap_or(0);
        let (head, bytes) = v.load(cap(When::Always), cap(When::Program), targets::looks_executable);
        let program = targets::looks_executable(&head);
        reads
            .iter()
            .map(|&(j, r, read)| {
                let whole = read.cap > 0 && (read.when == When::Always || program);
                let c =
                    Contents { bytes: bytes.as_deref().filter(|b| whole && b.len() as u64 <= read.cap), head: &head };
                (j, r, file(&jobs[j], rules.as_deref(), read, &c))
            })
            .collect()
    });
    let mut missed: std::collections::HashSet<&Path> = std::collections::HashSet::new();
    for (j, r, o) in done.into_iter().flatten() {
        missed.insert(jobs[j].root.as_path());
        outs[j][r] = Some(o);
    }
    if let (Some(c), Some(mut s)) = (cache, store.take()) {
        // A root whose every result came from its record, and that lost
        // none, keeps its record as it is.
        let roots: std::collections::HashSet<&Path> = jobs.iter().map(|j| j.root.as_path()).collect();
        let unchanged: std::collections::HashSet<&Path> = roots
            .into_iter()
            .filter(|root| !missed.contains(root) && hits.get(root).copied().unwrap_or(0) == s.old_count(root))
            .collect();
        for root in &unchanged {
            s.unchanged(root);
        }
        for (j, p) in plans.iter().enumerate() {
            if unchanged.contains(jobs[j].root.as_path()) {
                continue;
            }
            for (r, read) in p.reads().iter().enumerate() {
                if let (Some(o), Some(st)) = (&outs[j][r], stat_of(j, r)) {
                    s.put(&jobs[j], read, &st, o);
                }
            }
        }
        s.save(c, started);
    }
    let items: Vec<(&Job, &Plan, &Vec<Option<Out>>)> =
        jobs.iter().zip(&plans).zip(&outs).map(|((j, p), o)| (j, p, o)).collect();
    // Finishing a hidden-text job runs git for the commit messages.
    let found = parallel::par_map(&items, parallel::PROBES, |(j, p, o)| finish(j, p, o));
    Results { found: jobs.into_iter().zip(found).collect(), rules }
}

#[cfg(test)]
#[path = "pass_tests.rs"]
mod tests;
