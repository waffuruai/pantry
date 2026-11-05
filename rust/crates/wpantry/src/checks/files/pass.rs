//! The pass: every content check over every root it is given, each file
//! stat once and read once, the checks' per-file steps side by side.

use super::view::HEAD;
use super::{Contents, FileView, Read, Stat};
use crate::checks::documents::{self, Doc};
use crate::checks::hidden::{self, Hidden};
use crate::checks::malware;
use crate::checks::supply_chain::mptcp::{self, Exposure};
use crate::checks::suspects::{self, Kind, Suspect};
use crate::utils::parallel;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A check that reads file contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Check {
    Hidden,
    Suspects(Kind),
    Mptcp,
    Documents,
    /// Which files in a repo are programs, for the malware scan.
    Programs,
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
    Programs(Vec<PathBuf>),
}

/// What a check reads of one root, and what it knows without reading.
enum Plan {
    Hidden(hidden::Plan),
    Suspects(suspects::Plan),
    Mptcp(mptcp::Plan),
    Documents(documents::Plan),
    Programs(malware::Plan),
}

impl Plan {
    fn reads(&self) -> &[Read] {
        match self {
            Plan::Hidden(p) => &p.reads,
            Plan::Suspects(p) => &p.reads,
            Plan::Mptcp(p) => &p.reads,
            Plan::Documents(p) => &p.reads,
            Plan::Programs(p) => &p.reads,
        }
    }
}

/// One file's result for one check.
enum Out {
    Hidden(Vec<Hidden>),
    Suspects(suspects::FileResult),
    Mptcp(Option<mptcp::Facts>),
    Documents(Vec<Doc>),
    Program(bool),
}

fn plan(job: &Job, walk: &[(PathBuf, Vec<String>)], stat: super::Stats) -> Plan {
    match job.check {
        Check::Hidden => Plan::Hidden(hidden::plan(&job.root, walk, stat)),
        Check::Suspects(kind) => Plan::Suspects(suspects::plan(&job.root, kind, walk, stat)),
        Check::Mptcp => Plan::Mptcp(mptcp::plan(&job.root, walk, stat)),
        Check::Documents => Plan::Documents(documents::plan(&job.root, walk, stat)),
        Check::Programs => Plan::Programs(malware::plan(walk, stat)),
    }
}

fn file(job: &Job, read: &Read, c: &Contents) -> Out {
    match job.check {
        Check::Hidden => Out::Hidden(hidden::file(read, c)),
        Check::Suspects(kind) => Out::Suspects(suspects::file(kind, read, c)),
        Check::Mptcp => Out::Mptcp(mptcp::file(read, c)),
        Check::Documents => Out::Documents(documents::file(read, c)),
        Check::Programs => Out::Program(malware::file(c)),
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
        Plan::Programs(p) => Found::Programs(malware::finish(p, &of!(Program))),
    }
}

/// Every job's findings.
#[derive(Debug, Default)]
pub struct Results {
    found: HashMap<Job, Found>,
}

impl Results {
    /// `job`'s findings: from the pass, or (a job it wasn't given) run now.
    pub fn get(&self, job: &Job) -> Found {
        match self.found.get(job) {
            Some(f) => f.clone(),
            None => run(std::slice::from_ref(job)).found.remove(job).expect("the job just run"),
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

    pub fn programs(&self, root: &Path) -> Vec<PathBuf> {
        match self.get(&Job::new(Check::Programs, root, malware::DEEP)) {
            Found::Programs(v) => v,
            _ => unreachable!("a programs job finds programs"),
        }
    }
}

/// Run `jobs`: each root walked once (the walk is shared), each file
/// stat once and read once, at the largest cap any check asks of it,
/// every check's per-file step on it side by side, then each job's
/// findings from its files' results.
pub fn run(jobs: &[Job]) -> Results {
    let mut uniq: Vec<Job> = Vec::new();
    for j in jobs {
        if !uniq.contains(j) {
            uniq.push(j.clone());
        }
    }
    let jobs = uniq;
    let walks: Vec<Vec<(PathBuf, Vec<String>)>> =
        jobs.iter().map(|j| crate::utils::walk::walk(&j.root, j.depth)).collect();
    let mut index: HashMap<PathBuf, usize> = HashMap::new();
    let mut views: Vec<FileView> = Vec::new();
    for (dir, files) in walks.iter().flatten() {
        for f in files {
            let p = dir.join(f);
            if !index.contains_key(&p) {
                index.insert(p.clone(), views.len());
                views.push(FileView::new(p));
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
        jobs.iter().zip(&walks).map(|(j, w)| plan(j, w, &stat)).collect()
    };
    let mut users: Vec<Vec<(usize, usize)>> = vec![Vec::new(); views.len()];
    for (j, p) in plans.iter().enumerate() {
        for (r, read) in p.reads().iter().enumerate() {
            let i = *index.entry(read.path.clone()).or_insert_with(|| {
                views.push(FileView::new(read.path.clone()));
                users.push(Vec::new());
                views.len() - 1
            });
            users[i].push((j, r));
        }
    }
    let todo: Vec<usize> = (0..views.len()).filter(|&i| !users[i].is_empty()).collect();
    let done: Vec<Vec<(usize, usize, Out)>> = parallel::par_map(&todo, parallel::cores(), |&i| {
        let v = &views[i];
        let reads: Vec<(usize, usize, &Read)> = users[i].iter().map(|&(j, r)| (j, r, &plans[j].reads()[r])).collect();
        let cap = reads.iter().map(|(_, _, r)| r.cap).max().unwrap_or(0);
        let bytes = if cap > 0 { v.read(cap) } else { None };
        let head: &[u8] = match &bytes {
            _ if reads.iter().all(|(_, _, r)| r.cap > 0) => &[],
            Some(b) => &b[..b.len().min(HEAD)],
            None => v.head(),
        };
        reads
            .iter()
            .map(|&(j, r, read)| {
                let c = Contents {
                    bytes: bytes.as_deref().filter(|b| read.cap > 0 && b.len() as u64 <= read.cap),
                    head: if read.cap == 0 { head } else { &[] },
                };
                (j, r, file(&jobs[j], read, &c))
            })
            .collect()
    });
    let mut outs: Vec<Vec<Option<Out>>> = plans.iter().map(|p| p.reads().iter().map(|_| None).collect()).collect();
    for (j, r, o) in done.into_iter().flatten() {
        outs[j][r] = Some(o);
    }
    let items: Vec<(&Job, &Plan, &Vec<Option<Out>>)> =
        jobs.iter().zip(&plans).zip(&outs).map(|((j, p), o)| (j, p, o)).collect();
    // Finishing a hidden-text job runs git for the commit messages.
    let found = parallel::par_map(&items, parallel::PROBES, |(j, p, o)| finish(j, p, o));
    Results { found: jobs.into_iter().zip(found).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::temp::TempDir;

    fn write(d: &TempDir, rel: &str, body: &[u8]) -> PathBuf {
        let p = d.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn each_file_is_opened_once_whichever_checks_read_it() {
        let d = TempDir::new("pass").unwrap();
        let root = d.path();
        // Read as text by hidden text, suspect code and MPTCP, as a
        // document and an image by documents, and its head by programs.
        let svg = write(&d, "web/logo.svg", b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>x</script></svg>");
        let go = write(&d, "cmd/main.go", b"package main\nfunc main() { net.Listen(\"tcp\", \":80\") }\n");
        let js = write(&d, "web/app.js", b"const a = 1;\n");
        let sh = write(&d, "tools/run.sh", b"#!/bin/sh\necho hi\n");
        let blob = write(&d, "lib/addon.node", b"not a binary at all");
        let jobs = [
            Job::new(Check::Hidden, root, hidden::DEPTH),
            Job::new(Check::Suspects(Kind::Repo), root, suspects::DEPTH),
            Job::new(Check::Mptcp, root, mptcp::DEPTH),
            Job::new(Check::Documents, root, 6),
            Job::new(Check::Programs, root, malware::DEEP),
        ];
        let results = run(&jobs);
        for p in [&svg, &go, &js, &sh, &blob] {
            assert_eq!(super::super::view::opens(p), 1, "{} opened once", p.display());
        }
        assert_eq!(results.programs(root), std::slice::from_ref(&sh));
        assert!(results.suspects(root, Kind::Repo).iter().any(|s| s.id == "SUSPECT-BINARY-BLOB"));
        // The pass gives what each check finds alone.
        assert_eq!(results.hidden(root), hidden::scan_repo(root));
        assert_eq!(results.documents(root, 6), documents::scan_dir(root, 6));
        assert_eq!(results.mptcp(root), mptcp::scan_repo(root));
    }

    #[test]
    fn a_job_the_pass_was_not_given_runs_on_demand() {
        let d = TempDir::new("pass").unwrap();
        write(&d, "a.sh", b"#!/bin/sh\n");
        let results = run(&[]);
        assert_eq!(results.programs(d.path()), [d.path().join("a.sh")]);
    }
}
