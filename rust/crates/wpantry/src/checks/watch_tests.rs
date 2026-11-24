//! Risk: a scan tells its watch steps out of the order `steps` promised,
//! skips one, or tells a finding twice or not at all. Oracle: `steps` for
//! the same options, and the scan's own outcome (no ignore file here, so
//! every finding made is a finding reported).

use super::*;
use crate::checks::{Options, Scan};
use crate::db::Cache;
use crate::utils::net::Fake;
use crate::utils::temp::TempDir;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Default)]
struct Recorder {
    steps: Mutex<Vec<String>>,
    at: Mutex<Vec<(PathBuf, At)>>,
    repos: Mutex<Vec<usize>>,
    findings: Mutex<Vec<(String, String)>>,
}

impl Watch for Recorder {
    fn step(&self, id: &str) {
        self.steps.lock().unwrap().push(id.to_string());
    }
    fn at(&self, path: &Path, what: At) {
        self.at.lock().unwrap().push((path.to_path_buf(), what));
    }
    fn repos(&self, n: usize) {
        self.repos.lock().unwrap().push(n);
    }
    fn finding(&self, f: &Finding) {
        let step = self.steps.lock().unwrap().last().cloned().unwrap_or_default();
        self.findings.lock().unwrap().push((step, f.key()));
    }
}

fn ids(opts: &Options) -> Vec<&'static str> {
    steps(opts).iter().map(|s| s.id).collect()
}

#[test]
fn the_steps_follow_the_options() {
    let base = Options::default();
    assert_eq!(
        ids(&base),
        [
            "sources",
            "repos",
            "dependencies",
            "secrets",
            "repo-files",
            "images",
            "extensions",
            "malicious",
            "malware",
            "rating"
        ]
    );
    let machine = Options { machine: true, ..Default::default() };
    assert_eq!(ids(&machine)[2], "machine");
    assert!(ids(&machine).contains(&"breach"));
    assert!(!ids(&Options { no_malware: true, ..Default::default() }).contains(&"malware"));
    let deep = ids(&Options { deep: true, ..Default::default() });
    assert_eq!(&deep[deep.len() - 2..], ["file-secrets", "rating"]);
    // Every id once, every title short and plain.
    let all = ids(&Options { machine: true, deep: true, ..Default::default() });
    let mut uniq = all.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), all.len());
    for s in steps(&Options { machine: true, deep: true, ..Default::default() }) {
        assert!(s.title.len() <= 60 && !s.title.ends_with('.'), "{s:?}");
        assert!(s.id.chars().all(|c| c.is_ascii_lowercase() || c == '-'), "{s:?}");
    }
    assert_eq!(At::File.name(), "file");
    assert_eq!(At::Dir.name(), "dir");
    Quiet.step("sources");
    Quiet.at(Path::new("/"), At::Dir);
    Quiet.repos(1);
    Quiet.finding(&Finding::default());
}

/// A deep scan of a folder holding a secret and a lockfile, offline: the
/// watch hears every step in order, each finding once in the step that
/// made it, and only paths inside the folder.
#[test]
fn a_scan_tells_its_watch_every_step_in_order_and_each_finding_once() {
    let tmp = TempDir::new("watch").unwrap();
    let dir = tmp.path().join("project");
    std::fs::create_dir_all(&dir).unwrap();
    // A GitHub token from the rules' own cases, stored reversed (tests/secret-cases.toml).
    let token: String = "gvrMOVt7kvW7QXR9RsHxWt65VWBByL5t718Z_phg".chars().rev().collect(); // gitleaks:allow
    std::fs::write(dir.join("settings.txt"), format!("token = {token}\n")).unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\n")
        .unwrap();
    let net = Fake::new(|r| panic!("offline, yet asked {}", r.url));
    let opts = Options {
        paths: Some(vec![dir.clone()]),
        machine: false,
        no_malware: true,
        deep: true,
        offline: true,
        ..Default::default()
    };
    let cache = Cache::open(Some(&tmp.path().join("w.db"))).unwrap();
    let rec = Recorder::default();
    let out = Scan::new(opts.clone(), cache, &net, &|_| {}, &|_| {}).with_watch(&rec).run().unwrap();

    assert_eq!(*rec.steps.lock().unwrap(), ids(&opts));
    assert_eq!(*rec.repos.lock().unwrap(), [1]);
    let told = rec.findings.lock().unwrap().clone();
    let mut told_keys: Vec<String> = told.iter().map(|(_, k)| k.clone()).collect();
    let mut made: Vec<String> = out.findings.iter().map(Finding::key).collect();
    told_keys.sort();
    made.sort();
    assert_eq!(told_keys, made, "each finding told once");
    let secret = told.iter().find(|(_, k)| k.starts_with("secret|")).expect("the token is found");
    assert_eq!(secret.0, "file-secrets", "told in the step that made it");
    let at = rec.at.lock().unwrap().clone();
    assert!(at.iter().any(|(p, w)| *w == At::File && p.ends_with("Cargo.lock")), "{at:?}");
    assert!(at.iter().any(|(p, w)| *w == At::File && p.ends_with("settings.txt")), "{at:?}");
    let canon = std::fs::canonicalize(&dir).unwrap();
    for (p, _) in &at {
        assert!(p.starts_with(&dir) || p.starts_with(&canon), "{} is outside the scan", p.display());
    }
}
