//! The findings: one per model file or template file with something to
//! say, kind `model`, the component its hub repo id and file name when the
//! store says them, else its path; the rest counted as checked. A clean
//! result is "no known problem found", never "safe": a static check can't
//! see behaviour trained into the weights.

use super::known_bad::{self, List};
use super::{Issue, Level, Model, Where, ids};
use crate::checks::Scan;
use crate::checks::files::{Check, Job};
use crate::finding::Finding;
use crate::utils::files::short;
use std::path::PathBuf;

/// What the count of clean files is called in the report.
pub const CHECKED: &str = "AI model files and chat templates checked";

/// Every model and template the files pass read, as findings.
pub fn models(scan: &mut Scan) {
    let repos: Vec<PathBuf> = scan.repos.iter().map(|(_, r)| r.clone()).collect();
    let machine = scan.opts.machine && !scan.opts.scoped();
    let jobs = super::jobs(&repos, machine, &scan.home);
    if jobs.is_empty() {
        return;
    }
    scan.status("Reading AI model files and chat templates");
    let results = scan.read_files();
    let found: Vec<(Job, Vec<Model>)> = jobs.iter().map(|j| (j.clone(), results.models(j))).collect();
    let store = scan.malware.as_ref().map(|m| m.store.clone());
    let list = List::bundled();
    let names: Vec<(PathBuf, String)> = scan.repos.iter().map(|(n, r)| (r.clone(), n.clone())).collect();
    let mut read = 0i64;
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for (job, models) in found {
        let Check::Models(at) = job.check else { continue };
        let repo_name = names.iter().find(|(r, _)| *r == job.root).map(|(_, n)| n.clone());
        for m in models {
            if !seen.insert(m.path.clone()) {
                continue;
            }
            read += 1;
            let mut issues = m.result.issues.clone();
            issues.extend(listed(&list, store.as_deref(), at, &m));
            let Some(f) = finding(at, repo_name.as_deref(), &m, super::sorted(issues)) else { continue };
            scan.add(f);
        }
    }
    scan.count(CHECKED, read);
}

/// The hub repo id a model came from: a hub cache's repo, or an Ollama
/// model pulled from Hugging Face (`hf.co/org/name:tag`).
fn hub_repo(at: Where, m: &Model) -> Option<String> {
    match at {
        Where::Hub if !m.meta.repo.is_empty() => Some(m.meta.repo.clone()),
        Where::Ollama => {
            let n = m.meta.repo.rsplit_once(':').map_or(m.meta.repo.as_str(), |(n, _)| n);
            ["hf.co/", "huggingface.co/"].iter().find_map(|p| n.strip_prefix(p)).map(String::from)
        }
        _ => None,
    }
}

/// What the known-bad list and the user's indicator lists say of a file:
/// a listed repo, hash or Ollama model fails; a demonstration repo, or a
/// repo of an account that published malicious models, warns.
pub fn listed(list: &List, store: Option<&crate::sources::indicator_store::Store>, at: Where, m: &Model) -> Vec<Issue> {
    let mut out = Vec::new();
    if let Some(repo) = hub_repo(at, m) {
        if let Some(entry) = list.repo(&repo) {
            out.push(Issue::new(ids::KNOWN_BAD, Level::Fail, format!("on the known-bad list: {entry}")));
        } else if let Some(r) = list.demo(&repo) {
            out.push(Issue::new(
                ids::RESEARCH_DEMO,
                Level::Warn,
                format!("repo {r} is a public demonstration of an attack on model users ({})", list.source),
            ));
        } else if let Some(owner) = list.owner(&repo) {
            out.push(Issue::new(
                ids::KNOWN_BAD_OWNER,
                Level::Warn,
                format!(
                    "published by {owner}, an account behind confirmed malicious models ({}); this repo isn't on the list itself",
                    list.source
                ),
            ));
        }
    }
    if at == Where::Ollama
        && let Some(entry) = list.ollama(&m.meta.repo)
    {
        out.push(Issue::new(ids::KNOWN_BAD, Level::Fail, format!("on the known-bad list: {entry}")));
    }
    if let Some(h) = &m.meta.sha256 {
        if let Some(entry) = list.hash(h) {
            out.push(Issue::new(ids::KNOWN_BAD, Level::Fail, format!("on the known-bad list: {entry}")));
        } else if let Some(entry) = store.and_then(|s| known_bad::in_store(s, h)) {
            out.push(Issue::new(ids::KNOWN_BAD, Level::Fail, format!("on an indicator list: {entry}")));
        }
    }
    out
}

/// How the report names a file: the hub repo and file, the Ollama model,
/// the repo and its path, or the path.
pub fn component(at: Where, repo_name: Option<&str>, m: &Model) -> String {
    match at {
        Where::Hub if !m.meta.repo.is_empty() => format!("{}/{}", m.meta.repo, m.meta.name),
        Where::Ollama if !m.meta.repo.is_empty() => format!("ollama {}", m.meta.repo),
        Where::Tree if repo_name.is_some() => format!("{}/{}", repo_name.unwrap_or_default(), m.rel),
        _ => short(&m.path.to_string_lossy()),
    }
}

/// The finding for one file, or None when nothing was found in it.
pub fn finding(at: Where, repo_name: Option<&str>, m: &Model, issues: Vec<Issue>) -> Option<Finding> {
    let first = issues.first()?;
    let status = if first.level == Level::Fail { "fail" } else { "warn" };
    let mut notes: Vec<String> = Vec::new();
    for i in &issues {
        let n = if i.level == Level::Unchecked { format!("not checked: {}", i.note) } else { i.note.clone() };
        if !notes.contains(&n) {
            notes.push(n);
        }
    }
    let mut note = notes.join("; ");
    if note.chars().count() > 600 {
        note = note.chars().take(600).collect::<String>() + "…";
    }
    Some(Finding {
        kind: "model".into(),
        component: component(at, repo_name, m),
        location: short(&m.path.to_string_lossy()),
        vuln_id: first.id.into(),
        status: status.into(),
        note,
        fix_cmd: fix(first.id).into(),
        ..Default::default()
    })
}

/// What to do about a finding, by its first id.
pub fn fix(id: &str) -> &'static str {
    match id {
        ids::KNOWN_BAD | ids::APPENDED_PROGRAM => {
            "Don't load it or run anything its output tells you to; delete the file (and the repo's whole cache folder), and if a command it printed was run, treat the machine as compromised"
        }
        ids::TRAILING_DATA | ids::DATA_GAP => {
            "Don't run anything it tells you to; get the model again from its publisher and compare hashes, or delete it"
        }
        ids::DROPPER | ids::DOWNLOAD | ids::INJECTION => {
            "Don't use it with an agent that runs commands; delete it, or replace its chat template with the base model's"
        }
        ids::NOT_CHECKED => "Not checked: get the model from its publisher and compare its hash before you use it",
        ids::KNOWN_BAD_OWNER => {
            "Check where this model came from before you load it; prefer the original publisher's upload, and delete it if you can't tell"
        }
        ids::RESEARCH_DEMO => {
            "A demonstration of an attack, not a model to use: delete it unless you are studying the attack, and don't load it with tools that run code"
        }

        _ => "Read the chat template before you use the model with an agent that can run commands",
    }
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
