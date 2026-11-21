//! `wpantry fix secret <id>`: take a committed secret out of a repo's git
//! history, a step at a time, with a person at the terminal. The secret
//! itself never reaches a report, a log or an argument: it is typed with
//! echo off and kept in a 0600 file that is removed when the run ends.
//!
//! The steps are the ones the finding's fix script names
//! ([`leaks::fix`](crate::checks::supply_chain::leaks::fix)): show the
//! line, ask whether it's real, and if it isn't, add the file to the
//! repo's `.pantryignore`. If it is and it has been rotated, rewrite
//! history in a fresh mirror clone with `git filter-repo
//! --sensitive-data-removal --replace-text`, check the secret is gone, and
//! force-push only after asking.

use crate::checks::supply_chain::leaks;
use crate::error::{Error, Result};
use crate::finding::Finding;
use std::path::{Path, PathBuf};

/// What the run needs from the world, so a test can stand in for it.
pub trait Io {
    fn say(&mut self, line: &str);
    /// A yes/no question; `default` on an empty answer.
    fn ask(&mut self, question: &str, default: bool) -> bool;
    /// A line typed with echo off; None at end of input.
    fn secret(&mut self, prompt: &str) -> Option<String>;
    /// Run a command: whether it exited 0, and its output.
    fn run(&mut self, argv: &[&str]) -> (bool, String);
}

/// One file's secrets in one repo.
#[derive(Clone, Debug, PartialEq)]
pub struct Target {
    /// The repo, as the finding names it (`~/…`).
    pub repo: String,
    pub file: String,
    /// (rule, line, commit) of each hit.
    pub hits: Vec<(String, i64, String)>,
}

/// The file a secret finding is about, with every hit in that file among
/// `findings`.
pub fn target(f: &Finding, findings: &[Finding]) -> Option<Target> {
    if f.kind != "secret" {
        return None;
    }
    let (repo, file) = leaks::fix_target(&f.fix_cmd)?;
    let at = |x: &Finding| {
        let (line, commit) = x.location.strip_prefix("line ")?.split_once(", commit ")?;
        Some((x.vuln_id.clone(), line.parse::<i64>().ok()?, commit.to_string()))
    };
    let hits: Vec<(String, i64, String)> =
        findings.iter().filter(|x| x.kind == "secret" && x.component == f.component).filter_map(at).collect();
    (!hits.is_empty()).then_some(Target { repo, file, hits })
}

/// How a run ended.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// `--dry-run`: the script, printed.
    Shown,
    /// Not a secret: the file was added to the repo's `.pantryignore`.
    Ignored,
    /// Real, but not rotated yet: nothing changed.
    NotRotated,
    /// History rewritten; `pushed` whether the force-push ran.
    Rewritten { pushed: bool },
    /// The person said no somewhere: nothing changed.
    Declined,
}

fn expand(p: &str, home: &Path) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(p),
    }
}

/// Walk `t` with a person at `io`. `work` is a directory of the run's own
/// (it is created, used for the mirror clone and the 0600 replacements
/// file, and removed). `home` expands `~/`.
pub fn run(t: &Target, io: &mut dyn Io, dry_run: bool, work: &Path, home: &Path) -> Result<Outcome> {
    let hits: Vec<(&str, i64, &str)> = t.hits.iter().map(|(r, l, c)| (r.as_str(), *l, c.as_str())).collect();
    if dry_run {
        io.say(&leaks::fix(&t.repo, &t.file, &hits, false));
        return Ok(Outcome::Shown);
    }
    let repo = expand(&t.repo, home);
    let repo_s = repo.to_string_lossy().to_string();
    io.say(&format!("==> {} in {} ({} hit{})", t.file, t.repo, hits.len(), if hits.len() == 1 { "" } else { "s" }));
    // 1. the lines, on this terminal only
    let mut shown = Vec::new();
    for (_, line, commit) in &hits {
        if shown.contains(&(*commit, *line)) || shown.len() >= 5 {
            continue;
        }
        shown.push((*commit, *line));
        let (ok, out) = io.run(&["git", "-C", &repo_s, "show", &format!("{commit}:{}", t.file)]);
        let text = if ok {
            out.lines().nth((*line as usize).saturating_sub(1)).unwrap_or("").to_string()
        } else {
            "(that commit isn't in this clone)".to_string()
        };
        io.say(&format!("  {commit} line {line}: {text}"));
    }
    if !io.ask("Is this a real secret?", false) {
        let mut rules: Vec<&str> = hits.iter().map(|(r, _, _)| *r).collect();
        rules.sort_unstable();
        rules.dedup();
        let section = if rules.len() == 1 { format!("[secret {}]", rules[0]) } else { "[secret]".into() };
        let ignore = repo.join(crate::checks::ignore::FILE);
        if !io.ask(&format!("Add /{} under {section} to {}?", t.file, ignore.display()), true) {
            return Ok(Outcome::Declined);
        }
        let mut text = std::fs::read_to_string(&ignore).unwrap_or_default();
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!("{}{section}\n/{}\n", if text.is_empty() { "" } else { "\n" }, t.file));
        std::fs::write(&ignore, text)?;
        io.say(&format!("  ✓ added to {}: commit it, and the next scan leaves it out", ignore.display()));
        return Ok(Outcome::Ignored);
    }
    if !io.ask("Have you rotated it, so the old value no longer works?", false) {
        io.say(
            "  Rotate it first (revoke it where it was issued, and replace it where it's used), then run this again.",
        );
        return Ok(Outcome::NotRotated);
    }
    // 2. the tools and the remote
    let (ok, help) = io.run(&["git", "filter-repo", "-h"]);
    if !ok || !help.contains("--sensitive-data-removal") {
        return Err(Error::Failed(
            "git-filter-repo 2.47 or later is needed: brew install git-filter-repo, or pipx install git-filter-repo"
                .into(),
        ));
    }
    let (ok, url) = io.run(&["git", "-C", &repo_s, "remote", "get-url", "origin"]);
    let url = url.trim().to_string();
    if !ok || url.is_empty() {
        return Err(Error::Failed(format!("{} has no origin remote to rewrite", t.repo)));
    }
    // 3. the secrets, typed with echo off, into a 0600 file of this run's
    std::fs::create_dir_all(work)?;
    let result = rewrite(io, work, &url, hits.len());
    let _ = std::fs::remove_dir_all(work);
    result
}

fn rewrite(io: &mut dyn Io, work: &Path, url: &str, hits: usize) -> Result<Outcome> {
    let mut secrets: Vec<String> = Vec::new();
    io.say(&format!(
        "Paste the secret{}, then Enter{}. Nothing is shown.",
        if hits == 1 { "" } else { "s, one per line" },
        if hits == 1 { "" } else { "; an empty line ends" }
    ));
    loop {
        match io.secret("Secret: ") {
            Some(s) if !s.trim().is_empty() => {
                secrets.push(s.trim().to_string());
                if hits == 1 {
                    break;
                }
            }
            _ => break,
        }
    }
    if secrets.is_empty() {
        return Ok(Outcome::Declined);
    }
    let expressions = work.join("replacements.txt");
    let body: String = secrets.iter().map(|s| format!("{s}==>REDACTED\n")).collect();
    write_private(&expressions, &body)?;
    let mirror = work.join("mirror.git");
    let (m, e) = (mirror.to_string_lossy().to_string(), expressions.to_string_lossy().to_string());
    io.say(&format!("==> Cloning {url} as a mirror"));
    let (ok, out) = io.run(&["git", "clone", "--mirror", url, &m]);
    if !ok {
        return Err(Error::Failed(format!("git clone --mirror {url}: {}", out.trim())));
    }
    io.say("==> Rewriting history without it");
    let (ok, out) = io.run(&["git", "-C", &m, "filter-repo", "--sensitive-data-removal", "--replace-text", &e]);
    if !ok {
        return Err(Error::Failed(format!("git filter-repo: {}", out.trim())));
    }
    // The secret is gone from every commit before anything is pushed:
    // `git grep -F -f` reads it from a 0600 file, never an argument.
    let patterns = work.join("patterns.txt");
    write_private(&patterns, &secrets.iter().map(|s| format!("{s}\n")).collect::<String>())?;
    let p = patterns.to_string_lossy().to_string();
    let (ok, revs) = io.run(&["git", "-C", &m, "rev-list", "--all"]);
    if !ok {
        return Err(Error::Failed("git rev-list on the rewritten clone failed: nothing was pushed".into()));
    }
    let revs: Vec<&str> = revs.split_whitespace().collect();
    for chunk in revs.chunks(200) {
        let mut argv = vec!["git", "-C", m.as_str(), "grep", "-q", "-F", "-f", p.as_str()];
        argv.extend(chunk);
        if io.run(&argv).0 {
            return Err(Error::Failed("the rewritten history still holds the secret: nothing was pushed".into()));
        }
    }
    io.say("  ✓ no commit in the rewritten history holds it");
    if !io.ask(&format!("Force-push the rewritten history to {url}? Everyone with a clone has to re-clone."), false) {
        io.say("  Not pushed: nothing changed on the remote.");
        return Ok(Outcome::Rewritten { pushed: false });
    }
    let (ok, out) = io.run(&["git", "-C", &m, "push", "--force", "--mirror", "origin"]);
    if !ok {
        // GitHub refuses its read-only refs (refs/pull/*); the branches and tags still go.
        io.say(&format!("  ⚠ the push reported errors (GitHub's pull-request refs are read-only):\n{}", out.trim()));
    }
    io.say("  ✓ pushed. Re-clone your copy; on GitHub, ask support to purge cached views and pull-request refs.");
    Ok(Outcome::Rewritten { pushed: true })
}

fn write_private(path: &Path, body: &str) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(body.as_bytes())?;
    Ok(())
}

#[cfg(test)]
#[path = "secret_tests.rs"]
mod tests;
