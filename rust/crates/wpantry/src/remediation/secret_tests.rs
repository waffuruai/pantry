use super::*;
use std::collections::VecDeque;

/// A scripted terminal and a command log: answers in order, commands
/// answered by the first matching rule.
struct Fake {
    answers: VecDeque<bool>,
    secrets: VecDeque<&'static str>,
    said: Vec<String>,
    ran: Vec<String>,
    rules: Vec<(&'static str, bool, &'static str)>,
}

impl Fake {
    fn new(answers: &[bool], secrets: &[&'static str], rules: Vec<(&'static str, bool, &'static str)>) -> Fake {
        Fake {
            answers: answers.iter().copied().collect(),
            secrets: secrets.iter().copied().collect(),
            said: vec![],
            ran: vec![],
            rules,
        }
    }
}

impl Io for Fake {
    fn say(&mut self, line: &str) {
        self.said.push(line.to_string());
    }
    fn ask(&mut self, q: &str, default: bool) -> bool {
        self.said.push(format!("? {q}"));
        self.answers.pop_front().unwrap_or(default)
    }
    fn secret(&mut self, _: &str) -> Option<String> {
        self.secrets.pop_front().map(str::to_string)
    }
    fn run(&mut self, argv: &[&str]) -> (bool, String) {
        let line = argv.join(" ");
        self.ran.push(line.clone());
        for (needle, ok, out) in &self.rules {
            if line.contains(needle) {
                return (*ok, out.to_string());
            }
        }
        (true, String::new())
    }
}

fn t() -> Target {
    Target { repo: "~/r".into(), file: ".env".into(), hits: vec![("github-pat".into(), 2, "abc123".into())] }
}

const TOOLS: (&str, bool, &str) = ("filter-repo -h", true, "usage: --sensitive-data-removal");

#[test]
fn a_secret_finding_names_its_repo_file_and_every_hit() {
    let fix = crate::checks::supply_chain::leaks::fix("~/my repo", "a.env", &[("jwt", 3, "c1")], false);
    let f = |line: i64, commit: &str| Finding {
        kind: "secret".into(),
        component: "~/my repo/a.env".into(),
        location: format!("line {line}, commit {commit}"),
        vuln_id: "jwt".into(),
        fix_cmd: fix.clone(),
        ..Default::default()
    };
    let all = [f(3, "c1"), f(9, "c2")];
    let got = target(&all[0], &all).unwrap();
    assert_eq!((got.repo.as_str(), got.file.as_str(), got.hits.len()), ("~/my repo", "a.env", 2));
    assert!(target(&Finding { kind: "brew".into(), ..all[0].clone() }, &all).is_none());
}

#[test]
fn not_a_secret_adds_the_file_to_pantryignore() {
    let home = crate::utils::temp::TempDir::new("secret-home").unwrap();
    std::fs::create_dir_all(home.path().join("r")).unwrap();
    std::fs::write(home.path().join("r/.pantryignore"), "vendor/").unwrap();
    let mut io = Fake::new(&[false, true], &[], vec![("show abc123:.env", true, "A=1\nTOKEN=ghp_x\n")]);
    let out = run(&t(), &mut io, false, &home.path().join("work"), home.path()).unwrap();
    assert_eq!(out, Outcome::Ignored);
    assert!(io.said.iter().any(|l| l.contains("abc123 line 2: TOKEN=ghp_x")), "{:?}", io.said);
    assert_eq!(
        std::fs::read_to_string(home.path().join("r/.pantryignore")).unwrap(),
        "vendor/\n\n[secret github-pat]\n/.env\n"
    );
}

#[test]
fn a_real_secret_waits_for_rotation_then_rewrites_and_asks_before_the_push() {
    let home = crate::utils::temp::TempDir::new("secret-home").unwrap();
    let work = home.path().join("work");
    // not rotated: nothing runs past the question
    let mut io = Fake::new(&[true, false], &[], vec![]);
    assert_eq!(run(&t(), &mut io, false, &work, home.path()).unwrap(), Outcome::NotRotated);
    assert!(!io.ran.iter().any(|c| c.contains("clone")));
    // rotated, rewritten, push declined
    let rules = vec![
        TOOLS,
        ("remote get-url", true, "git@example:me/r.git\n"),
        ("rev-list", true, "c1\nc2\n"),
        ("grep -q", false, ""),
    ];
    let mut io = Fake::new(&[true, true, false], &["ghp_secret"], rules.clone());
    assert_eq!(run(&t(), &mut io, false, &work, home.path()).unwrap(), Outcome::Rewritten { pushed: false });
    assert!(io.ran.iter().any(|c| c.contains("clone --mirror git@example:me/r.git")));
    assert!(io.ran.iter().any(|c| c.contains("filter-repo --sensitive-data-removal --replace-text")));
    assert!(!io.ran.iter().any(|c| c.contains("push")), "{:?}", io.ran);
    assert!(!io.ran.iter().any(|c| c.contains("ghp_secret")), "the secret is never an argument: {:?}", io.ran);
    assert!(!work.exists(), "the run's files are removed");
    // pushed
    let mut io = Fake::new(&[true, true, true], &["ghp_secret"], rules);
    assert_eq!(run(&t(), &mut io, false, &work, home.path()).unwrap(), Outcome::Rewritten { pushed: true });
    assert!(io.ran.iter().any(|c| c.ends_with("push --force --mirror origin")));
}

#[test]
fn nothing_is_pushed_while_the_secret_is_still_there_or_the_tools_are_missing() {
    let home = crate::utils::temp::TempDir::new("secret-home").unwrap();
    let work = home.path().join("work");
    let rules = vec![TOOLS, ("remote get-url", true, "u\n"), ("rev-list", true, "c1\n"), ("grep -q", true, "")];
    let mut io = Fake::new(&[true, true, true], &["s"], rules);
    assert!(run(&t(), &mut io, false, &work, home.path()).is_err());
    assert!(!io.ran.iter().any(|c| c.contains("push")));
    let mut io = Fake::new(&[true, true], &["s"], vec![("filter-repo -h", false, "")]);
    let e = run(&t(), &mut io, false, &work, home.path()).unwrap_err().to_string();
    assert!(e.contains("git-filter-repo 2.47"), "{e}");
}

#[test]
fn a_dry_run_prints_the_script() {
    let home = crate::utils::temp::TempDir::new("secret-home").unwrap();
    let mut io = Fake::new(&[], &[], vec![]);
    assert_eq!(run(&t(), &mut io, true, &home.path().join("w"), home.path()).unwrap(), Outcome::Shown);
    assert!(io.said[0].starts_with("# If it's real") && io.ran.is_empty());
}
