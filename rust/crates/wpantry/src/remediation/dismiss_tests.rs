//! `wpantry ignore` as a library call: a real repo scan, the command, and
//! the next scan, over a temp cache, a temp home and a temp config folder.
//! Risks and oracles, per test: a rule that doesn't leave the finding out
//! or leaves out a neighbour (the next scan's findings, compared by id), a
//! remove that doesn't bring it back (the scan after it), an action not
//! logged (the cache's events), and a JSON shape a program can't rely on
//! (the key sets).

use super::*;
use crate::checks::supply_chain::projects::projects;
use crate::checks::supply_chain::testing;
use crate::checks::{Options, ignore};
use crate::utils::files::{TestHome, test_home};
use crate::utils::net::Fake;
use crate::utils::temp::TempDir;

const LOCK: &str = r#"{"name": "app", "lockfileVersion": 3, "packages": {"": {"name": "app"}, "node_modules/lodash": {"version": "4.17.20"}, "node_modules/left-pad": {"version": "1.3.0"}}}"#;
const LOCK_SUB: &str = r#"{"name": "sub", "lockfileVersion": 3, "packages": {"": {"name": "sub"}, "node_modules/lodash": {"version": "4.17.20"}}}"#;
const NOW: f64 = 1_800_000_000.0;

struct Rig {
    d: TempDir,
    _home: TestHome,
    env: Env,
    root: PathBuf,
    name: String,
    net: Fake,
}

impl Rig {
    fn new() -> Rig {
        let home = test_home();
        let d = TempDir::new("ic").unwrap();
        let (_, root) = testing::repo(&d, "app");
        testing::write(&root, "package-lock.json", LOCK);
        testing::write(&root, "sub/package-lock.json", LOCK_SUB);
        let name = root.to_string_lossy().into_owned();
        let h = crate::utils::files::home();
        let env = Env { user_file: h.join(".config/wpantry/ignore"), home: h };
        Rig { d, _home: home, env, root, name, net: testing::osv_net(&[("npm", "lodash"), ("npm", "left-pad")]) }
    }

    /// Secrets the history scan would report: this file under two rules, and another file.
    fn secrets(&self) -> Vec<Finding> {
        let at = |file: &str, rule: &str| Finding {
            kind: "secret".into(),
            component: format!("{}/{file}", self.name),
            location: "line 2, commit 0123456789ab".into(),
            vuln_id: rule.into(),
            status: "fail".into(),
            ..Default::default()
        };
        vec![at("cfg.env", "github-pat"), at("cfg.env", "jwt"), at("other.env", "github-pat")]
    }

    /// A scan of the repo as `wpantry scan` runs it: the lockfiles, the
    /// secrets, the ignore files, then the cache's latest scan.
    fn scan(&self) -> (Vec<Finding>, Vec<(String, i64)>) {
        let mut s = testing::scan(&self.net, &self.d, Options::default());
        s.repos = vec![(self.name.clone(), self.root.clone())];
        let repos = s.repos.clone();
        projects(&mut s, &repos).unwrap();
        s.findings.extend(self.secrets());
        ignore::apply_with(&mut s, &self.env.user_file);
        s.cache.replace_findings(&s.findings).unwrap();
        crate::history::record_scan_totals(&s.cache, NOW, &s.findings, &s.counts, (0, 0), &s.opts).unwrap();
        let out = (s.findings.clone(), s.counts.clone());
        s.cache.close().unwrap();
        out
    }

    fn cache(&self) -> Cache {
        Cache::open(Some(&self.d.path().join("w.db"))).unwrap()
    }

    fn add(&self, id: &str, scope: Scope, reason: Option<&str>, all_places: bool) -> Reply {
        let c = self.cache();
        let r = add(&c, &self.env, id, scope, reason, all_places, NOW).unwrap();
        c.close().unwrap();
        r
    }

    fn list(&self, path: Option<&Path>) -> Reply {
        let c = self.cache();
        let r = list(&c, &self.env, path).unwrap();
        c.close().unwrap();
        r
    }

    fn remove(&self, id: &str, path: Option<&Path>) -> Reply {
        let c = self.cache();
        let r = remove(&c, &self.env, id, path).unwrap();
        c.close().unwrap();
        r
    }

    fn events(&self) -> Vec<Value> {
        let c = self.cache();
        let e = history::events_of(&c, EVENT).unwrap().into_iter().map(|e| e.detail).collect();
        c.close().unwrap();
        e
    }
}

fn j(r: &Reply) -> Value {
    serde_json::from_str(&r.json.dumps()).unwrap()
}

fn keys(v: &Value) -> Vec<&str> {
    v.as_object().unwrap().keys().map(String::as_str).collect()
}

fn find<'a>(fs: &'a [Finding], kind: &str, component: &str, id: &str, location_ends: &str) -> &'a Finding {
    fs.iter()
        .find(|f| {
            f.kind == kind && f.component.ends_with(component) && f.vuln_id == id && f.location.ends_with(location_ends)
        })
        .unwrap_or_else(|| panic!("no {kind} {component} {id} {location_ends} in {fs:#?}"))
}

fn ids(fs: &[Finding]) -> Vec<String> {
    let mut v: Vec<String> = fs.iter().map(Finding::id).collect();
    v.sort();
    v
}

fn without(fs: &[Finding], gone: &[&Finding]) -> Vec<String> {
    let gone: Vec<String> = gone.iter().map(|f| f.id()).collect();
    ids(fs).into_iter().filter(|i| !gone.contains(i)).collect()
}

#[test]
fn a_user_rule_leaves_out_that_finding_and_its_neighbours_stay_until_it_is_removed() {
    let t = Rig::new();
    let (before, _) = t.scan();
    let lodash = find(&before, "project", "lodash", "GHSA-lodash", "app/package-lock.json").clone();
    let sub = find(&before, "project", "lodash", "GHSA-lodash", "sub/package-lock.json");
    let pad = find(&before, "project", "left-pad", "GHSA-left-pad", "app/package-lock.json");
    assert_ne!(lodash.location, sub.location);
    let r = t.add(&lodash.id(), Scope::User, Some("fixture, not shipped"), false);
    assert_eq!(r.code, 0, "{:?}", r.error);
    let v = j(&r);
    assert_eq!(v["changed"], true);
    assert_eq!(v["rules"][0]["section"], "project GHSA-lodash");
    assert_eq!(v["rules"][0]["pattern"], lodash.location, "the whole path, outside your home");
    let (after, counts) = t.scan();
    assert_eq!(
        ids(&after),
        without(&before, &[&lodash]),
        "exactly that finding went: the same rule in another file and another rule in that file stay"
    );
    assert!(counts.contains(&("findings skipped by your ignore file".to_string(), 1)), "{counts:?}");
    // Remove brings it back.
    let r = t.remove(&lodash.id(), None);
    assert_eq!(r.code, 0, "{:?}", r.error);
    assert_eq!(j(&r)["removed"][0]["finding_id"], lodash.id());
    let (back, _) = t.scan();
    assert_eq!(ids(&back), ids(&before));
    let _ = pad;
    assert_eq!(std::fs::read_to_string(&t.env.user_file).unwrap(), "", "nothing of ours is left in the file");
}

#[test]
fn a_repo_rule_leaves_out_one_secret_file_under_one_rule() {
    let t = Rig::new();
    let (before, _) = t.scan();
    let pat = find(&before, "secret", "cfg.env", "github-pat", "").clone();
    let jwt = find(&before, "secret", "cfg.env", "jwt", "");
    let other = find(&before, "secret", "other.env", "github-pat", "");
    let r = t.add(&pat.id(), Scope::Repo, None, false);
    assert_eq!(r.code, 0, "{:?}", r.error);
    let text = std::fs::read_to_string(t.root.join(".pantryignore")).unwrap();
    assert!(text.starts_with("[secret github-pat]\n/cfg.env\n# wpantry ignore: F-"), "{text}");
    let (after, counts) = t.scan();
    assert_eq!(
        ids(&after),
        without(&before, &[&pat]),
        "the same file under another rule, and the same rule in another file, stay"
    );
    assert!(counts.contains(&("findings skipped by a repo's .pantryignore".to_string(), 1)), "{counts:?}");
    assert!(after.iter().any(|f| f.id() == jwt.id()) && after.iter().any(|f| f.id() == other.id()));
    // By rule id, as `list` shows it, the file is as it was.
    let listed = j(&t.list(Some(&t.root)));
    let rule = listed["rules"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(t.remove(&rule, Some(&t.root)).code, 0);
    assert_eq!(std::fs::read_to_string(t.root.join(".pantryignore")).unwrap(), "");
    assert_eq!(ids(&t.scan().0), ids(&before));
}

#[test]
fn adding_twice_says_so_and_a_logged_finding_no_scan_lists_is_already_done() {
    let t = Rig::new();
    let (fs, _) = t.scan();
    let f = find(&fs, "secret", "other.env", "github-pat", "").clone();
    assert_eq!(t.add(&f.id(), Scope::Repo, None, false).code, 0);
    let file = std::fs::read_to_string(t.root.join(".pantryignore")).unwrap();
    let again = t.add(&f.id(), Scope::Repo, None, false);
    assert_eq!(again.code, 0);
    assert_eq!(j(&again)["already"], true);
    assert_eq!(j(&again)["changed"], false);
    assert!(again.lines[0].contains("already"), "{:?}", again.lines);
    assert_eq!(std::fs::read_to_string(t.root.join(".pantryignore")).unwrap(), file, "nothing changed");
    assert_eq!(t.events().len(), 1, "and nothing was logged for it");
    // After a scan that left it out, the latest scan no longer lists it.
    t.scan();
    let r = t.add(&f.id(), Scope::Repo, None, false);
    assert_eq!((r.code, j(&r)["already"].clone()), (0, Value::Bool(true)), "{:?}", r.error);
    // Taken out by hand, and not in the scan: nothing to go on.
    std::fs::write(t.root.join(".pantryignore"), "").unwrap();
    t.scan();
    let r = t.add(&f.id(), Scope::Repo, None, false);
    assert_eq!(r.code, 0, "the scan after the hand edit lists it again, so it is added again: {:?}", r.error);
    assert_eq!(j(&r)["changed"], true);
}

#[test]
fn an_unknown_finding_and_no_scan_are_refused_with_a_code() {
    let t = Rig::new();
    let r = t.add("F-0000000000", Scope::User, None, false);
    assert_eq!((r.code, j(&r)["refused"]["code"].clone()), (1, Value::from("no-scan")));
    t.scan();
    let r = t.add("F-0000000000", Scope::User, None, false);
    assert_eq!(r.code, 1);
    let v = j(&r);
    assert_eq!((v["refused"]["code"].clone(), v["changed"].clone()), (Value::from("not-found"), Value::Bool(false)));
    assert!(r.error.unwrap().contains("wpantry fix list"), "tells where the ids are");
    assert!(!t.env.user_file.exists());
}

#[test]
fn what_cannot_be_ignored_is_refused_and_the_log_stays_empty() {
    let t = Rig::new();
    let posture = Finding {
        kind: "posture".into(),
        component: "FileVault".into(),
        location: "CIS 2.6.1".into(),
        vuln_id: "POSTURE-FILEVAULT".into(),
        status: "fail".into(),
        ..Default::default()
    };
    let c = t.cache();
    c.replace_findings(std::slice::from_ref(&posture)).unwrap();
    crate::history::record_scan_totals(&c, NOW, std::slice::from_ref(&posture), &[], (0, 0), &Options::default())
        .unwrap();
    c.close().unwrap();
    let r = t.add(&posture.id(), Scope::User, None, false);
    assert_eq!(r.code, 1);
    assert_eq!(j(&r)["refused"]["code"], "no-path");
    assert!(r.error.unwrap().contains("posture"), "points at the posture policy");
    assert!(t.events().is_empty());
}

#[test]
fn a_repo_cannot_hide_what_protects_its_owner_but_the_owner_can() {
    let t = Rig::new();
    let mal = Finding {
        kind: "project".into(),
        component: "evil-pkg".into(),
        location: t.root.join("package-lock.json").to_string_lossy().into_owned(),
        vuln_id: "MAL-2026-1".into(),
        status: "fail".into(),
        severity: "MALICIOUS".into(),
        ..Default::default()
    };
    let c = t.cache();
    c.replace_findings(std::slice::from_ref(&mal)).unwrap();
    crate::history::record_scan_totals(&c, NOW, std::slice::from_ref(&mal), &[], (0, 0), &Options::default()).unwrap();
    c.close().unwrap();
    let r = t.add(&mal.id(), Scope::Repo, None, false);
    assert_eq!((r.code, j(&r)["refused"]["code"].clone()), (1, Value::from("repo-cannot-skip")));
    assert!(!t.root.join(".pantryignore").exists());
    assert_eq!(t.add(&mal.id(), Scope::User, None, false).code, 0);
}

#[test]
fn every_action_is_logged_with_the_finding_scope_file_and_reason() {
    let t = Rig::new();
    let (fs, _) = t.scan();
    let f = find(&fs, "project", "left-pad", "GHSA-left-pad", "app/package-lock.json").clone();
    t.add(&f.id(), Scope::Repo, Some("not reachable"), false);
    t.remove(&f.id(), None);
    let events = t.events();
    assert_eq!(events.len(), 2, "{events:?}");
    let (a, r) = (&events[0], &events[1]);
    assert_eq!((a["action"].clone(), r["action"].clone()), (Value::from("add"), Value::from("remove")));
    assert_eq!(
        a["finding"],
        json!({"id": f.id(), "kind": "project", "component": "left-pad", "location": f.location, "vuln_id": "GHSA-left-pad"})
    );
    assert_eq!(
        (a["scope"].clone(), a["reason"].clone(), a["finding_id"].clone()),
        ("repo".into(), "not reachable".into(), f.id().into())
    );
    assert!(Path::new(a["file"].as_str().unwrap()).ends_with("app/.pantryignore"), "{}", a["file"]);
    assert_eq!(r["rules"], a["rules"], "the remove names the rules the add wrote");
    assert_eq!((r["scope"].clone(), r["file"].clone()), (a["scope"].clone(), a["file"].clone()));
    // The audit report carries them, with the scans.
    let c = t.cache();
    let h = crate::reporters::history(&c, 14).unwrap();
    c.close().unwrap();
    let kinds: Vec<&str> = h.events.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, ["scan", EVENT, EVENT]);
}

#[test]
fn list_shows_hand_written_and_command_written_rules_and_what_was_removed_by_hand() {
    let t = Rig::new();
    let (fs, _) = t.scan();
    std::fs::create_dir_all(t.env.user_file.parent().unwrap()).unwrap();
    std::fs::write(&t.env.user_file, "# research\n[malware]\n~/samples/\n").unwrap();
    let a = find(&fs, "secret", "cfg.env", "github-pat", "").clone();
    let b = find(&fs, "secret", "other.env", "github-pat", "").clone();
    t.add(&a.id(), Scope::User, Some("revoked"), false);
    t.add(&b.id(), Scope::Repo, None, false);
    let r = t.list(Some(&t.root.join("sub")));
    assert_eq!(r.code, 0, "{:?}", r.error);
    let v = j(&r);
    assert_eq!(keys(&v), ["action", "files", "impl", "removed_by_hand", "rules", "schema", "version"]);
    assert_eq!(v["schema"], 1);
    let rules = v["rules"].as_array().unwrap();
    let row =
        |scope: &str, pattern: &str| rules.iter().find(|r| r["scope"] == scope && r["pattern"] == pattern).unwrap();
    let hand = row("user", "~/samples/");
    assert_eq!(
        (hand["source"].clone(), hand["section"].clone(), hand["finding_id"].clone()),
        ("hand".into(), "malware".into(), Value::Null)
    );
    let mine = rules.iter().find(|r| r["finding_id"] == a.id()).unwrap();
    assert_eq!(
        (mine["source"].clone(), mine["reason"].clone(), mine["section"].clone()),
        ("command".into(), "revoked".into(), "secret github-pat".into())
    );
    assert_eq!(mine["added"], "2027-01-15 08:00 UTC");
    let repo_rule = row("repo", "/other.env");
    assert_eq!(repo_rule["finding_id"], b.id());
    assert_eq!(
        keys(mine),
        ["active", "added", "file", "finding_id", "id", "line", "pattern", "reason", "scope", "section", "source"]
    );
    assert!(v["removed_by_hand"].as_array().unwrap().is_empty());
    let text = r.lines.join("\n");
    assert!(
        text.contains(&format!("written by wpantry ignore for {}", a.id())) && text.contains("written by hand"),
        "{text}"
    );
    // Someone deletes the repo's file: the log still says it was added.
    std::fs::remove_file(t.root.join(".pantryignore")).unwrap();
    let v = j(&t.list(Some(&t.root)));
    let gone = v["removed_by_hand"].as_array().unwrap();
    assert_eq!(gone.len(), 1, "{v}");
    assert_eq!((gone[0]["pattern"].clone(), gone[0]["finding_id"].clone()), ("/other.env".into(), b.id().into()));
    assert_eq!(keys(&gone[0]), ["added", "file", "finding_id", "id", "pattern", "reason", "scope", "section"]);
    assert!(v["rules"].as_array().unwrap().iter().all(|r| r["scope"] == "user"));
    // Without --path, the repo's file isn't looked at.
    assert!(j(&t.list(None))["removed_by_hand"].as_array().unwrap().is_empty());
    // Removing what was removed by hand is a no-op that is logged, once.
    let r = t.remove(&b.id(), None);
    assert_eq!((r.code, j(&r)["already_gone"].clone()), (0, Value::Bool(true)), "{:?}", r.error);
    assert!(j(&t.list(Some(&t.root)))["removed_by_hand"].as_array().unwrap().is_empty());
    assert_eq!(t.events().last().unwrap()["already_gone"], true);
}

#[test]
fn remove_takes_a_hand_written_rule_by_its_listed_id_and_refuses_what_it_cannot_find() {
    let t = Rig::new();
    t.scan();
    std::fs::write(t.root.join(".pantryignore"), "# keep\n[secret jwt]\n/a.env\n/b.env\n").unwrap();
    let listed = j(&t.list(Some(&t.root)));
    let id = listed["rules"][0]["id"].as_str().unwrap().to_string();
    // A repo's rule is found only when the repo is named.
    let r = t.remove(&id, None);
    assert_eq!((r.code, j(&r)["refused"]["code"].clone()), (1, Value::from("not-found")));
    assert!(r.error.unwrap().contains("--path"));
    let r = t.remove(&id, Some(&t.root));
    assert_eq!(r.code, 0, "{:?}", r.error);
    assert_eq!(std::fs::read_to_string(t.root.join(".pantryignore")).unwrap(), "# keep\n[secret jwt]\n/b.env\n");
    assert_eq!(keys(&j(&r)), ["action", "changed", "id", "impl", "removed", "schema", "version"]);
    assert_eq!(keys(&j(&r)["removed"][0]), ["file", "finding_id", "id", "pattern", "scope", "section"]);
    assert_eq!(t.remove("R-0000000000", None).code, 1);
    assert_eq!(t.remove("F-0000000000", None).code, 1);
}

#[test]
fn an_unreadable_repo_file_is_an_error_in_the_listing_not_a_silent_gap() {
    let t = Rig::new();
    #[cfg(unix)]
    {
        std::fs::write(t.d.path().join("elsewhere"), "*\n").unwrap();
        std::os::unix::fs::symlink(t.d.path().join("elsewhere"), t.root.join(".pantryignore")).unwrap();
        let r = t.list(Some(&t.root));
        assert_eq!(r.code, 1);
        assert!(j(&r)["files"][1]["error"].as_str().unwrap().contains("not a regular file"), "{}", j(&r));
        assert!(r.error.is_some());
    }
    let r = t.list(None);
    assert_eq!(r.code, 0);
    assert_eq!(
        j(&r)["files"],
        json!([{"scope": "user", "file": edit::file_key(&t.env.user_file), "exists": false, "error": null}])
    );
}

#[test]
fn all_places_covers_every_lockfile_of_the_package_and_the_log_names_each_rule() {
    let t = Rig::new();
    let (before, _) = t.scan();
    let lodash = find(&before, "project", "lodash", "GHSA-lodash", "app/package-lock.json").clone();
    let r = t.add(&lodash.id(), Scope::User, None, true);
    assert_eq!(r.code, 0, "{:?}", r.error);
    assert_eq!(j(&r)["rules"].as_array().unwrap().len(), 2, "one rule per place");
    let (after, _) = t.scan();
    assert!(after.iter().all(|f| f.vuln_id != "GHSA-lodash"));
    assert!(after.iter().any(|f| f.vuln_id == "GHSA-left-pad"), "another package stays");
    let rules = t.events()[0]["rules"].as_array().unwrap().len();
    assert_eq!(rules, 2);
    assert_eq!(t.remove(&lodash.id(), None).code, 0);
    assert_eq!(ids(&t.scan().0), ids(&before));
}

#[test]
fn rule_ids_are_told_from_finding_ids() {
    assert!(is_rule_id("R-3fa9c01b2e") && is_rule_id("r-3FA9C01B2E"));
    assert!(!is_rule_id("F-3fa9c01b2e") && !is_rule_id("R-3fa9c01b2") && !is_rule_id("R-zzzzzzzzzz"));
    // Twelve bytes of wider characters: not an id, and not a panic.
    assert!(!is_rule_id("€€€€") && !is_rule_id("Ré3fa9c01b2") && !is_rule_id(""));
}
