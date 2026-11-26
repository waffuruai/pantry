//! `wpantry ignore add | list | remove`: dismiss a finding by writing the
//! rule that leaves it out into your ignore file or a repo's
//! `.pantryignore`, show what those files hold, and take a rule out again.
//!
//! The files are the source of truth for what a scan skips: a hand edit
//! keeps working, and `list` reads the files. The cache's `events` table
//! (kind `ignore`) is the log of what this command did, so `report audit`
//! shows it: when, add or remove, the finding (kind, component, location,
//! advisory or rule), the scope, the file and the reason. `list` reconciles
//! the two: a rule the log says was added and the file no longer holds was
//! removed by hand.
//!
//! This module decides and records; it prints nothing. It returns a
//! [`Reply`] (the exit code, the JSON, the lines) for the CLI to print.
//!
//! ```text
//! wpantry ignore add F-3fa9c01b2e --scope repo --reason "revoked in 2025"
//! wpantry ignore list --path ~/code/app
//! wpantry ignore remove F-3fa9c01b2e
//! ```

use crate::checks::ignore_edit::{self as edit, Added, Env, Refused, Request, Rule, Scope, Stop, Target, Want};
use crate::db::Cache;
use crate::error::Result;
use crate::finding::Finding;
use crate::history::{self, Event};
use crate::remediation::queue;
use crate::reporters;
use crate::utils::files::short;
use crate::utils::json::{J, obj};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The `events.kind` this command logs under.
pub const EVENT: &str = "ignore";

/// What a command decided: its exit code, its JSON (for `--json`) and its
/// lines (otherwise), and the message on stderr when it didn't do it.
#[derive(Debug)]
pub struct Reply {
    pub code: i32,
    pub json: J,
    pub lines: Vec<String>,
    pub error: Option<String>,
}

fn envelope(action: &str, rest: Vec<(&str, J)>) -> J {
    let mut pairs: Vec<(String, J)> = vec![
        ("schema".into(), J::Int(crate::SCHEMA)),
        ("impl".into(), crate::IMPL.into()),
        ("version".into(), crate::VERSION.into()),
        ("action".into(), action.into()),
    ];
    pairs.extend(rest.into_iter().map(|(k, v)| (k.to_string(), v)));
    J::Obj(pairs)
}

fn opt(s: Option<&str>) -> J {
    s.filter(|s| !s.is_empty()).map_or(J::Null, J::from)
}

/// A request that wasn't done, as exit 1: nothing changed.
fn refused(action: &str, r: Refused, id: &str) -> Reply {
    Reply {
        code: 1,
        json: envelope(
            action,
            vec![
                ("id", id.into()),
                ("changed", J::Bool(false)),
                ("refused", obj([("code", r.code.into()), ("message", r.message.as_str().into())])),
            ],
        ),
        lines: Vec::new(),
        error: Some(r.message),
    }
}

fn plain(code: &'static str, message: String) -> Refused {
    Refused { code, message }
}

fn finding_json(f: &Finding) -> J {
    obj([
        ("id", f.id().into()),
        ("kind", f.kind.as_str().into()),
        ("component", f.component.as_str().into()),
        ("location", f.location.as_str().into()),
        ("vuln_id", f.vuln_id.as_str().into()),
    ])
}

fn finding_value(f: &Finding) -> Value {
    json!({"id": f.id(), "kind": f.kind, "component": f.component, "location": f.location, "vuln_id": f.vuln_id})
}

fn rule_json(r: &edit::Written) -> J {
    obj([
        ("id", r.id.as_str().into()),
        ("section", r.section.as_str().into()),
        ("pattern", r.pattern.as_str().into()),
        ("place", r.place.as_str().into()),
    ])
}

/// One rule this command logged, as the log last left it.
#[derive(Clone, Debug)]
struct Logged {
    id: String,
    scope: Scope,
    file: String,
    section: String,
    pattern: String,
    finding_id: String,
    finding: Value,
    at: f64,
    reason: Option<String>,
}

/// The rules the log says are in the files: every add, less what a later
/// remove took out.
fn ledger(events: &[Event]) -> Vec<Logged> {
    let mut out: Vec<Logged> = Vec::new();
    let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    for e in events.iter().filter(|e| e.kind == EVENT) {
        let d = &e.detail;
        let rules = d.get("rules").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
        match d.get("action").and_then(Value::as_str) {
            Some("add") => {
                for r in rules {
                    let id = text(r, "id");
                    out.retain(|l| l.id != id);
                    out.push(Logged {
                        id,
                        scope: Scope::parse(&text(d, "scope")).unwrap_or(Scope::User),
                        file: text(d, "file"),
                        section: text(r, "section"),
                        pattern: text(r, "pattern"),
                        finding_id: text(d, "finding_id"),
                        finding: d.get("finding").cloned().unwrap_or(Value::Null),
                        at: e.at,
                        reason: d.get("reason").and_then(Value::as_str).map(str::to_string),
                    });
                }
            }
            Some("remove") => {
                for r in rules {
                    let id = text(r, "id");
                    out.retain(|l| l.id != id);
                }
            }
            _ => {}
        }
    }
    out
}

fn log(cache: &Cache, detail: Value) -> Result<()> {
    history::event(cache, EVENT, &detail)
}

fn who() -> (String, String) {
    (history::user(), history::host())
}

// add -----------------------------------------------------------------

/// `ignore add FINDING_ID`.
pub fn add(
    cache: &Cache,
    env: &Env,
    id: &str,
    scope: Scope,
    reason: Option<&str>,
    all_places: bool,
    now: f64,
) -> Result<Reply> {
    let Some(report) = reporters::latest(cache, None)? else {
        return Ok(refused("add", plain("no-scan", "no scan yet: run wpantry scan".into()), id));
    };
    let findings = &report.outcome.findings;
    let Some(f) = queue::find(findings, id) else {
        // Left out by an earlier add, and no scan since: already done.
        let events = history::events_of(cache, EVENT)?;
        for l in ledger(&events).iter().filter(|l| l.finding_id.eq_ignore_ascii_case(id)) {
            let t = Target { scope: l.scope, file: PathBuf::from(&l.file) };
            if edit::read_rules(&t).ok().flatten().is_some_and(|rs| rs.iter().any(|r| r.id == l.id)) {
                return Ok(already(id, &t));
            }
        }
        return Ok(refused(
            "add",
            plain(
                "not-found",
                format!(
                    "no finding {id} in the latest scan (#{}): wpantry fix list shows the ids",
                    report.outcome.scan_id
                ),
            ),
            id,
        ));
    };
    let req = Request { finding: f, all: findings, scope, all_places, reason, now };
    match edit::add(&req, env) {
        Err(Stop::Refused(r)) => Ok(refused("add", r, &f.id())),
        Err(Stop::Failed(e)) => Err(e),
        Ok(Added::Already { target }) => Ok(already(&f.id(), &target)),
        Ok(Added::Wrote { target, rules, left_out }) => {
            let file = edit::file_key(&target.file);
            let reason = reason.map(str::trim).filter(|r| !r.is_empty());
            let (user, host) = who();
            let rules_v: Vec<Value> =
                rules.iter().map(|r| json!({"id": r.id, "section": r.section, "pattern": r.pattern})).collect();
            log(
                cache,
                json!({"action": "add", "finding_id": f.id(), "finding": finding_value(f), "scope": scope.name(),
                       "file": file, "rules": rules_v, "reason": reason, "all_places": all_places,
                       "user": user, "host": host}),
            )
            .map_err(|e| crate::error::Error::Failed(format!("wrote {file}, but couldn't log it: {e}")))?;
            let mut lines = vec![format!(
                "✓ ignored {} ({} {} {})",
                f.id(),
                f.kind,
                f.component,
                if f.vuln_id.is_empty() { "" } else { f.vuln_id.as_str() }
            )];
            lines.push(format!("  wrote to {} ({}):", short(&target.file.to_string_lossy()), scope.name()));
            for r in &rules {
                lines.push(format!("    [{}]  {}", r.section, r.pattern));
            }
            for l in &left_out {
                lines.push(format!("  not covered: {} ({})", l.finding_id, l.why));
            }
            lines.push(format!("  The next scan leaves it out; wpantry ignore remove {} brings it back.", f.id()));
            let json = envelope(
                "add",
                vec![
                    ("changed", J::Bool(true)),
                    ("finding", finding_json(f)),
                    ("scope", scope.name().into()),
                    ("file", file.into()),
                    ("rules", J::Arr(rules.iter().map(rule_json).collect())),
                    ("reason", opt(reason)),
                    ("all_places", J::Bool(all_places)),
                    (
                        "left_out",
                        J::Arr(
                            left_out
                                .iter()
                                .map(|l| obj([("id", l.finding_id.as_str().into()), ("why", l.why.as_str().into())]))
                                .collect(),
                        ),
                    ),
                ],
            );
            Ok(Reply { code: 0, json, lines, error: None })
        }
    }
}

fn already(id: &str, target: &Target) -> Reply {
    let file = edit::file_key(&target.file);
    Reply {
        code: 0,
        json: envelope(
            "add",
            vec![
                ("id", id.into()),
                ("changed", J::Bool(false)),
                ("already", J::Bool(true)),
                ("scope", target.scope.name().into()),
                ("file", file.into()),
            ],
        ),
        lines: vec![format!(
            "✓ {id} is already left out by {}: nothing changed",
            short(&target.file.to_string_lossy())
        )],
        error: None,
    }
}

// list ----------------------------------------------------------------

/// The files `list` and `remove` look in: your file, and the repo's for
/// `--path DIR`.
fn files(env: &Env, path: Option<&Path>) -> Vec<Target> {
    let mut v = vec![Target::user(env)];
    if let Some(dir) = path {
        v.push(Target::repo(&edit::repo_for(dir, env)));
    }
    v
}

fn rule_listing(r: &Rule) -> J {
    let m = r.mark.as_ref();
    obj([
        ("id", r.id.as_str().into()),
        ("scope", r.scope.name().into()),
        ("file", r.file.as_str().into()),
        ("line", J::Int(r.line as i64)),
        ("section", opt(Some(&r.section))),
        ("active", J::Bool(r.active)),
        ("pattern", r.pattern.as_str().into()),
        ("source", if m.is_some() { "command" } else { "hand" }.into()),
        ("finding_id", opt(m.map(|m| m.finding_id.as_str()))),
        ("added", opt(m.map(|m| m.when.as_str()))),
        ("reason", opt(m.map(|m| m.reason.as_str()))),
    ])
}

/// `ignore list [--path DIR]`.
pub fn list(cache: &Cache, env: &Env, path: Option<&Path>) -> Result<Reply> {
    let targets = files(env, path);
    let events = history::events_of(cache, EVENT)?;
    let logged = ledger(&events);
    let mut file_rows = Vec::new();
    let mut rule_rows = Vec::new();
    let mut gone_rows = Vec::new();
    let mut lines = vec!["==> Ignore rules".to_string()];
    let mut code = 0;
    let mut errors = Vec::new();
    for t in &targets {
        let key = edit::file_key(&t.file);
        let shown = short(&t.file.to_string_lossy());
        let label = if t.scope == Scope::User { "your file" } else { "the repo's file" };
        let (exists, rules, error) = match edit::read_rules(t) {
            Ok(Some(rs)) => (true, rs, None),
            Ok(None) => (false, Vec::new(), None),
            Err(e) => (true, Vec::new(), Some(e)),
        };
        file_rows.push(obj([
            ("scope", t.scope.name().into()),
            ("file", key.as_str().into()),
            ("exists", J::Bool(exists)),
            ("error", opt(error.as_deref())),
        ]));
        if let Some(e) = &error {
            code = 1;
            errors.push(format!("{shown}: {e}"));
            lines.push(format!("{label} {shown}: can't be read: {e}"));
            continue;
        }
        if !exists {
            lines.push(format!("{label} {shown}: none yet"));
        } else {
            lines.push(format!("{label} {shown}: {} rule{}", rules.len(), if rules.len() == 1 { "" } else { "s" }));
        }
        let present: HashSet<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        for r in &rules {
            let head = if r.section.is_empty() { "(every check)".to_string() } else { format!("[{}]", r.section) };
            let flag = if r.active { "" } else { "  (its header can't be read: applies to nothing)" };
            lines.push(format!("  {}  {head}  {}{flag}", r.id, r.pattern));
            match &r.mark {
                Some(m) => lines.push(format!(
                    "      written by wpantry ignore for {} on {}{}",
                    m.finding_id,
                    m.when,
                    if m.reason.is_empty() { String::new() } else { format!(": {}", m.reason) }
                )),
                None => lines.push("      written by hand".to_string()),
            }
            rule_rows.push(rule_listing(r));
        }
        for l in logged.iter().filter(|l| l.scope == t.scope && l.file == key && !present.contains(l.id.as_str())) {
            lines.push(format!(
                "  removed by hand: {}  [{}]  {}  (logged as added for {})",
                l.id, l.section, l.pattern, l.finding_id
            ));
            gone_rows.push(obj([
                ("id", l.id.as_str().into()),
                ("scope", l.scope.name().into()),
                ("file", l.file.as_str().into()),
                ("section", opt(Some(&l.section))),
                ("pattern", l.pattern.as_str().into()),
                ("finding_id", l.finding_id.as_str().into()),
                ("added", history::stamp(l.at).into()),
                ("reason", opt(l.reason.as_deref())),
            ]));
        }
    }
    let json = envelope(
        "list",
        vec![("files", J::Arr(file_rows)), ("rules", J::Arr(rule_rows)), ("removed_by_hand", J::Arr(gone_rows))],
    );
    Ok(Reply { code, json, lines, error: (!errors.is_empty()).then(|| errors.join("\n")) })
}

// remove --------------------------------------------------------------

/// `ignore remove RULE_ID|FINDING_ID [--path DIR]`.
pub fn remove(cache: &Cache, env: &Env, id: &str, path: Option<&Path>) -> Result<Reply> {
    let by_rule = id.as_bytes().get(..2).is_some_and(|b| b.eq_ignore_ascii_case(b"R-"));
    let want = if by_rule { Want::Rule(id) } else { Want::Finding(id) };
    let events = history::events_of(cache, EVENT)?;
    let logged = ledger(&events);
    let matches =
        |l: &Logged| if by_rule { l.id.eq_ignore_ascii_case(id) } else { l.finding_id.eq_ignore_ascii_case(id) };
    // Your file, the repo `--path` names, and the repos the log says this
    // id was written in.
    let mut targets = files(env, path);
    for l in logged.iter().filter(|l| matches(l)) {
        let t = Target { scope: l.scope, file: PathBuf::from(&l.file) };
        if !targets.iter().any(|x| x.key() == t.key()) {
            targets.push(t);
        }
    }
    let removed = match edit::remove(&targets, want) {
        Ok(r) => r,
        Err(Stop::Refused(r)) => return Ok(refused("remove", r, id)),
        Err(Stop::Failed(e)) => return Err(e),
    };
    let (user, host) = who();
    if removed.is_empty() {
        let gone: Vec<&Logged> = logged.iter().filter(|l| matches(l)).collect();
        if gone.is_empty() {
            let hint = if by_rule { " (a hand-written rule in a repo's file needs --path DIR)" } else { "" };
            return Ok(refused(
                "remove",
                plain("not-found", format!("no rule or finding {id} in the ignore files{hint}")),
                id,
            ));
        }
        // Logged as added, and no longer in its file: record that it's gone.
        for (scope, file) in distinct(&gone) {
            let rs: Vec<Value> = gone
                .iter()
                .filter(|l| l.scope == scope && l.file == file)
                .map(|l| json!({"id": l.id, "section": l.section, "pattern": l.pattern}))
                .collect();
            let first = gone.iter().find(|l| l.scope == scope && l.file == file).expect("grouped from gone");
            log(
                cache,
                json!({"action": "remove", "finding_id": first.finding_id, "finding": first.finding,
                       "scope": scope.name(), "file": file, "rules": rs, "already_gone": true,
                       "user": user, "host": host}),
            )?;
        }
        return Ok(Reply {
            code: 0,
            json: envelope(
                "remove",
                vec![("id", id.into()), ("changed", J::Bool(false)), ("already_gone", J::Bool(true))],
            ),
            lines: vec![format!(
                "✓ {id} was logged as added, but its rule is no longer in the file: nothing to remove"
            )],
            error: None,
        });
    }
    let mut lines = Vec::new();
    for (scope, file) in distinct_rules(&removed) {
        let rs: Vec<&edit::Removed> = removed.iter().filter(|r| r.rule.scope == scope && r.rule.file == file).collect();
        let finding_id = rs.iter().find_map(|r| r.rule.mark.as_ref().map(|m| m.finding_id.clone()));
        let finding = logged
            .iter()
            .find(|l| finding_id.as_deref() == Some(l.finding_id.as_str()))
            .map_or(Value::Null, |l| l.finding.clone());
        let rules_v: Vec<Value> =
            rs.iter().map(|r| json!({"id": r.rule.id, "section": r.rule.section, "pattern": r.rule.pattern})).collect();
        log(
            cache,
            json!({"action": "remove", "finding_id": finding_id, "finding": finding, "scope": scope.name(),
                   "file": file, "rules": rules_v, "already_gone": false, "user": user, "host": host}),
        )
        .map_err(|e| crate::error::Error::Failed(format!("removed from {file}, but couldn't log it: {e}")))?;
        for r in &rs {
            lines.push(format!(
                "✓ removed {} from {}: [{}] {}",
                r.rule.id,
                short(&file),
                r.rule.section,
                r.rule.pattern
            ));
        }
    }
    lines.push("  The next scan reports it again.".into());
    let removed_json = removed
        .iter()
        .map(|r| {
            let m = r.rule.mark.as_ref();
            obj([
                ("id", r.rule.id.as_str().into()),
                ("scope", r.rule.scope.name().into()),
                ("file", r.rule.file.as_str().into()),
                ("section", opt(Some(&r.rule.section))),
                ("pattern", r.rule.pattern.as_str().into()),
                ("finding_id", opt(m.map(|m| m.finding_id.as_str()))),
            ])
        })
        .collect();
    Ok(Reply {
        code: 0,
        json: envelope(
            "remove",
            vec![("id", id.into()), ("changed", J::Bool(true)), ("removed", J::Arr(removed_json))],
        ),
        lines,
        error: None,
    })
}

fn distinct(v: &[&Logged]) -> Vec<(Scope, String)> {
    let mut out: Vec<(Scope, String)> = Vec::new();
    for l in v {
        if !out.iter().any(|(s, f)| *s == l.scope && *f == l.file) {
            out.push((l.scope, l.file.clone()));
        }
    }
    out
}

fn distinct_rules(v: &[edit::Removed]) -> Vec<(Scope, String)> {
    let mut out: Vec<(Scope, String)> = Vec::new();
    for r in v {
        if !out.iter().any(|(s, f)| *s == r.rule.scope && *f == r.rule.file) {
            out.push((r.rule.scope, r.rule.file.clone()));
        }
    }
    out
}

/// Whether a word is a rule id: `R-` and ten hex digits.
pub fn is_rule_id(word: &str) -> bool {
    // By byte: a word of other characters has no boundary at 2 to slice at.
    let b = word.as_bytes();
    b.len() == 12 && b[..2].eq_ignore_ascii_case(b"R-") && b[2..].iter().all(u8::is_ascii_hexdigit)
}

#[cfg(test)]
#[path = "dismiss_tests.rs"]
mod tests;
