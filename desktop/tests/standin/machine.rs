//! Stand-in for a machine-scope scanner. A real machine scan also reads the
//! host's own apps and tools, so offline it always has gaps a test can't
//! control. This one follows the scanner's contract instead: two `excluded`
//! findings for skipped personal folders, a real gap only when asked
//! (`PANTRY_FAKE_GAP=1`), and a fix verified only by a complete scan that no
//! longer lists the finding.

use crate::util::{self, after, has};
use serde_json::{Value, json};
use std::process::exit;

const FIX: &str = "npm install left-pad@2.0";

pub fn run(args: &[String]) {
    let state_path = std::env::var("PANTRY_FAKE_STATE").expect("PANTRY_FAKE_STATE");
    let mut st = util::load(
        &state_path,
        json!({"scans": [], "fixed": false, "fixes": [], "log": []}),
    );
    util::log_call(&mut st, args);
    let home = std::env::var("HOME").expect("HOME");
    let location = std::path::Path::new(&home)
        .join("project")
        .display()
        .to_string();
    let key = ["osv", "left-pad", location.as_str(), "TEST-MACHINE-1"];
    let fixed = st["fixed"] == json!(true);

    match args.first().map(String::as_str).unwrap_or("") {
        "report" => {
            util::save(&state_path, &st);
            let Some(last) = st["scans"].as_array().and_then(|s| s.last()).cloned() else {
                eprintln!("no scan yet");
                exit(1);
            };
            let mut exposure = problem(&key);
            exposure["resolved"] = if util::on(&st["resolved"]) {
                json!(util::stamp())
            } else {
                Value::Null
            };
            let plan = if fixed {
                json!([])
            } else {
                json!([{"id": "f1", "how": "wpantry", "run": "wpantry fix f1", "fix_cmd": FIX}])
            };
            let scans: Vec<Value> = st["scans"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["scan"].clone())
                .collect();
            println!(
                "{}",
                json!({
                    "schema": 1, "scan": last["scan"], "findings": last["findings"], "fix_plan": plan,
                    "checked": {}, "unfixed": 0,
                    "history": {"scans": scans, "exposures": [exposure], "fixes": st["fixes"]},
                })
            );
        }
        "scan" => {
            if has(args, "--path") || has(args, "--no-machine") {
                eprintln!("the machine stand-in got a folder scan: {args:?}");
                exit(1);
            }
            let skip = has(args, "--no-personal-files")
                || std::env::var("PANTRY_FAKE_SKIP").as_deref() == Ok("1");
            let rows = scan_findings(&key, fixed, skip);
            let gaps = rows
                .iter()
                .filter(|r| r["kind"] == "unchecked" && r["excluded"] != true)
                .count();
            let scope = if skip {
                "machine:~;no-personal-files"
            } else {
                "machine:~"
            };
            let id = st["scans"].as_array().unwrap().len() + 1;
            let fails = rows.iter().filter(|r| r["status"] == "fail").count();
            let warns = rows.iter().filter(|r| r["status"] == "warn").count();
            let scan = json!({"id": id, "when": util::stamp(), "scope": scope,
                              "fails": fails, "warns": warns, "unchecked": gaps});
            st["scans"]
                .as_array_mut()
                .unwrap()
                .push(json!({"scan": scan, "findings": rows}));
            // A complete scan that no longer lists the finding resolves it
            // and verifies the fix; a scan with a gap resolves nothing.
            if gaps == 0 && fixed {
                st["resolved"] = json!(true);
                for fix in st["fixes"].as_array_mut().unwrap() {
                    if fix["verified_scan"].is_null() {
                        fix["verified_scan"] = json!(id);
                    }
                }
            }
            util::save(&state_path, &st);
            println!("{}", json!({"schema": 1, "findings": rows}));
            exit(i32::from(fails > 0));
        }
        "fix" => {
            let scan: i64 = after(args, "--from-scan")
                .and_then(|s| s.parse().ok())
                .expect("--from-scan N");
            if has(args, "--dry-run") {
                util::save(&state_path, &st);
                println!("{}", json!({"schema": 1, "scan": scan, "command": FIX}));
            } else {
                st["fixed"] = json!(true);
                st["fixes"].as_array_mut().unwrap().push(json!({
                    "when": util::stamp(), "command": FIX, "ok": true,
                    "verified_scan": null, "targets": [key.join("|")],
                }));
                util::save(&state_path, &st);
                println!("Fixed left-pad.");
            }
        }
        "schedule" => {
            util::save(&state_path, &st);
            println!("{}", util::unscheduled());
        }
        _ => {
            util::save(&state_path, &st);
            eprintln!("unsupported in the stand-in: {args:?}");
            exit(2);
        }
    }
}

fn finding(
    id: &str,
    kind: &str,
    component: &str,
    note: &str,
    status: &str,
    excluded: bool,
) -> Value {
    json!({"id": id, "kind": kind, "component": component, "version": "", "location": "",
           "vuln_id": "", "status": status, "note": note, "fixed": "", "severity": "",
           "kev": false, "fix_cmd": "", "fix_auto": false, "excluded": excluded})
}

fn problem(key: &[&str; 4]) -> Value {
    let mut item = finding(
        "f1",
        "osv",
        "left-pad",
        "left-pad 1.0 has a known security hole.",
        "fail",
        false,
    );
    for (field, value) in [
        ("version", json!("1.0")),
        ("location", json!(key[2])),
        ("vuln_id", json!(key[3])),
        ("fixed", json!("2.0")),
        ("severity", json!("high")),
        ("fix_cmd", json!(FIX)),
        ("fix_auto", json!(true)),
    ] {
        item[field] = value;
    }
    item
}

fn scan_findings(key: &[&str; 4], fixed: bool, skip: bool) -> Vec<Value> {
    let mut rows = if fixed { vec![] } else { vec![problem(key)] };
    if skip {
        rows.push(finding(
            "x1",
            "unchecked",
            "Personal documents and images",
            "Skipped by your choice (--no-personal-files). Downloads, Desktop and Documents were not read.",
            "warn",
            true,
        ));
        rows.push(finding(
            "x2",
            "unchecked",
            "Safari settings",
            "Skipped by your choice (--no-personal-files). Safari's protected app data was not read.",
            "warn",
            true,
        ));
    }
    if std::env::var("PANTRY_FAKE_GAP").as_deref() == Ok("1") {
        rows.push(finding(
            "g1",
            "unchecked",
            "CISA KEV (exploited-in-the-wild marks)",
            "CISA KEV list unreachable and not cached",
            "warn",
            false,
        ));
    }
    rows
}
