//! Stand-in for the outcome checks: two fixable findings in one folder, two
//! open problems from scans of other folders (one folder still there, one
//! gone), and knobs (a JSON file read on every call) that make a fix leave
//! its finding behind, fail, run slowly, or break the reload after it.
//!
//! Knobs (`PANTRY_FAKE_KNOBS`, all optional): `many`, `report_sleep`,
//! `report_fails`, `scan_sleep`, `scan_garbage`, `scan_offline`, `fresh`,
//! `gap`, `sticky`, `update_stale` (flags); `dry_run_hidden`,
//! `dry_run_other_scan`, `fix_sleep`, `fix_fail` (lists of finding ids);
//! `dry_run_suffix` (id to extra words).

use crate::util::{self, after, has, lists, on};
use serde_json::{Value, json};
use std::process::exit;
use std::time::Duration;

struct Paths {
    state: String,
    main: String,
    other: String,
    gone: String,
}

pub fn run(args: &[String]) {
    let var = |name: &str| {
        std::env::var(format!("PANTRY_FAKE_{name}"))
            .unwrap_or_else(|_| panic!("PANTRY_FAKE_{name}"))
    };
    let paths = Paths {
        state: var("STATE"),
        main: var("MAIN"),
        other: var("OTHER"),
        gone: var("GONE"),
    };
    let knobs = util::load(&var("KNOBS"), json!({}));
    let mut st = util::load(
        &paths.state,
        json!({"scans": [], "fixed": [], "fixes": [], "log": [], "other_resolved": false}),
    );
    util::log_call(&mut st, args);
    let pid_file = std::path::PathBuf::from(format!("{}.pid", paths.state));
    let sleep = || std::thread::sleep(Duration::from_secs(60));

    match args.first().map(String::as_str).unwrap_or("") {
        "report" => {
            util::save(&paths.state, &st);
            if on(&knobs["report_sleep"]) {
                util::write_pid(&pid_file);
                sleep();
            }
            if on(&knobs["report_fails"]) && on(&st["fixes"]) {
                eprintln!("database is locked");
                exit(3);
            }
            let Some(last) = st["scans"].as_array().and_then(|s| s.last()).cloned() else {
                eprintln!("no scan yet");
                exit(1);
            };
            let mut earlier = vec![exposure("e2", "gone-tool", &paths.gone, &paths)];
            if !on(&st["other_resolved"]) {
                earlier.insert(0, exposure("e1", "other-tool", &paths.other, &paths));
            }
            let plan: Vec<Value> = last["findings"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["kind"] != "unchecked")
                .map(|r| {
                    let id = r["id"].as_str().unwrap();
                    json!({"id": id, "how": "wpantry", "run": format!("wpantry fix {id}"), "fix_cmd": r["fix_cmd"]})
                })
                .collect();
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
                    "history": {"scans": scans, "exposures": earlier, "fixes": st["fixes"]},
                })
            );
        }
        "scan" => {
            if on(&knobs["scan_sleep"]) {
                util::write_pid(&pid_file);
                util::save(&paths.state, &st);
                sleep();
            }
            if on(&knobs["scan_garbage"]) {
                util::save(&paths.state, &st);
                println!("<html>proxy error</html>");
                exit(0);
            }
            let path = after(args, "--path").unwrap_or("").to_string();
            if on(&knobs["scan_offline"]) && !has(args, "--offline") {
                util::save(&paths.state, &st);
                eprintln!("error sending request: dns error: failed to lookup address");
                exit(2);
            }
            if on(&knobs["fresh"]) {
                st["fixed"] = json!([]); // The problems are back, for the next check.
            }
            let mut rows = if path == paths.other {
                st["other_resolved"] = json!(true);
                vec![]
            } else {
                latest_rows(&knobs, &st, &paths)
            };
            if on(&knobs["gap"]) {
                rows.push(json!({"id": "g1", "kind": "unchecked", "component": "CISA KEV", "version": "",
                                 "location": "", "vuln_id": "", "status": "warn",
                                 "note": "CISA KEV list unreachable", "fixed": "", "severity": "",
                                 "kev": false, "fix_cmd": "", "fix_auto": false, "excluded": false}));
            }
            let gaps = rows.iter().filter(|r| r["kind"] == "unchecked").count();
            let fails = rows.iter().filter(|r| r["status"] == "fail").count();
            let id = st["scans"].as_array().unwrap().len() + 1;
            let scan = json!({"id": id, "when": util::stamp(), "scope": format!("repos:{path}"),
                              "fails": fails, "warns": 0, "unchecked": gaps});
            st["scans"]
                .as_array_mut()
                .unwrap()
                .push(json!({"scan": scan, "findings": rows}));
            util::save(&paths.state, &st);
            println!("{}", json!({"schema": 1, "findings": rows}));
            exit(i32::from(fails > 0));
        }
        "fix" => {
            let fid = args.get(1).expect("fix ID").clone();
            let scan: i64 = after(args, "--from-scan")
                .and_then(|s| s.parse().ok())
                .expect("--from-scan N");
            let last = st["scans"]
                .as_array()
                .and_then(|s| s.last())
                .expect("a scan before a fix");
            let Some(row) = last["findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == fid.as_str())
                .cloned()
            else {
                eprintln!("the stand-in has no finding {fid}");
                exit(1);
            };
            let fix_cmd = row["fix_cmd"].as_str().unwrap().to_string();
            if has(args, "--dry-run") {
                util::save(&paths.state, &st);
                let mut command = fix_cmd;
                // A right-to-left override makes the command read differently
                // from how it runs; an answer for another scan is not this fix.
                if lists(&knobs["dry_run_hidden"], &fid) {
                    command.push_str(" \u{202e}exe.gnp");
                }
                // Extra words after a well-formed command: run as more arguments.
                command.push_str(knobs["dry_run_suffix"][fid.as_str()].as_str().unwrap_or(""));
                let answer = if lists(&knobs["dry_run_other_scan"], &fid) {
                    scan + 1
                } else {
                    scan
                };
                println!(
                    "{}",
                    json!({"schema": 1, "scan": answer, "command": command})
                );
                exit(0);
            }
            if lists(&knobs["fix_sleep"], &fid) {
                util::write_pid(&pid_file);
                util::save(&paths.state, &st);
                sleep();
            }
            if lists(&knobs["fix_fail"], &fid) {
                util::save(&paths.state, &st);
                eprintln!(
                    "npm ERR! code E404 for {}",
                    row["component"].as_str().unwrap()
                );
                exit(1);
            }
            // A sticky fix runs and exits 0, but the problem stays.
            if !on(&knobs["sticky"]) {
                st["fixed"].as_array_mut().unwrap().push(json!(fid));
            }
            st["fixes"].as_array_mut().unwrap().push(json!({
                "when": util::stamp(), "command": fix_cmd, "ok": true,
                "verified_scan": null, "targets": [key(&row)],
            }));
            util::save(&paths.state, &st);
            println!("Ran {fix_cmd}");
        }
        "schedule" => {
            util::save(&paths.state, &st);
            println!("{}", util::unscheduled());
        }
        "update" => {
            util::save(&paths.state, &st);
            let version = std::env::var("PANTRY_FAKE_VERSION").expect("PANTRY_FAKE_VERSION");
            println!(
                "{}",
                json!({"current": version, "latest": version, "available": false, "assets": [],
                       "checked_at": "2026-05-05 20:11 UTC", "stale": on(&knobs["update_stale"])})
            );
        }
        _ => {
            util::save(&paths.state, &st);
            eprintln!("unsupported in the stand-in: {args:?}");
            exit(2);
        }
    }
}

fn finding(fid: &str, component: &str, paths: &Paths) -> Value {
    json!({"id": fid, "kind": "osv", "component": component, "version": "1.0",
           "location": paths.main, "vuln_id": format!("TEST-2026-{}", fid.to_uppercase()), "status": "fail",
           "note": format!("{component} has a known security hole."), "fixed": "2.0", "severity": "high",
           "kev": false, "fix_cmd": format!("npm install {component}@2.0"), "fix_auto": true})
}

fn key(item: &Value) -> String {
    ["kind", "component", "location", "vuln_id"]
        .map(|field| item[field].as_str().unwrap_or(""))
        .join("|")
}

fn latest_rows(knobs: &Value, st: &Value, paths: &Paths) -> Vec<Value> {
    // A component name with a right-to-left override and an escape code:
    // the window must show it without them. Its fix command is plain: a
    // hidden character there is refused (the dry_run_hidden knob checks that).
    let mut bravo = finding("f2", "bravo\u{202e}gnp.exe\u{1b}[31m", paths);
    bravo["fix_cmd"] = json!("npm install bravo@2.0");
    let mut rows = vec![finding("f1", "alpha", paths), bravo];
    if on(&knobs["many"]) {
        // Enough rows that the last ones sit below the fold of the smallest window.
        for n in 3..15 {
            let mut row = finding(&format!("f{n}"), &format!("extra-{n}"), paths);
            row["severity"] = json!("low");
            row["status"] = json!("warn");
            rows.push(row);
        }
    }
    rows.retain(|r| !lists(&st["fixed"], r["id"].as_str().unwrap()));
    rows
}

fn exposure(eid: &str, component: &str, folder: &str, paths: &Paths) -> Value {
    let mut item = finding(eid, component, paths);
    item["location"] = json!(folder);
    item["severity"] = json!("medium");
    item["fix_auto"] = json!(false);
    item["resolved"] = Value::Null;
    item["scope"] = json!(format!("repos:{folder}"));
    item
}
