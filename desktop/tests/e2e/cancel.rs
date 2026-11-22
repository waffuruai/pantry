//! Cancel and the time limit kill the scanner: the `sleepy` stand-in scans
//! until it is killed and writes its pid first (macOS and Linux).

use crate::harness::{Ctx, Driver, pid_alive, read_pid, standin, wait_until};
use crate::oracles::audit;
use serde_json::json;

pub fn cancel_and_timeout(app: &std::path::Path, ctx: &Ctx) {
    let pid_file = ctx.temp.join("fake pid");
    let env = ctx.env.with(&[
        ("PANTRY_FAKE_MODE", "sleepy".as_ref()),
        ("PANTRY_FAKE_PID", pid_file.as_os_str()),
    ]);
    let mut d = Driver::start(app, Some(&standin()), &env);
    assert!(d.settled()["report"].is_null());
    // Cmd/Ctrl+R starts a scan.
    let reply = d.key("R", true);
    assert_eq!(reply["busy"], "Scanning…", "{}", reply["busy"]);
    wait_until("the scan never reported a status line", || {
        pid_file.exists()
            && d.state()["busy_note"]
                .as_str()
                .is_some_and(|n| !n.is_empty())
    });
    let current = d.state();
    assert!(
        current["busy_note"] == "reading the test folder" && current["cancellable"] == true,
        "{current}"
    );
    assert_eq!(d.label("task.note"), "reading the test folder");
    audit(&mut d, "running scan");
    let pid = read_pid(&pid_file);
    assert!(pid_alive(pid));
    d.click("task.cancel");
    let state = d.settled();
    assert_eq!(state["error"]["kind"], "cancelled", "{}", state["error"]);
    assert!(!pid_alive(pid), "Cancel left the scanner running");
    d.click("error.dismiss");

    // The time limit, shortened for the test.
    std::fs::remove_file(&pid_file).expect("clear the pid file");
    d.ok("set_time_limit", json!({"milliseconds": 700}));
    d.action("scan", json!({"offline": true}));
    let state = d.settled();
    assert_eq!(state["error"]["kind"], "timed_out", "{}", state["error"]);
    let pid = read_pid(&pid_file);
    assert!(!pid_alive(pid), "the time limit left the scanner running");
    d.ok("set_time_limit", json!({"milliseconds": 0}));
    // The cancel op itself.
    std::fs::remove_file(&pid_file).expect("clear the pid file");
    d.action("scan", json!({"offline": true}));
    wait_until("the stand-in never started", || pid_file.exists());
    d.ok("cancel", serde_json::Value::Null);
    assert_eq!(d.settled()["error"]["kind"], "cancelled");
    d.close();
}
