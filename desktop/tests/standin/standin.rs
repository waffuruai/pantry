//! Stand-in scanner for the desktop end-to-end suite (tests/e2e). It follows
//! the scanner's JSON contract closely enough for the window to react, and
//! records what it was asked so the suite can check the calls.
//!
//! It never ships: Cargo builds it next to the desktop for tests, but
//! rust/release/build.sh builds only the binary it is told to and
//! release/package.py packs only the files it is given. Run alone it refuses
//! to do anything.
//!
//! The suite picks a behaviour with `PANTRY_FAKE_MODE`:
//!
//! - `sleepy`: quick answers, and a scan that runs until it is killed
//!   (Cancel and the time limit).
//! - `machine`: a machine-scope scanner with skipped personal folders
//!   (`PANTRY_FAKE_STATE`, `PANTRY_FAKE_GAP`, `PANTRY_FAKE_SKIP`).
//! - `outcome`: two fixable findings and knobs read from a JSON file on
//!   every call (`PANTRY_FAKE_KNOBS`).
//!
//! `wpantry-standin __touch PATH` creates PATH. The suite stores it as an
//! automatic fix command, so the real scanner can run a fix whose effect the
//! suite can see, on every OS.
//!
//! ```text
//! PANTRY_FAKE_MODE=sleepy PANTRY_FAKE_PID=/tmp/pid wpantry-standin scan
//! wpantry-standin __touch "/tmp/patch ran"
//! ```

mod machine;
mod outcome;
mod util;

use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("__touch") {
        let Some(path) = args.get(1) else {
            eprintln!("usage: wpantry-standin __touch PATH");
            exit(2);
        };
        if let Err(error) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            eprintln!("could not create {path}: {error}");
            exit(1);
        }
        return;
    }
    match std::env::var("PANTRY_FAKE_MODE").as_deref() {
        Ok("sleepy") => sleepy(&args),
        Ok("machine") => machine::run(&args),
        Ok("outcome") => outcome::run(&args),
        _ => {
            eprintln!(
                "wpantry-standin is a test stand-in for the Pantry scanner; set PANTRY_FAKE_MODE."
            );
            exit(2);
        }
    }
}

/// Quick answers, and a scan that runs until it is killed. Its pid goes to
/// `PANTRY_FAKE_PID` before the status line, so the suite can check the
/// process is gone after Cancel or the time limit.
fn sleepy(args: &[String]) {
    match args.first().map(String::as_str) {
        Some("report") => {
            eprintln!("no scan yet");
            exit(1);
        }
        Some("schedule") => println!("{}", util::unscheduled()),
        Some("scan") => {
            let pid_file = std::env::var("PANTRY_FAKE_PID").expect("PANTRY_FAKE_PID");
            util::write_pid(std::path::Path::new(&pid_file));
            eprintln!("reading the test folder");
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
        // The shell stand-in this replaces answered anything else with
        // nothing and status 0.
        _ => {}
    }
}
