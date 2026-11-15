//! The process-wide pace (`utils::parallel::Pace`): unset, `par_map` and
//! `cores` behave as before and a scan finds what it always found; set, no
//! `par_map` runs more than its width at once, the hook runs before each
//! item and may hold the work or stop it, and a scan still finds exactly
//! the same. One test function: the pace is process-wide, so its steps must
//! not run side by side with each other.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wpantry::checks::{Options, Scan};
use wpantry::db::Cache;
use wpantry::utils::net::{Fake, Response};
use wpantry::utils::parallel::{Pace, cores, pace, par_map, set_pace};

/// Most items of `n` running at once in `par_map(.., width, ..)`, and the
/// results (each item doubled, in order).
fn peak(n: usize, width: usize) -> (usize, Vec<usize>) {
    let items: Vec<usize> = (0..n).collect();
    let (live, top) = (AtomicUsize::new(0), AtomicUsize::new(0));
    let out = par_map(&items, width, |&i| {
        let now = live.fetch_add(1, Ordering::SeqCst) + 1;
        top.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(50));
        live.fetch_sub(1, Ordering::SeqCst);
        i * 2
    });
    (top.load(Ordering::SeqCst), out)
}

/// A checkout (a `.git` folder, as the supply-chain tests make one) with
/// enough files for the files pass to spread over threads, a lockfile and
/// text with hidden characters.
fn fixture(root: &std::path::Path) {
    let p = root.join("project");
    std::fs::create_dir_all(p.join("src")).unwrap();
    std::fs::create_dir_all(p.join(".git")).unwrap();
    std::fs::write(
        p.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"smallvec\"\nversion = \"1.6.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    )
    .unwrap();
    std::fs::write(p.join("src/hidden.rs"), "let ok = \"a\u{202e}b\u{200b}c\";\n").unwrap();
    for i in 0..300 {
        std::fs::write(p.join(format!("src/f{i}.txt")), format!("line {i}\n").repeat(i % 7 + 1)).unwrap();
    }
}

/// One offline folder scan of the fixture into a fresh database: the
/// findings and the counts, as text.
fn scan(root: &std::path::Path, db: &str) -> String {
    let net = Fake::new(|_| Ok(Response::not_found()));
    let opts = Options { paths: Some(vec![root.join("project")]), machine: false, offline: true, ..Default::default() };
    let cache = Cache::open(Some(&root.join(db))).unwrap();
    let out = Scan::new(opts, cache, &net, &|_| {}, &|_| {}).run().unwrap();
    format!("{:#?}\n{:#?}\n{} {}", out.findings, out.counts, out.unfixed, out.unknown_licenses)
}

#[test]
fn a_pace_bounds_and_holds_the_workers_and_changes_no_result() {
    // Unset (the default): the width asked for, all the machine's cores.
    assert!(pace().is_none());
    let machine = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    assert_eq!(cores(), machine);
    let (top, out) = peak(24, 8);
    assert_eq!(top, 8, "unset: par_map runs its full width");
    assert_eq!(out, (0..24).map(|i| i * 2).collect::<Vec<_>>());

    let tmp = wpantry::utils::temp::TempDir::new("pace").unwrap();
    fixture(tmp.path());
    let before = scan(tmp.path(), "a.db");
    assert!(!before.starts_with("[]"), "the fixture has findings: {before}");

    // Set: at most its width, the hook once per item, the same results.
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    assert!(
        set_pace(Some(Pace::new(2, move || {
            c.fetch_add(1, Ordering::SeqCst);
        })))
        .is_none()
    );
    assert_eq!(cores(), machine.min(2));
    let (top, out) = peak(24, 8);
    assert!(top <= 2, "paced: {top} at once");
    assert_eq!(out, (0..24).map(|i| i * 2).collect::<Vec<_>>());
    assert_eq!(calls.load(Ordering::SeqCst), 24);
    let paced = scan(tmp.path(), "b.db");
    assert_eq!(paced, before, "a paced scan finds exactly the same");

    // A hook that blocks holds every item until it lets go.
    let hold = Arc::new(AtomicBool::new(true));
    let h = hold.clone();
    set_pace(Some(Pace::new(2, move || {
        while h.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
    })));
    let done = Arc::new(Mutex::new(None));
    let d = done.clone();
    let t = std::thread::spawn(move || *d.lock().unwrap() = Some(par_map(&[1, 2, 3], 8, |i| i + 1)));
    std::thread::sleep(Duration::from_millis(150));
    assert!(done.lock().unwrap().is_none(), "held: nothing finished");
    hold.store(false, Ordering::SeqCst);
    t.join().unwrap();
    assert_eq!(done.lock().unwrap().clone(), Some(vec![2, 3, 4]));

    // A hook that unwinds stops the work: par_map panics, no item runs.
    let ran = Arc::new(AtomicUsize::new(0));
    set_pace(Some(Pace::new(2, || std::panic::resume_unwind(Box::new("stop")))));
    let r = ran.clone();
    let stopped = std::panic::catch_unwind(|| {
        par_map(&[1, 2, 3], 8, |_| {
            r.fetch_add(1, Ordering::SeqCst);
        })
    });
    assert!(stopped.is_err());
    assert_eq!(ran.load(Ordering::SeqCst), 0);

    // Cleared: back to the default.
    set_pace(None);
    assert!(pace().is_none());
    assert_eq!(cores(), machine);
    assert_eq!(peak(24, 8).0, 8);
    assert_eq!(scan(tmp.path(), "c.db"), before);
}
