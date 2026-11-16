//! Work spread over threads: [`par_map`] for probes that wait on a
//! subprocess or the network, [`spread`] for a pool of workers that share
//! one queue of their own.
//!
//! An app that links the library can set a process-wide [`Pace`] for a
//! scan it runs in the background: every [`par_map`] then runs at most
//! `width` of its threads at once, [`cpu_budget`] answers at most `width`,
//! and the pace's hook runs on each worker before each item (to lower the
//! thread's priority, to wait while the app needs the machine, or to unwind
//! and stop). With no pace set, the default, nothing changes. What a scan
//! finds never depends on the pace: [`par_map`] keeps `items`' order at any
//! width.
//!
//! A pace can be cleared in the middle of a scan (the app wants the
//! library back soon): a running [`par_map`] then runs its full width from
//! its next item on, since it starts every thread its caller asked for and
//! only the ones past the pace's width wait.
//!
//! A worker that unwinds (the hook stopping the work, or a bug) stops the
//! other workers at their next item, and the unwind goes on from the
//! calling thread with its own payload once they have ended. The scope's
//! own "a scoped thread panicked" panic never happens, so a stop prints
//! nothing.
//!
//! Known limits of the pace (it covers [`par_map`] and [`spread`] only):
//! - `checks::machine` runs up to four one-shot probe threads beside the
//!   scan's own thread (the trust stores, Software Update, persistence,
//!   `brew vulns`), and the inventory one more (Docker). The pace does not
//!   count or hold them; the `par_map`s inside them are paced.
//! - The width bounds each [`par_map`] or [`spread`] on its own, not the
//!   process: two of them running at once (one in a probe thread above,
//!   one on the scan's thread) run up to twice the width together. A
//!   process-wide count would deadlock a `par_map` nested in another's
//!   item, so it is left out (TODO: a count that a nested call skips).
//! - Subprocesses (brew, gitleaks, softwareupdate and the other probes)
//!   run at the QoS macOS gives a new process, not the QoS of the thread
//!   that started them: a thread's QoS is not passed to a child process.
//!
//! ```
//! use std::sync::Arc;
//! use std::sync::atomic::{AtomicUsize, Ordering};
//! use wpantry::utils::parallel::{Pace, cpu_budget, cores, par_map, set_pace};
//! let calls = Arc::new(AtomicUsize::new(0));
//! let c = calls.clone();
//! let before = set_pace(Some(Pace::new(1, move || { c.fetch_add(1, Ordering::SeqCst); })));
//! assert_eq!(cpu_budget(), 1);
//! assert!(cores() >= 1, "cores() is the machine's, paced or not");
//! assert_eq!(par_map(&[1, 2, 3], 8, |i| i * 2), vec![2, 4, 6]);
//! assert_eq!(calls.load(Ordering::SeqCst), 3);
//! set_pace(before);
//! ```

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Duration;

/// How many probes (subprocesses, mostly) run at once in [`par_map`].
pub const PROBES: usize = 8;

/// A process-wide limit on the library's worker threads (see the module
/// doc). One scan at a time should hold it: it is not per scan.
#[derive(Clone)]
pub struct Pace {
    /// Most threads any [`par_map`] runs at once (at least 1).
    width: usize,
    /// Run on a worker thread before each item.
    hook: Arc<dyn Fn() + Send + Sync>,
}

impl Pace {
    /// At most `width` threads at once (0 counts as 1); `hook` runs on a
    /// worker before each item.
    pub fn new(width: usize, hook: impl Fn() + Send + Sync + 'static) -> Pace {
        Pace { width: width.max(1), hook: Arc::new(hook) }
    }

    /// Most threads any [`par_map`] runs at once (at least 1).
    pub fn width(&self) -> usize {
        self.width
    }
}

impl std::fmt::Debug for Pace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pace({})", self.width)
    }
}

static PACE: RwLock<Option<Pace>> = RwLock::new(None);

/// Wakes the workers that wait past the pace's width when it changes.
static CHANGED: (Mutex<()>, Condvar) = (Mutex::new(()), Condvar::new());

/// How long a waiting worker sleeps before it looks again by itself. A
/// pace change, the end of the items or a stop wakes it at once; this is
/// only a backstop.
const PARKED: Duration = Duration::from_millis(500);

fn wake_parked() {
    let _g = CHANGED.0.lock().unwrap_or_else(|p| p.into_inner());
    CHANGED.1.notify_all();
}

/// Wait for a change while `still` holds. `still` is read under the
/// lock every waker takes, so a change between the look and the wait
/// still wakes this thread.
fn park(still: impl Fn() -> bool) {
    let g = CHANGED.0.lock().unwrap_or_else(|p| p.into_inner());
    if still() {
        let _ = CHANGED.1.wait_timeout(g, PARKED);
    }
}

/// Set (Some) or clear (None) the pace; returns the one it replaces.
pub fn set_pace(pace: Option<Pace>) -> Option<Pace> {
    let was = std::mem::replace(&mut *PACE.write().unwrap_or_else(|p| p.into_inner()), pace);
    wake_parked();
    was
}

/// The pace in effect, if any.
pub fn pace() -> Option<Pace> {
    PACE.read().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Run the pace's hook on this thread, if a pace is set (a worker of
/// [`spread`] calls it before each item).
pub fn before_item() {
    if let Some(p) = pace() {
        (p.hook)();
    }
}

/// `f` over `items`, at most `width` at once (and at most the [`Pace`]'s
/// width when one is set), the results in `items`' order.
/// For probes that wait on a subprocess or the network: an inventory that
/// runs a few hundred of them one after another spends seconds waiting.
///
/// Under a pace it still starts `width` threads (at most one per item);
/// those past the pace's width wait, and join in if the pace widens or is
/// cleared while it runs.
pub fn par_map<T: Sync, R: Send>(items: &[T], width: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    // Paced when it started: then every item looks at the pace again. Not
    // paced: a pace set later does not apply to this call.
    let paced = pace().is_some();
    let next = AtomicUsize::new(0);
    let done = Mutex::new(Vec::with_capacity(items.len()));
    let stopped: Mutex<Option<Box<dyn Any + Send>>> = Mutex::new(None);
    let out_of_items = || next.load(Ordering::Relaxed) >= items.len();
    std::thread::scope(|s| {
        for k in 0..width.clamp(1, items.len().max(1)) {
            let (next, done, stopped, f) = (&next, &done, &stopped, &f);
            s.spawn(move || {
                let work = || {
                    loop {
                        let p = if paced { pace() } else { None };
                        let past_width = || pace().is_some_and(|p| k >= p.width);
                        if p.as_ref().is_some_and(|p| k >= p.width) {
                            if out_of_items() {
                                return;
                            }
                            park(|| !out_of_items() && past_width());
                            continue;
                        }
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(i) else {
                            // The parked ones have nothing left to wait for.
                            wake_parked();
                            return;
                        };
                        if let Some(p) = &p {
                            (p.hook)();
                        }
                        let r = f(item);
                        done.lock().unwrap_or_else(|p| p.into_inner()).push((i, r));
                    }
                };
                if let Err(e) = catch_unwind(AssertUnwindSafe(work)) {
                    // The others take no further item; the first unwind is
                    // the one that goes on, after the scope.
                    next.store(usize::MAX / 2, Ordering::Relaxed);
                    stopped.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert(e);
                    wake_parked();
                }
            });
        }
    });
    if let Some(e) = stopped.into_inner().unwrap_or_else(|p| p.into_inner()) {
        resume_unwind(e);
    }
    let mut done = done.into_inner().unwrap_or_else(|p| p.into_inner());
    done.sort_by_key(|(i, _)| *i);
    done.into_iter().map(|(_, r)| r).collect()
}

/// `work` on `threads` scoped threads (at most the [`Pace`]'s width when
/// one is set), for workers that share a queue of their own; each calls
/// [`before_item`] before each item. An unwind in any of them goes on from
/// here with its own payload once all have ended (no scope panic).
///
/// ```
/// use std::sync::Mutex;
/// let queue = Mutex::new(vec![1, 2, 3]);
/// let sum = Mutex::new(0);
/// wpantry::utils::parallel::spread(2, || {
///     while let Some(i) = { queue.lock().unwrap().pop() } {
///         wpantry::utils::parallel::before_item();
///         *sum.lock().unwrap() += i;
///     }
/// });
/// assert_eq!(*sum.lock().unwrap(), 6);
/// ```
pub fn spread(threads: usize, work: impl Fn() + Sync) {
    let threads = pace().map_or(threads, |p| threads.min(p.width));
    let stopped: Mutex<Option<Box<dyn Any + Send>>> = Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                if let Err(e) = catch_unwind(AssertUnwindSafe(&work)) {
                    stopped.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert(e);
                }
            });
        }
    });
    if let Some(e) = stopped.into_inner().unwrap_or_else(|p| p.into_inner()) {
        resume_unwind(e);
    }
}

/// The machine's logical cores (1 when unknown), paced or not: a
/// [`par_map`] over them keeps its full width ready for when the pace
/// clears. For sizing work that runs its own threads (a subprocess's
/// `--threads`), use [`cpu_budget`].
pub fn cores() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// The cores work outside [`par_map`] may use: [`cores`], at most the
/// [`Pace`]'s width when one is set (at least 1).
pub fn cpu_budget() -> usize {
    pace().map_or(cores(), |p| cores().min(p.width)).max(1)
}

#[cfg(test)]
#[path = "parallel_tests.rs"]
mod tests;
