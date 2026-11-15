//! Work spread over threads: [`par_map`] for probes that wait on a
//! subprocess or the network.
//!
//! An app that links the library can set a process-wide [`Pace`] for a
//! scan it runs in the background: every [`par_map`] then uses at most
//! `width` threads, [`cores`] answers at most `width`, and the pace's hook
//! runs on each worker before each item (to lower the thread's priority,
//! to wait while the app needs the machine, or to unwind and stop). With
//! no pace set, the default, nothing changes. What a scan finds never
//! depends on the pace: [`par_map`] keeps `items`' order at any width.
//!
//! ```
//! use std::sync::Arc;
//! use std::sync::atomic::{AtomicUsize, Ordering};
//! use wpantry::utils::parallel::{Pace, cores, par_map, set_pace};
//! let calls = Arc::new(AtomicUsize::new(0));
//! let c = calls.clone();
//! let before = set_pace(Some(Pace::new(1, move || { c.fetch_add(1, Ordering::SeqCst); })));
//! assert_eq!(cores(), 1);
//! assert_eq!(par_map(&[1, 2, 3], 8, |i| i * 2), vec![2, 4, 6]);
//! assert_eq!(calls.load(Ordering::SeqCst), 3);
//! set_pace(before);
//! ```

use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};

/// How many probes (subprocesses, mostly) run at once in [`par_map`].
pub const PROBES: usize = 8;

/// A process-wide limit on the library's worker threads (see the module
/// doc). One scan at a time should hold it: it is not per scan.
#[derive(Clone)]
pub struct Pace {
    /// Most threads any [`par_map`] runs at once (at least 1).
    pub width: usize,
    /// Run on a worker thread before each item.
    pub hook: Arc<dyn Fn() + Send + Sync>,
}

impl Pace {
    pub fn new(width: usize, hook: impl Fn() + Send + Sync + 'static) -> Pace {
        Pace { width: width.max(1), hook: Arc::new(hook) }
    }
}

impl std::fmt::Debug for Pace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pace({})", self.width)
    }
}

static PACE: RwLock<Option<Pace>> = RwLock::new(None);

/// Set (Some) or clear (None) the pace; returns the one it replaces.
pub fn set_pace(pace: Option<Pace>) -> Option<Pace> {
    std::mem::replace(&mut *PACE.write().unwrap_or_else(|p| p.into_inner()), pace)
}

/// The pace in effect, if any.
pub fn pace() -> Option<Pace> {
    PACE.read().unwrap_or_else(|p| p.into_inner()).clone()
}

/// `f` over `items`, at most `width` at once (and at most the [`Pace`]'s
/// width when one is set), the results in `items`' order.
/// For probes that wait on a subprocess or the network: an inventory that
/// runs a few hundred of them one after another spends seconds waiting.
pub fn par_map<T: Sync, R: Send>(items: &[T], width: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let pace = pace();
    let width = pace.as_ref().map_or(width, |p| width.min(p.width));
    let hook = pace.as_ref().map(|p| p.hook.as_ref());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let done = std::sync::Mutex::new(Vec::with_capacity(items.len()));
    std::thread::scope(|s| {
        for _ in 0..width.clamp(1, items.len().max(1)) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { return };
                    if let Some(h) = hook {
                        h();
                    }
                    let r = f(item);
                    done.lock().expect("lock").push((i, r));
                }
            });
        }
    });
    let mut done = done.into_inner().expect("lock");
    done.sort_by_key(|(i, _)| *i);
    done.into_iter().map(|(_, r)| r).collect()
}

/// The machine's logical cores (1 when unknown), at most the [`Pace`]'s
/// width when one is set.
pub fn cores() -> usize {
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    pace().map_or(n, |p| n.min(p.width))
}

#[cfg(test)]
#[path = "parallel_tests.rs"]
mod tests;
