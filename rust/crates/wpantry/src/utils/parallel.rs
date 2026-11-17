//! Work spread over threads: [`par_map`] for probes that wait on a
//! subprocess or the network.

use std::sync::atomic::Ordering;

/// How many probes (subprocesses, mostly) run at once in [`par_map`].
pub const PROBES: usize = 8;

/// `f` over `items`, at most `width` at once, the results in `items`' order.
/// For probes that wait on a subprocess or the network: an inventory that
/// runs a few hundred of them one after another spends seconds waiting.
pub fn par_map<T: Sync, R: Send>(items: &[T], width: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let done = std::sync::Mutex::new(Vec::with_capacity(items.len()));
    std::thread::scope(|s| {
        for _ in 0..width.clamp(1, items.len().max(1)) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { return };
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

/// The machine's logical cores (1 when unknown).
pub fn cores() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

#[cfg(test)]
#[path = "parallel_tests.rs"]
mod tests;
