use super::*;
use std::time::{Duration, Instant};

#[test]
fn par_map_keeps_order_and_runs_at_once() {
    let items: Vec<u64> = (0..24).collect();
    let start = Instant::now();
    let out = par_map(&items, 8, |&i| {
        std::thread::sleep(Duration::from_millis(50));
        i * 2
    });
    assert_eq!(out, items.iter().map(|i| i * 2).collect::<Vec<_>>());
    // 24 sleeps of 50 ms, 8 at a time, take about 150 ms, not 1.2 s.
    assert!(start.elapsed() < Duration::from_millis(900), "{:?}", start.elapsed());
    assert!(par_map(&[] as &[u8], 8, |&b| b).is_empty());
}
