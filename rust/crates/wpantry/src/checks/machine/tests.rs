use super::*;

#[test]
fn a_probe_result_is_joined() {
    assert_eq!(std::thread::scope(|s| joined(s.spawn(|| 41 + 1))), 42);
}
