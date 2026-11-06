use super::*;

#[test]
fn cycles_name_a_release_line() {
    assert_eq!(Cycle::Major.of("3.12.4"), "3");
    assert_eq!(Cycle::Minor.of("3.12.4"), "3.12");
    assert_eq!(Cycle::Minor.of("3"), "3");
    assert_eq!(Cycle::Java.of("1.8.0_392"), "8");
    assert_eq!(Cycle::Java.of("1."), "");
    assert_eq!(Cycle::Java.of("21.0.5"), "21");
}
