use super::*;

#[test]
fn versions_in_tool_output() {
    assert_eq!(version_in("git version 2.43.0"), "2.43.0");
    assert_eq!(version_in("v8.30.1"), "8.30.1");
    assert_eq!(version_in("RPM version 4.19.1.1"), "4.19.1.1");
    assert_eq!(version_in("Docker version 27.3.1, build ce12230"), "27.3.1");
    assert_eq!(version_in("build 7 of 12"), "");
}
