use super::*;

/// Oracle: a path is left out exactly while a guard names a folder at or
/// above it, by spelling; dropping the guard lets it through again, and a
/// second guard's folders don't outlive it.
#[test]
fn a_guard_leaves_its_folders_out_until_dropped() {
    let home = Path::new("/no-such-home-privacy-test");
    assert!(!is_left_out(home.join("Documents/x")));
    let mac = leave_out(folders(home, true));
    for inside in ["Documents", "Desktop/a.txt", "Downloads/r/.git", "Library/Mobile Documents/x", "Pictures/p.jpg"] {
        assert!(is_left_out(home.join(inside)), "{inside}");
    }
    for outside in ["code/r", "Library/LaunchAgents/x.plist", "DocumentsOld/x", ".config"] {
        assert!(!is_left_out(home.join(outside)), "{outside}");
    }
    let other = Path::new("/no-such-other-home");
    let plain = leave_out(folders(other, false));
    assert!(is_left_out(other.join("Desktop")));
    assert!(!is_left_out(other.join("Pictures")), "the macOS list only on macOS");
    drop(mac);
    assert!(!is_left_out(home.join("Documents/x")));
    assert!(is_left_out(other.join("Desktop")));
    drop(plain);
    assert!(!is_left_out(other.join("Desktop")));
}
