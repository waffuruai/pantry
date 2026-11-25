use super::*;

/// Oracle: a path is left out exactly while a guard names a folder at or
/// above it, by spelling; dropping the guard lets it through again, and a
/// second guard's folders don't outlive it.
#[test]
fn a_guard_leaves_its_folders_out_until_dropped() {
    let home = Path::new("/no-such-home-privacy-test");
    assert!(!is_left_out(home.join("Documents/x")));
    let mac = leave_out(folders(home, true), Vec::new());
    for inside in ["Documents", "Desktop/a.txt", "Downloads/r/.git", "Library/Mobile Documents/x", "Pictures/p.jpg"] {
        assert!(is_left_out(home.join(inside)), "{inside}");
    }
    for outside in ["code/r", "Library/LaunchAgents/x.plist", "DocumentsOld/x", ".config"] {
        assert!(!is_left_out(home.join(outside)), "{outside}");
    }
    let other = Path::new("/no-such-other-home");
    let plain = leave_out(folders(other, false), Vec::new());
    assert!(is_left_out(other.join("Desktop")));
    assert!(!is_left_out(other.join("Pictures")), "the macOS list only on macOS");
    drop(mac);
    assert!(!is_left_out(home.join("Documents/x")));
    assert!(is_left_out(other.join("Desktop")));
    drop(plain);
    assert!(!is_left_out(other.join("Desktop")));
}

/// Risk: the match was `starts_with` on the spelling as given, so on a
/// case-insensitive volume `/home/documents/x` or
/// `/home/Library/../Documents/x` (a launch agent's program, a PATH entry)
/// was not recognised as inside `Documents`, and the scan went on to stat it
/// or run `codesign` on it, which raises the privacy prompt. Oracle: the
/// same place spelled differently is left out or not alike. `..` and `.`
/// fold on every system. Case folds where the volume ignores it (macOS,
/// Windows) and not on Linux, whose `documents` is another folder. The
/// exception for a path the user named folds the same way. No path here
/// exists: nothing is opened.
/// Known bad: plain `starts_with`.
#[test]
fn a_left_out_folder_is_recognised_in_every_spelling_of_it() {
    let home = Path::new("/no-such-home-spelling");
    let _guard = leave_out(folders(home, true), vec![home.join("Documents/named")]);
    for inside in [
        "Documents",
        "Documents/x",
        "Library/../Documents/x",
        "code/./../Desktop/y",
        "Documents/named/../other",
        "Documents/named/..",
        "Documents/./x",
        "Library/Containers/../Mail/a",
    ] {
        assert!(is_left_out(home.join(inside)), "{inside}");
    }
    for outside in ["Documents/../code/r", "Documents/named/sub/../x", "DocumentsOld/x", "Documents/named", "x/../y"] {
        assert!(!is_left_out(home.join(outside)), "{outside}");
    }
    // Case: the same folder on a case-insensitive volume, another one on Linux.
    let folds = cfg!(any(target_os = "macos", windows));
    for (spelled, left) in [
        ("documents/x", folds),
        ("DOWNLOADS", folds),
        ("Library/mobile documents/x", folds),
        ("library/../DESKTOP/z", folds),
        // The named path folds the same way: its own subtree, in another case, still gets in
        // where case does not matter, and stays left out where it does.
        ("Documents/NAMED/src", !folds),
        ("DOCUMENTS/other", folds),
    ] {
        assert_eq!(is_left_out(home.join(spelled)), left, "{spelled}, case-insensitive volume: {folds}");
    }
    // `within`, the comparison the scan uses for the paths the user names.
    assert!(within(home.join("a/../Documents/x"), home.join("Documents")));
    assert!(!within(home.join("Documents"), home.join("Documents/x")), "a folder is not inside its child");
    assert_eq!(within(home.join("DOCUMENTS/x"), home.join("documents")), folds);
}
