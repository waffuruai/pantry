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

/// Risk: on Windows `canonicalize` spells a path `\\?\C:\...`, which the
/// comparison took for another drive, so a folder given in its canonical
/// spelling (the home folder's, as `folders` adds it) did not hold a path
/// written plainly, nor the reverse. Oracle: both spellings are the same
/// place. Windows only: `\\?\` is no prefix elsewhere.
#[cfg(windows)]
#[test]
fn the_verbatim_spelling_is_the_same_folder() {
    assert!(within(r"C:\Users\u\Documents\x", r"\\?\C:\Users\u\Documents"));
    assert!(within(r"\\?\C:\Users\u\Documents\x", r"C:\Users\u\Documents"));
    assert!(!within(r"\\?\C:\Users\u\Code", r"C:\Users\u\Documents"));
}

/// Risk: the check goes by the spelling alone, so a PATH entry or a login
/// item's program that reaches `Documents` through a link (`~/bin` linked to
/// `~/Documents/bin`, `work/docs/..`-style spellings, a relative path from
/// the folder itself) passes it, and the scan stats or opens the folder the
/// flag promised not to touch. Oracle: a layout of real links in a temp
/// dir; the answer is fixed by where each path leads, and nothing leads
/// anywhere for a loop, a dangling link or a path that is not there.
/// Known bad: `is_left_out` alone.
#[cfg(unix)]
#[test]
fn a_path_that_reaches_a_left_out_folder_through_a_link_is_left_out() {
    use std::os::unix::fs::symlink;
    let d = crate::utils::temp::TempDir::new("privacy-links").unwrap();
    // The temp folder under its canonical spelling (macOS keeps it behind a link): the guard names
    // the folders as `folders` does, in the spelling the links lead to.
    let h = std::fs::canonicalize(d.path()).unwrap().join("home");
    std::fs::create_dir_all(h.join("Documents/bin")).unwrap();
    std::fs::create_dir_all(h.join("work")).unwrap();
    std::fs::create_dir_all(h.join("bin-real")).unwrap();
    symlink("Documents/bin", h.join("bin")).unwrap(); // relative target
    symlink(h.join("Documents"), h.join("work/docs")).unwrap(); // absolute target
    symlink("hop2", h.join("hop1")).unwrap();
    symlink("Documents", h.join("hop2")).unwrap(); // two links in a row
    symlink("loop-b", h.join("loop-a")).unwrap();
    symlink("loop-a", h.join("loop-b")).unwrap();
    symlink("nowhere", h.join("dangling")).unwrap();
    let guard = leave_out(vec![h.join("Documents")], Vec::new());
    for inside in [
        "Documents/bin",
        "bin",
        "work/docs",
        "work/docs/bin",
        "hop1/bin",
        "work/docs/..",
        "work/docs/../Documents/x",
        "bin/tool",
    ] {
        assert!(reaches_left_out(h.join(inside)), "{inside}");
    }
    for outside in ["bin-real", "work", "loop-a", "loop-a/x", "dangling", "dangling/x", "absent/x"] {
        assert!(!reaches_left_out(h.join(outside)), "{outside}");
    }
    // The cheap spelling check does not know about links: that is the gap.
    assert!(!is_left_out(h.join("bin")));
    // A path the user named inside the folder is still let in.
    drop(guard);
    let guard = leave_out(vec![h.join("Documents")], vec![h.join("Documents/bin")]);
    assert!(!reaches_left_out(h.join("bin")), "the named path is read as asked, by the link too");
    drop(guard);
    assert!(!reaches_left_out(h.join("bin")), "nothing is left out once the guard is gone");
}
