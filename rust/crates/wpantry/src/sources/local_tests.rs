//! Local sources (`path = ...`), read into the copy a fetched source makes.
//! The oracle throughout is the copy on disk where
//! `sources::user::place` puts it, the source's kept outcome
//! (`fetch::last_error`), and a count of content reads ([`READS`]), never
//! timing.

use super::*;
use crate::sources::file::merged;
use crate::sources::testing::cache;
use crate::sources::user::fetch_files;
use crate::utils::net::Fake;
use crate::utils::temp::TempDir;

/// A local source of the user's from one sources-file entry.
fn local(id: &str, kind: &str, format: &str, path: &Path, extra: &str) -> Source {
    let body = format!(
        "[[source]]\nid = \"{id}\"\nkind = \"{kind}\"\nformat = \"{format}\"\npath = '{}'\n{extra}\n",
        path.display()
    );
    merged(&body).unwrap().into_iter().last().unwrap()
}

fn reads() -> usize {
    READS.with(|r| r.get())
}

/// Changes a file's modification time, so a rewrite of the same size is
/// seen as a change on any file system's clock.
fn bump(p: &Path, secs: u64) {
    let f = std::fs::File::options().write(true).open(p).unwrap();
    f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000 + secs)).unwrap();
}

/// Risk: a local list or rules file doesn't end up where the scan reads
/// copies, or is only read online. Oracle: the copy's path and bytes, with
/// a network that answers nothing and `offline` set (a local source
/// contacts nobody, so it is still read).
#[test]
fn a_local_file_lands_in_its_place_offline_too() {
    let (d, c) = cache();
    let rules = d.path().join("rules");
    let list = d.path().join("team-hashes.txt");
    std::fs::write(&list, "aa\nbb\n").unwrap();
    let s = local("t-local-hashes", "hashes", "lines", &list, "");
    let net = Fake::offline();
    assert!(fetch_files(&c, &net, &rules, std::slice::from_ref(&s), std::slice::from_ref(&s), true).is_empty());
    assert_eq!(std::fs::read(rules.join("iocs/user-t-local-hashes.hashes.txt")).unwrap(), b"aa\nbb\n");
    assert!(net.requests().is_empty(), "nothing asked of the network");
}

/// Risk: an unchanged file is read on every scan (slow on a big rules
/// folder), or a changed one is never read again. Oracle: the read count
/// and the copy's bytes; the fingerprint is the files' sizes and times.
#[test]
fn a_local_file_is_read_again_only_when_it_changed() {
    let (d, c) = cache();
    let rules = d.path().join("rules");
    let list = d.path().join("hosts.txt");
    std::fs::write(&list, "one.example\n").unwrap();
    bump(&list, 1);
    let s = local("t-local-fresh", "hosts", "lines", &list, "refresh = \"1s\"");
    let copy = rules.join("iocs/user-t-local-fresh.hosts.txt");
    let net = Fake::offline();
    let run = || fetch_files(&c, &net, &rules, std::slice::from_ref(&s), std::slice::from_ref(&s), false);
    let before = reads();
    assert!(run().is_empty());
    assert_eq!(reads() - before, 1);
    assert!(run().is_empty() && run().is_empty());
    assert_eq!(reads() - before, 1, "unchanged: not read again, whatever its refresh says");
    std::fs::write(&list, "two.example\n").unwrap();
    bump(&list, 2);
    assert!(run().is_empty());
    assert_eq!(reads() - before, 2, "changed (same size, new time): read again");
    assert_eq!(std::fs::read_to_string(&copy).unwrap(), "two.example\n");
    std::fs::remove_file(&copy).unwrap();
    assert!(run().is_empty());
    assert_eq!(reads() - before, 3, "a copy that went away is made again");
    assert!(copy.is_file());
}

/// Risk: a source file that went away, or one that fails its pin, wipes the
/// copy the scan had, or fails with no word of why. Oracle: the last good
/// copy's bytes stay and the source's kept error says why, as for a
/// download that failed.
#[test]
fn a_missing_or_mispinned_file_keeps_the_last_good_copy_and_says_why() {
    let (d, c) = cache();
    let rules = d.path().join("rules");
    let list = d.path().join("names.txt");
    std::fs::write(&list, "evil.exe\n").unwrap();
    let pin = crate::utils::sha256::hex(b"evil.exe\n");
    let s = local("t-local-keep", "filenames", "lines", &list, &format!("sha256 = \"{pin}\""));
    let copy = rules.join("iocs/user-t-local-keep.filenames.txt");
    let net = Fake::offline();
    let run = || fetch_files(&c, &net, &rules, std::slice::from_ref(&s), std::slice::from_ref(&s), false);
    assert!(run().is_empty());
    assert_eq!(std::fs::read_to_string(&copy).unwrap(), "evil.exe\n", "matches its pin");
    std::fs::write(&list, "other.exe\nmore.exe\n").unwrap();
    assert!(run().is_empty());
    assert_eq!(std::fs::read_to_string(&copy).unwrap(), "evil.exe\n", "a copy that fails its pin isn't kept");
    assert!(fetch::last_error(&s.id).unwrap().contains("sha256 pin"), "{:?}", fetch::last_error(&s.id));
    let before = reads();
    assert!(run().is_empty());
    assert_eq!(reads() - before, 1, "a refused read is tried again next time, not taken as current");
    std::fs::remove_file(&list).unwrap();
    assert!(run().is_empty(), "the last good copy is in use");
    assert_eq!(std::fs::read_to_string(&copy).unwrap(), "evil.exe\n");
    assert!(fetch::last_error(&s.id).unwrap().contains("names.txt"), "{:?}", fetch::last_error(&s.id));
    std::fs::remove_file(&copy).unwrap();
    let failed = run();
    assert_eq!(failed.len(), 1, "no copy at all: said so");
    assert!(failed[0].1.contains("names.txt"), "with the reason: {failed:?}");
}

/// Risk: a local file past the cap is read whole (memory), or past the
/// copy. Oracle: `max_bytes` refuses it, as a download over its cap is.
#[test]
fn a_local_file_over_its_cap_is_refused() {
    let (d, c) = cache();
    let list = d.path().join("big.txt");
    std::fs::write(&list, "x".repeat(64)).unwrap();
    let s = local("t-local-big", "hashes", "lines", &list, "max_bytes = 10");
    assert_eq!(fetch::file_of(&c, &Fake::offline(), &s, "user:t-local-big", false).unwrap(), None);
    assert!(fetch::last_error(&s.id).unwrap().contains("over 10 bytes"), "{:?}", fetch::last_error(&s.id));
    let ok = local("t-local-small", "hashes", "lines", &list, "max_bytes = 64");
    assert!(fetch::file_of(&c, &Fake::offline(), &ok, "user:t-local-small", false).unwrap().is_some());
}

/// Risk: a folder of rules is joined in an order that changes between
/// machines, takes files that aren't rules or are in subfolders, or a
/// folder is accepted for a list. Oracle: the joined copy (byte-wise name
/// order, a newline after each file, as Elastic's are joined) and the
/// refusal for a non-YARA kind.
#[test]
fn a_rules_folder_is_its_yar_files_joined_in_name_order() {
    let (d, c) = cache();
    let rules = d.path().join("rules");
    let folder = d.path().join("team-rules");
    std::fs::create_dir_all(folder.join("sub")).unwrap();
    std::fs::write(folder.join("b.yar"), "rule B { condition: true }").unwrap();
    std::fs::write(folder.join("A.yar"), "rule A { condition: true }").unwrap();
    std::fs::write(folder.join("notes.txt"), "not rules").unwrap();
    std::fs::write(folder.join("c.yara"), "rule C { condition: true }").unwrap();
    std::fs::write(folder.join("sub/d.yar"), "rule D { condition: true }").unwrap();
    let s = local("t-local-folder", "yara", "yara", &folder, "");
    let net = Fake::offline();
    assert!(fetch_files(&c, &net, &rules, std::slice::from_ref(&s), std::slice::from_ref(&s), true).is_empty());
    assert_eq!(
        std::fs::read_to_string(rules.join("user-t-local-folder.yar")).unwrap(),
        "rule A { condition: true }\nrule B { condition: true }\n",
        "*.yar directly in the folder, A before b (byte order)"
    );
    let before = reads();
    assert!(fetch_files(&c, &net, &rules, std::slice::from_ref(&s), std::slice::from_ref(&s), true).is_empty());
    assert_eq!(reads(), before, "unchanged folder: not read again");
    std::fs::write(folder.join("e.yar"), "rule E { condition: true }").unwrap();
    assert!(fetch_files(&c, &net, &rules, std::slice::from_ref(&s), std::slice::from_ref(&s), true).is_empty());
    assert_eq!(reads(), before + 1, "a file added: read again");
    assert!(
        std::fs::read_to_string(rules.join("user-t-local-folder.yar"))
            .unwrap()
            .ends_with("rule E { condition: true }\n")
    );
    let pinned = local(
        "t-local-folder-pin",
        "yara",
        "yara",
        &folder,
        &format!(
            "sha256 = \"{}\"",
            crate::utils::sha256::hex(
                b"rule A { condition: true }\nrule B { condition: true }\nrule E { condition: true }\n"
            )
        ),
    );
    assert!(
        fetch::file_of(&c, &net, &pinned, "user:t-local-folder-pin", false).unwrap().is_some(),
        "pin over the join"
    );
    let list = local("t-local-list-folder", "hosts", "lines", &folder, "");
    assert_eq!(fetch::file_of(&c, &net, &list, "user:t-local-list-folder", false).unwrap(), None);
    assert!(fetch::last_error(&list.id).unwrap().contains("only of YARA rules"), "{:?}", fetch::last_error(&list.id));
    let empty = d.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let none = local("t-local-empty", "yara", "yara", &empty, "");
    assert_eq!(fetch::file_of(&c, &net, &none, "user:t-local-empty", false).unwrap(), None);
    assert!(fetch::last_error(&none.id).unwrap().contains("no .yar files"));
    let rules_over = local("t-local-folder-cap", "yara", "yara", &folder, "max_bytes = 40");
    assert_eq!(fetch::file_of(&c, &net, &rules_over, "user:t-local-folder-cap", false).unwrap(), None);
    assert!(fetch::last_error(&rules_over.id).unwrap().contains("40 bytes"), "the cap is over the join");
}

/// Risk: a symlink inside a rules folder reads a file outside it (a
/// secret, another user's file). Oracle: the joined copy holds only the
/// folder's own regular files. The source's path itself may be a symlink:
/// it is resolved once.
#[cfg(unix)]
#[test]
fn a_symlink_in_a_rules_folder_is_not_followed() {
    let (d, c) = cache();
    let rules = d.path().join("rules");
    let outside = d.path().join("outside.yar");
    std::fs::write(&outside, "rule Outside { condition: true }").unwrap();
    let folder = d.path().join("team-rules");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.yar"), "rule A { condition: true }").unwrap();
    std::os::unix::fs::symlink(&outside, folder.join("b.yar")).unwrap();
    std::os::unix::fs::symlink(d.path(), folder.join("up.yar")).unwrap();
    let linked = d.path().join("linked-rules");
    std::os::unix::fs::symlink(&folder, &linked).unwrap();
    let s = local("t-local-links", "yara", "yara", &linked, "");
    let net = Fake::offline();
    assert!(fetch_files(&c, &net, &rules, std::slice::from_ref(&s), std::slice::from_ref(&s), true).is_empty());
    assert_eq!(std::fs::read_to_string(rules.join("user-t-local-links.yar")).unwrap(), "rule A { condition: true }\n");
    let file_link = d.path().join("list-link.txt");
    std::os::unix::fs::symlink(&outside, &file_link).unwrap();
    let one = local("t-local-file-link", "yara", "yara", &file_link, "");
    assert!(fetch::file_of(&c, &net, &one, "user:t-local-file-link", false).unwrap().is_some(), "a symlinked path");
}

/// Risk: a gzip list read from this machine is handled differently from
/// the same list downloaded. Oracle: the copy is the file's bytes as a
/// download's would be, and the indicator reader inflates it into the same
/// entries as the plain list.
#[test]
fn a_gzip_list_is_copied_as_is_and_read_like_a_downloaded_one() {
    let (d, c) = cache();
    let rules = d.path().join("rules");
    let plain = format!("{}\n", crate::utils::sha256::hex(b"bad"));
    let gz = crate::utils::archive::gzip::tests::stored(plain.as_bytes(), Some("h.txt"));
    let list = d.path().join("hashes.txt.gz");
    std::fs::write(&list, &gz).unwrap();
    let s = local("t-local-gz", "hashes", "lines", &list, "");
    let net = Fake::offline();
    assert!(fetch_files(&c, &net, &rules, std::slice::from_ref(&s), std::slice::from_ref(&s), true).is_empty());
    assert_eq!(std::fs::read(rules.join("iocs/user-t-local-gz.hashes.txt")).unwrap(), gz);
    let zipped = crate::sources::indicator_lists::store(&rules.join("iocs"), &|id| id == "t-local-gz").len();
    let flat = TempDir::new("flat").unwrap();
    std::fs::write(flat.path().join("user-t-local-gz.hashes.txt"), &plain).unwrap();
    let unzipped = crate::sources::indicator_lists::store(flat.path(), &|id| id == "t-local-gz").len();
    assert!(zipped > 0);
    assert_eq!(zipped, unzipped);
}

/// A folder of `.yar` files holding `files` (name, content), read under a
/// cap of `cap` bytes through the folder read itself.
fn folder_read(files: &[(&str, &str)], cap: u64) -> std::result::Result<Vec<u8>, String> {
    let d = TempDir::new("local-cap").unwrap();
    for (name, body) in files {
        std::fs::write(d.path().join(name), body).unwrap();
    }
    let s = local("t-local-cap", "yara", "yara", d.path(), &format!("max_bytes = {cap}"));
    read(&s, &locate(&s).unwrap())
}

/// Risk: a file and its newline exactly fill the cap, and the next file is
/// empty: it passes a zero-byte check, and the newline after it puts the
/// copy one byte over `max_bytes`. Oracle: the copy is never longer than the
/// cap, and the refusal names the cap, as for any file that does not fit.
/// An empty file needs its newline too, so it is over the cap, not skipped.
#[test]
fn an_empty_file_after_a_folder_that_fills_the_cap_is_refused() {
    let e = folder_read(&[("a.yar", "abcd"), ("b.yar", "")], 5).unwrap_err();
    assert!(e.contains("b.yar") && e.contains("5 bytes"), "{e}");
}

/// Risk: the fix refuses what fits. Oracle: one byte of room is enough for
/// an empty file's newline, and a folder that fills the cap exactly with
/// its last newline is accepted, at exactly `max_bytes` long.
#[test]
fn a_folder_that_fits_the_cap_exactly_is_accepted() {
    assert_eq!(folder_read(&[("a.yar", "abc"), ("b.yar", "")], 5).unwrap(), b"abc\n\n");
    assert_eq!(folder_read(&[("a.yar", "abcd")], 5).unwrap(), b"abcd\n");
    assert!(folder_read(&[("a.yar", "abcde")], 5).is_err(), "no room for the newline");
}

/// Risk: the cap holds for the cases chosen by hand and not for the others.
/// Oracle: over every small cap and every pair or triple of small file
/// sizes, an `Ok` copy is never longer than the cap, and is refused only
/// when the files plus a newline each really exceed it.
#[test]
fn a_joined_folder_is_never_over_its_cap() {
    for cap in 1u64..=8 {
        for sizes in (0..=cap as usize + 1).flat_map(|a| (0..=3).flat_map(move |b| (0..=3).map(move |c| [a, b, c]))) {
            let bodies: Vec<String> = sizes.iter().map(|n| "x".repeat(*n)).collect();
            let files = [("a.yar", bodies[0].as_str()), ("b.yar", bodies[1].as_str()), ("c.yar", bodies[2].as_str())];
            let need: u64 = sizes.iter().map(|n| *n as u64 + 1).sum();
            match folder_read(&files, cap) {
                Ok(b) => {
                    assert!(b.len() as u64 <= cap && b.len() as u64 == need, "cap {cap} sizes {sizes:?}: {}", b.len())
                }
                Err(e) => assert!(need > cap, "cap {cap} sizes {sizes:?} refused though it fits: {e}"),
            }
        }
    }
}

/// Risk: one Latin-1 or UTF-16 `.yar` file in a folder makes the joined
/// copy invalid UTF-8, the rules loader skips the whole copy, and the source
/// contributes no rules with no error and nothing reported unchecked.
/// Oracle: the source's outcome through `fetch_files` (what the scan turns
/// into an `unchecked` finding): it fails naming the bad file, and no copy
/// of the good file is left behind to look like a checked source.
#[test]
fn a_folder_with_a_latin1_or_utf16_rules_file_fails_naming_the_file() {
    let bad: [(&str, &[u8]); 2] = [
        ("latin1.yar", b"rule L { strings: $a = \"caf\xE9\" condition: $a }\n"),
        // UTF-16LE with its byte order mark, as a Windows editor writes it.
        ("utf16.yar", b"\xFF\xFEr\0u\0l\0e\0 \0U\0 \0{\0 \0c\0o\0n\0d\0i\0t\0i\0o\0n\0:\0 \0t\0r\0u\0e\0 \0}\0"),
    ];
    for (name, bytes) in bad {
        let (d, c) = cache();
        let rules = d.path().join("rules");
        let folder = d.path().join("team");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("a-good.yar"), "rule Good { condition: true }").unwrap();
        std::fs::write(folder.join(name), bytes).unwrap();
        let s = local(&format!("t-local-enc-{}", &name[..4]), "yara", "yara", &folder, "");
        let failed =
            fetch_files(&c, &Fake::offline(), &rules, std::slice::from_ref(&s), std::slice::from_ref(&s), true);
        assert_eq!(failed.len(), 1, "{name}: the source is reported failed, not silently empty: {failed:?}");
        assert_eq!(failed[0].0, s.id);
        assert!(failed[0].1.contains(name) && failed[0].1.contains("UTF-8"), "{name}: {}", failed[0].1);
        assert!(!rules.join(format!("user-{}.yar", s.id)).exists(), "{name}: no copy of the good file alone");
    }
}

/// Risk: the same check missed for a single `.yar` file as the source.
/// Oracle: the source fails naming the file; a non-YARA list is untouched
/// (the check is for rules, which the rules loader reads as text).
#[test]
fn a_single_latin1_rules_file_fails_and_a_hosts_list_is_not_checked() {
    let (d, c) = cache();
    let rules = d.path().join("rules");
    let file = d.path().join("one.yar");
    std::fs::write(&file, b"rule L { strings: $a = \"caf\xE9\" condition: $a }").unwrap();
    let s = local("t-local-enc-file", "yara", "yara", &file, "");
    let failed = fetch_files(&c, &Fake::offline(), &rules, std::slice::from_ref(&s), std::slice::from_ref(&s), true);
    assert!(failed.len() == 1 && failed[0].1.contains("one.yar"), "{failed:?}");
    let list = d.path().join("hosts.txt");
    std::fs::write(&list, b"caf\xE9.example\n").unwrap();
    let h = local("t-local-enc-hosts", "hosts", "lines", &list, "");
    assert!(
        fetch_files(&c, &Fake::offline(), &rules, std::slice::from_ref(&h), std::slice::from_ref(&h), true).is_empty()
    );
}

/// Decision (what the YARA loader tolerates): a UTF-8 byte order mark is
/// valid UTF-8 but not YARA syntax,
/// and in a joined folder it would sit mid-file. A file that starts with
/// one is accepted and the mark dropped, so its rules compile.
/// Oracle: the copy's bytes carry no mark, and the compiled rules of the
/// copy (loaded the way a scan loads them) include the BOM file's rule.
#[test]
fn a_utf8_bom_rules_file_is_accepted_with_the_mark_dropped_and_compiles() {
    let (d, c) = cache();
    let rules = d.path().join("rules");
    let folder = d.path().join("team");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.yar"), b"\xEF\xBB\xBFrule Bom_A { strings: $a = \"aaa\" condition: $a }").unwrap();
    std::fs::write(folder.join("b.yar"), b"\xEF\xBB\xBFrule Bom_B { strings: $a = \"bbb\" condition: $a }").unwrap();
    let s = local("t-local-bom", "yara", "yara", &folder, "");
    assert!(
        fetch_files(&c, &Fake::offline(), &rules, std::slice::from_ref(&s), std::slice::from_ref(&s), true).is_empty()
    );
    let copy = std::fs::read(rules.join("user-t-local-bom.yar")).unwrap();
    assert!(!copy.windows(3).any(|w| w == b"\xEF\xBB\xBF"), "no byte order mark left in the copy");
    let loaded = crate::checks::malware::yara::load(&rules, false, &|_: &str| true);
    let names: Vec<&str> = loaded.rules.rules().iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"Bom_A") && names.contains(&"Bom_B"), "both files' rules compile: {names:?}");
    assert!(loaded.skipped.is_empty());
}
