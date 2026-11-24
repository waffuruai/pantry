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
