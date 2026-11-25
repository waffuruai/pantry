//! Folders of OSV records on this machine (`format = "osv-dir"`). The
//! oracles are the rows the load leaves in `local_vulns` (by source and
//! id), the counts and error `wpantry sources` shows, a count of folder
//! reads ([`READS`], never timing), and what [`osv::lookup`] answers for an
//! item, offline, with nothing from OSV cached.

use super::*;
use crate::sources::file::merged;
use crate::sources::testing::cache;
use crate::utils::net::Fake;
use crate::utils::temp::TempDir;
use serde_json::json;
use std::path::Path;

/// An osv-dir source of the user's from one sources-file entry.
fn dir_source(id: &str, path: &Path, extra: &str) -> Source {
    let body = format!(
        "[[source]]\nid = \"{id}\"\nkind = \"advisories\"\nformat = \"osv-dir\"\npath = '{}'\n{extra}\n",
        path.display()
    );
    merged(&body).unwrap().into_iter().last().unwrap()
}

fn reads() -> usize {
    READS.with(|r| r.get())
}

/// A record affecting `pkg` in `eco` below `fixed`.
fn rec(id: &str, eco: &str, pkg: &str, fixed: &str) -> Value {
    json!({"id": id, "summary": format!("{id} summary"), "modified": "2026-11-01T00:00:00Z",
           "affected": [{"package": {"ecosystem": eco, "name": pkg},
                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]})
}

fn put(dir: &Path, rel: &str, body: impl AsRef<[u8]>) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

/// Changes a file's modification time, so a rewrite of the same size is a
/// change on any file system's clock.
fn bump(p: &Path, secs: u64) {
    let f = std::fs::File::options().write(true).open(p).unwrap();
    f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000 + secs)).unwrap();
}

/// The ids a source holds, in order.
fn held(c: &Cache, source: &str) -> Vec<String> {
    let mut stmt = c.conn.prepare("SELECT id FROM local_vulns WHERE source = ? ORDER BY id").unwrap();
    stmt.query_map([source], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap()
}

fn run(c: &Cache, s: &Source) -> Vec<(String, String)> {
    load(c, std::slice::from_ref(s), std::slice::from_ref(s)).unwrap()
}

fn item(e: &str, n: &str, v: &str) -> Item {
    (e.into(), n.into(), v.into())
}

/// Risk: records in the folder aren't loaded, or only a flat folder works,
/// or a deeper layout reads more of the disk than the rules allow. Oracle:
/// the ids held after a load: the flat file and the one-level
/// `<ecosystem>/` file, not the one two levels down; the counts say two
/// records and no file skipped.
#[test]
fn a_folder_and_one_level_of_subfolders_load_and_deeper_is_ignored() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    put(&dir, "TEAM-1.json", rec("TEAM-1", "npm", "a", "1.0.1").to_string());
    put(&dir, "npm/TEAM-2.json", rec("TEAM-2", "npm", "b", "1.0.1").to_string());
    put(&dir, "npm/deep/TEAM-3.json", rec("TEAM-3", "npm", "c", "1.0.1").to_string());
    put(&dir, "notes.txt", "not a record");
    let s = dir_source("t-dir-load", &dir, "");
    assert!(run(&c, &s).is_empty());
    assert_eq!(held(&c, "t-dir-load"), ["TEAM-1", "TEAM-2"]);
    assert_eq!(counts(&c, "t-dir-load").unwrap(), Some((2, 0)));
    assert!(fetch::last_error("t-dir-load").is_none());
}

/// Risk: a symlink in the folder reads a file or folder outside it.
/// Oracle: only the folder's own regular file is held; the symlinked file
/// and the records under a symlinked subfolder are not, and nothing about
/// them is counted as skipped (they aren't read at all).
#[cfg(unix)]
#[test]
fn a_symlinked_file_or_subfolder_is_not_followed() {
    let (d, c) = cache();
    let outside = d.path().join("outside");
    put(&outside, "OUT-1.json", rec("OUT-1", "npm", "a", "1.0.1").to_string());
    let dir = d.path().join("advisories");
    put(&dir, "TEAM-1.json", rec("TEAM-1", "npm", "a", "1.0.1").to_string());
    std::os::unix::fs::symlink(outside.join("OUT-1.json"), dir.join("OUT-1.json")).unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("pypi")).unwrap();
    let s = dir_source("t-dir-links", &dir, "");
    assert!(run(&c, &s).is_empty());
    assert_eq!(held(&c, "t-dir-links"), ["TEAM-1"]);
    assert_eq!(counts(&c, "t-dir-links").unwrap(), Some((1, 0)));
}

/// Risk: one bad file stops the whole folder, or bad files vanish without
/// a word. Oracle: the good record is held, and the three bad files (not
/// JSON, JSON that isn't an OSV record, a record with no usable
/// `affected`) are counted as skipped.
#[test]
fn files_that_arent_osv_records_are_skipped_and_counted() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    put(&dir, "good.json", rec("TEAM-1", "npm", "a", "1.0.1").to_string());
    put(&dir, "broken.json", "{\"id\": \"TEAM-2\", ");
    put(&dir, "other.json", json!({"name": "a package.json"}).to_string());
    put(&dir, "empty.json", json!({"id": "TEAM-3", "affected": []}).to_string());
    put(&dir, "nameless.json", json!({"id": "TEAM-4", "affected": [{"package": {"ecosystem": "npm"}}]}).to_string());
    let s = dir_source("t-dir-skip", &dir, "");
    assert!(run(&c, &s).is_empty());
    assert_eq!(held(&c, "t-dir-skip"), ["TEAM-1"]);
    assert_eq!(counts(&c, "t-dir-skip").unwrap(), Some((1, 4)));
    assert!(record(br#"{"id": "has space", "affected": [{"package": {"ecosystem": "npm", "name": "a"}}]}"#).is_none());
    assert!(
        record(br#"{"id": "G-1", "affected": [{"ranges": [{"type": "GIT", "repo": "https://x.example/r"}]}]}"#)
            .is_some()
    );
}

/// Risk: two files with the same id give a different record on different
/// machines (directory order). Oracle: the file later in byte-wise path
/// order wins (`b.json` over `a.json`, `npm/a.json` over both, since `/`
/// sorts after `.`), whatever order they were written in.
#[test]
fn a_duplicate_id_goes_to_the_later_path() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    put(&dir, "npm/a.json", rec("TEAM-1", "npm", "third", "1.0.1").to_string());
    put(&dir, "b.json", rec("TEAM-1", "npm", "second", "1.0.1").to_string());
    put(&dir, "a.json", rec("TEAM-1", "npm", "first", "1.0.1").to_string());
    let s = dir_source("t-dir-dup", &dir, "");
    assert!(run(&c, &s).is_empty());
    let (r, _) = by_id(&c, "TEAM-1", false).unwrap().unwrap();
    assert_eq!(r["affected"][0]["package"]["name"], "third");
    assert_eq!(counts(&c, "t-dir-dup").unwrap(), Some((1, 0)));
}

/// Risk: a folder with too many files, a file over the cap, or too many
/// bytes together is read anyway (memory, time), or wipes the last good
/// load. Oracle: each limit refuses the read with the reason kept for
/// `wpantry sources`; the records of the last good load stay.
#[test]
fn the_limits_refuse_the_read_and_keep_the_last_good_load() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    put(&dir, "a.json", rec("TEAM-1", "npm", "a", "1.0.1").to_string());
    let s = dir_source("t-dir-limits", &dir, "max_bytes = 600");
    let roomy = Limits { files: 2, bytes: 1500 };
    let once = |limits: Limits| load_with(&c, std::slice::from_ref(&s), std::slice::from_ref(&s), limits).unwrap();
    assert!(once(roomy).is_empty());
    assert_eq!(held(&c, "t-dir-limits"), ["TEAM-1"]);
    put(&dir, "b.json", rec("TEAM-2", "npm", "b", "1.0.1").to_string());
    put(&dir, "c.json", rec("TEAM-3", "npm", "c", "1.0.1").to_string());
    assert!(once(roomy).is_empty(), "a last good load is in use: not unchecked");
    assert!(fetch::last_error(&s.id).unwrap().contains("more than 2 .json files"), "{:?}", fetch::last_error(&s.id));
    assert_eq!(held(&c, "t-dir-limits"), ["TEAM-1"], "the last good load stays");
    std::fs::remove_file(dir.join("c.json")).unwrap();
    put(&dir, "b.json", format!("{} {}", rec("TEAM-2", "npm", "b", "1.0.1"), " ".repeat(500)));
    assert!(once(roomy).is_empty());
    assert!(fetch::last_error(&s.id).unwrap().contains("over 600 bytes"), "{:?}", fetch::last_error(&s.id));
    assert_eq!(held(&c, "t-dir-limits"), ["TEAM-1"]);
    put(&dir, "b.json", format!("{} {}", rec("TEAM-2", "npm", "b", "1.0.1"), " ".repeat(300)));
    assert!(once(Limits { files: 2, bytes: 600 }).is_empty());
    assert!(fetch::last_error(&s.id).unwrap().contains("600 bytes together"), "{:?}", fetch::last_error(&s.id));
    assert_eq!(held(&c, "t-dir-limits"), ["TEAM-1"]);
    put(&dir, "b.json", rec("TEAM-2", "npm", "b", "1.0.1").to_string());
    assert!(once(roomy).is_empty());
    assert_eq!(held(&c, "t-dir-limits"), ["TEAM-1", "TEAM-2"], "back under the limits: read");
    assert_eq!((MAX_FILES, MAX_TOTAL_BYTES), (100_000, 1 << 30), "the limits the spec names");
    // No good load at all: the scan says so.
    let fresh = dir_source("t-dir-limits-new", &dir, "max_bytes = 10");
    let failed = load(&c, std::slice::from_ref(&fresh), std::slice::from_ref(&fresh)).unwrap();
    assert_eq!(failed.len(), 1);
    assert!(failed[0].1.contains("over 10 bytes"), "{failed:?}");
}

/// Risk: a pinned folder is used with files other than the ones checked,
/// or the pin isn't the one the spec defines. Oracle: [`pin`] over the
/// files (relative path, size, bytes, in byte-wise path order) matches and
/// loads; one changed byte is refused and keeps the pinned records.
#[test]
fn a_pin_over_the_folder_is_checked() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    let a = rec("TEAM-1", "npm", "a", "1.0.1").to_string();
    let b = rec("TEAM-2", "PyPI", "b", "1.0.1").to_string();
    put(&dir, "npm/a.json", &a);
    put(&dir, "b.json", &b);
    let want = pin(&[(b"npm/a.json", a.as_bytes()), (b"b.json", b.as_bytes())]);
    let spelled = crate::utils::sha256::hex(format!("b.json\n{}\n{b}npm/a.json\n{}\n{a}", b.len(), a.len()).as_bytes());
    assert_eq!(want, spelled, "the pin as the spec spells it");
    // The spec's worked example, as its shell recipe computes it.
    assert_eq!(
        pin(&[(b"npm/b.json", b"[]"), (b"a.json", b"{}")]),
        "3b6c89d0178b63e132c8513b2914d4df4443bc5f47fe77f0ac661d7eb1767f0b"
    );
    let s = dir_source("t-dir-pin", &dir, &format!("sha256 = \"{want}\""));
    assert!(run(&c, &s).is_empty());
    assert_eq!(held(&c, "t-dir-pin"), ["TEAM-1", "TEAM-2"]);
    put(&dir, "b.json", b.replace("1.0.1", "1.0.2"));
    assert!(run(&c, &s).is_empty());
    assert!(fetch::last_error(&s.id).unwrap().contains("sha256 pin"), "{:?}", fetch::last_error(&s.id));
    let (r, _) = by_id(&c, "TEAM-2", false).unwrap().unwrap();
    assert_eq!(r["affected"][0]["ranges"][0]["events"][1]["fixed"], "1.0.1", "the pinned record stays");
}

/// Risk: an unchanged folder is read on every scan (slow on a big one), or
/// an added, changed or removed file doesn't take effect. Oracle: the read
/// count and the ids held after each change.
#[test]
fn only_a_changed_folder_is_read_and_each_change_takes_effect() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    put(&dir, "a.json", rec("TEAM-1", "npm", "a", "1.0.1").to_string());
    bump(&dir.join("a.json"), 1);
    let s = dir_source("t-dir-fresh", &dir, "refresh = \"1s\"");
    let before = reads();
    assert!(run(&c, &s).is_empty());
    assert!(run(&c, &s).is_empty() && run(&c, &s).is_empty());
    assert_eq!(reads() - before, 1, "unchanged: not read again, whatever its refresh says");
    put(&dir, "npm/b.json", rec("TEAM-2", "npm", "b", "1.0.1").to_string());
    assert!(run(&c, &s).is_empty());
    assert_eq!((reads() - before, held(&c, "t-dir-fresh")), (2, vec!["TEAM-1".to_string(), "TEAM-2".to_string()]));
    put(&dir, "a.json", rec("TEAM-1", "npm", "a", "1.0.2").to_string());
    bump(&dir.join("a.json"), 2);
    assert!(run(&c, &s).is_empty());
    assert_eq!(reads() - before, 3, "changed (same size, new time): read again");
    let (r, _) = by_id(&c, "TEAM-1", false).unwrap().unwrap();
    assert_eq!(r["affected"][0]["ranges"][0]["events"][1]["fixed"], "1.0.2");
    std::fs::remove_file(dir.join("npm/b.json")).unwrap();
    assert!(run(&c, &s).is_empty());
    assert_eq!((reads() - before, held(&c, "t-dir-fresh")), (4, vec!["TEAM-1".to_string()]), "removed: gone");
}

/// Risk: two folders overwrite each other's records (the same id in both),
/// or a source taken out of the sources file keeps matching. Oracle: both
/// sources hold their own row for the shared id; a source no longer
/// declared loses its rows, its fingerprint and its counts, and one only
/// turned off (declared, not in use) keeps them.
#[test]
fn two_sources_stay_apart_and_a_removed_source_takes_its_records() {
    let (d, c) = cache();
    let (one, two) = (d.path().join("one"), d.path().join("two"));
    put(&one, "x.json", rec("SHARED-1", "npm", "a", "1.0.1").to_string());
    put(&two, "x.json", rec("SHARED-1", "npm", "a", "2.0.1").to_string());
    put(&two, "y.json", rec("TWO-1", "npm", "b", "1.0.1").to_string());
    let (a, b) = (dir_source("t-dir-one", &one, ""), dir_source("t-dir-two", &two, ""));
    let both = [a.clone(), b.clone()];
    assert!(load(&c, &both, &both).unwrap().is_empty());
    assert_eq!(held(&c, "t-dir-one"), ["SHARED-1"]);
    assert_eq!(held(&c, "t-dir-two"), ["SHARED-1", "TWO-1"]);
    // Turned off for this run: declared, not loaded, records kept.
    assert!(load(&c, std::slice::from_ref(&a), &both).unwrap().is_empty());
    assert_eq!(held(&c, "t-dir-two"), ["SHARED-1", "TWO-1"]);
    // Taken out of the sources file.
    assert!(load(&c, std::slice::from_ref(&a), std::slice::from_ref(&a)).unwrap().is_empty());
    assert!(held(&c, "t-dir-two").is_empty());
    assert_eq!(counts(&c, "t-dir-two").unwrap(), None);
    assert!(c.get("user:t-dir-two_fp").unwrap().is_none());
    let names: i64 =
        c.conn.query_row("SELECT COUNT(*) FROM local_vuln_names WHERE source = 't-dir-two'", [], |r| r.get(0)).unwrap();
    assert_eq!(names, 0);
    assert_eq!(held(&c, "t-dir-one"), ["SHARED-1"]);
}

/// Risk: a local record is matched differently from a remote one: a fixed
/// version flagged, a vulnerable one missed, an ecosystem's own version
/// order ignored. Oracle: `osv::lookup`, offline with nothing from OSV,
/// returns the record for the vulnerable version and not for the fixed one
/// in npm (semver), PyPI (PEP 440: `1.0rc1` is before `1.0`) and Debian
/// (dpkg: `1:1.0` is after `9.9`), each marked with its source and the item
/// still reported unanswered by OSV.
#[test]
fn a_local_record_flags_a_vulnerable_version_and_not_a_fixed_one() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    let semver = json!({"id": "TEAM-NPM", "affected": [{"package": {"ecosystem": "npm", "name": "acme-widget"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}]}]});
    put(&dir, "npm/TEAM-NPM.json", semver.to_string());
    put(&dir, "PyPI/TEAM-PY.json", rec("TEAM-PY", "PyPI", "acme-tool", "1.0").to_string());
    put(&dir, "Debian/TEAM-DEB.json", rec("TEAM-DEB", "Debian:12", "acme-daemon", "1:1.0").to_string());
    let s = dir_source("t-dir-match", &dir, "");
    assert!(run(&c, &s).is_empty());
    set_test_in_use(Some(&["t-dir-match"]));
    let items = [
        item("npm", "acme-widget", "1.2.3"),
        item("npm", "acme-widget", "1.2.4"),
        item("PyPI", "acme-tool", "1.0rc1"),
        item("PyPI", "acme-tool", "1.0"),
        item("Debian:12", "acme-daemon", "9.9"),
        item("Debian:12", "acme-daemon", "1:1.0"),
    ];
    let got = osv::lookup(&c, &Fake::offline(), &items, false, true, &|_| {}, &|_| {}).unwrap();
    set_test_in_use(None);
    let ids = |it: &Item| -> Vec<String> {
        got.found.get(it).map(|r| r.iter().map(|r| str_at(r, "id").to_string()).collect()).unwrap_or_default()
    };
    assert_eq!(ids(&items[0]), ["TEAM-NPM"]);
    assert!(ids(&items[1]).is_empty(), "the fixed version");
    assert_eq!(ids(&items[2]), ["TEAM-PY"]);
    assert!(ids(&items[3]).is_empty());
    assert_eq!(ids(&items[4]), ["TEAM-DEB"]);
    assert!(ids(&items[5]).is_empty());
    assert_eq!(got.found[&items[0]][0][SOURCE_KEY], "t-dir-match");
    assert!(got.unanswered.contains(&items[0]), "OSV itself never answered it");
    assert!(!got.found.contains_key(&items[1]), "nothing local and nothing from OSV: still unanswered");
}

/// Risk: a local record's fix isn't the one suggested, or a remote record
/// and a local one for the same advisory are two findings; a withdrawn
/// local record still counts. Oracle: the scan's finding (through the same
/// `Scan::advisories` remote records use) has the record's fixed version,
/// its range, the note naming the source and the record's own link; a
/// remote record aliasing the local id is one finding with it; a withdrawn
/// record gives none.
#[test]
fn a_local_record_makes_the_same_finding_a_remote_one_does() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    let mut local = rec("TEAM-2026-0001", "npm", "acme-internal-widget", "1.2.4");
    local["references"] = json!([{"type": "PACKAGE", "url": "https://registry.example/acme"},
                                 {"type": "ADVISORY", "url": "https://advisories.example/TEAM-2026-0001"}]);
    put(&dir, "a.json", local.to_string());
    let mut gone = rec("TEAM-2026-0002", "npm", "acme-internal-widget", "9.0.0");
    gone["withdrawn"] = json!("2026-11-02T00:00:00Z");
    put(&dir, "b.json", gone.to_string());
    let s = dir_source("t-dir-finding", &dir, "");
    assert!(run(&c, &s).is_empty());
    set_test_in_use(Some(&["t-dir-finding"]));
    let it = item("npm", "acme-internal-widget", "1.2.3");
    let got = osv::lookup(&c, &Fake::offline(), std::slice::from_ref(&it), false, true, &|_| {}, &|_| {}).unwrap();
    set_test_in_use(None);
    let recs = osv::records_for(&got.found, [&it]);
    assert_eq!(recs.len(), 1, "the withdrawn record isn't used: {recs:?}");
    let net = Fake::offline();
    let mut scan =
        crate::checks::Scan::new(crate::checks::Options::default(), cache_in_new(&d), &net, &|_| {}, &|_| {});
    let mut comp = crate::component::Component::new("project", "acme-internal-widget", "1.2.3", "/w/package-lock.json");
    comp.osv = Some(it.clone());
    scan.advisories(&comp, &[], None, "fail", Some(osv::group_by_alias(&recs)));
    assert_eq!(scan.findings.len(), 1);
    let f = &scan.findings[0];
    assert_eq!(
        (f.vuln_id.as_str(), f.fixed.as_str(), f.affected_range.as_str()),
        ("TEAM-2026-0001", "1.2.4", "<1.2.4")
    );
    assert_eq!(
        f.note,
        "TEAM-2026-0001 summary (from your source t-dir-finding: https://advisories.example/TEAM-2026-0001)"
    );
    assert!(!f.note.contains("osv.dev"));
    // The same advisory from OSV, naming the local id as an alias: one finding.
    let remote = json!({"id": "GHSA-acme-0001", "aliases": ["TEAM-2026-0001"], "summary": "remote summary",
        "affected": [{"package": {"ecosystem": "npm", "name": "acme-internal-widget"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}]}]});
    let both = vec![remote, recs[0].clone()];
    scan.findings.clear();
    scan.advisories(&comp, &[], None, "fail", Some(osv::group_by_alias(&both)));
    assert_eq!(scan.findings.len(), 1, "{:?}", scan.findings);
    assert_eq!(scan.findings[0].vuln_id, "GHSA-acme-0001");
    assert_eq!(scan.findings[0].note, "remote summary (also in your source t-dir-finding)");
}

/// A second cache in `d`, for a scan beside the one a test loads into.
fn cache_in_new(d: &TempDir) -> Cache {
    Cache::open(Some(&d.path().join("scan.db"))).unwrap()
}

/// Risk: a remote record and a local one with the same id are shown twice,
/// or OSV's record loses to a copy on disk. Oracle: `osv::lookup` returns
/// one record for the id, OSV's, and the item counts as answered by OSV.
#[test]
fn a_local_record_with_the_id_of_a_cached_remote_one_is_the_same_advisory() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    put(&dir, "a.json", rec("GHSA-same", "npm", "lib", "2.0.0").to_string());
    let s = dir_source("t-dir-same", &dir, "");
    assert!(run(&c, &s).is_empty());
    let mut remote = rec("GHSA-same", "npm", "lib", "2.0.0");
    remote["summary"] = json!("from OSV");
    remote[SOURCE_KEY] = json!("forged");
    c.put_vuln(&remote).unwrap();
    c.put_query("npm", "lib", "1.0.0", &["GHSA-same".into()]).unwrap();
    set_test_in_use(Some(&["t-dir-same"]));
    let it = item("npm", "lib", "1.0.0");
    let got = osv::lookup(&c, &Fake::offline(), std::slice::from_ref(&it), false, true, &|_| {}, &|_| {}).unwrap();
    set_test_in_use(None);
    assert_eq!(got.found[&it].len(), 1);
    assert_eq!(got.found[&it][0]["summary"], "from OSV");
    assert!(got.found[&it][0].get(SOURCE_KEY).is_none(), "a remote record never claims a local source");
    assert!(!got.unanswered.contains(&it));
}

/// Risk: a record only a service could judge (a range of git commits) is
/// taken as affecting every version, or dropped without a word. Oracle:
/// it isn't returned, and the answer's gaps name the source and the id, as
/// the remote path hands such a version back to OSV's query API instead of
/// judging it.
#[test]
fn a_record_that_cant_be_judged_here_is_a_gap_not_a_finding() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    let git = json!({"id": "TEAM-GIT", "affected": [{"package": {"ecosystem": "npm", "name": "lib"},
        "ranges": [{"type": "GIT", "repo": "https://git.example/lib", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}]}]});
    put(&dir, "git.json", git.to_string());
    let s = dir_source("t-dir-git", &dir, "");
    assert!(run(&c, &s).is_empty());
    set_test_in_use(Some(&["t-dir-git"]));
    let it = item("npm", "lib", "1.0.0");
    let got = osv::lookup(&c, &Fake::offline(), std::slice::from_ref(&it), false, true, &|_| {}, &|_| {}).unwrap();
    set_test_in_use(None);
    assert!(!got.found.contains_key(&it));
    assert!(got.gaps.iter().any(|g| g.contains("t-dir-git") && g.contains("TEAM-GIT")), "{:?}", got.gaps);
}

/// Risk: a source not in use (off, or deep on a default scan) still
/// matches. Oracle: with no osv-dir source in use, the loaded record isn't
/// returned.
#[test]
fn a_source_not_in_use_doesnt_match() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    put(&dir, "a.json", rec("TEAM-OFF", "npm", "lib", "2.0.0").to_string());
    let s = dir_source("t-dir-off", &dir, "tier = \"off\"");
    assert!(run(&c, &s).is_empty());
    let it = item("npm", "lib", "1.0.0");
    let on = matching(&c, [&it], &["t-dir-off".to_string()]).unwrap();
    assert_eq!(on.found[&it].len(), 1);
    assert!(matching(&c, [&it], &[]).unwrap().found.is_empty());
}

/// Risk: a record's link is OSV.dev's though the record never names it, or
/// a link that isn't https (or isn't one line) reaches a report. Oracle:
/// [`link`] is the first ADVISORY or WEB reference when it is https, else
/// none.
#[test]
fn a_local_records_link_is_its_own_https_reference_or_none() {
    let with = |refs: Value| link(&json!({"id": "X", "references": refs}));
    assert_eq!(
        with(json!([{"type": "PACKAGE", "url": "https://p.example"}, {"type": "WEB", "url": "https://w.example/x"}])),
        Some("https://w.example/x".into())
    );
    assert_eq!(
        with(json!([{"type": "ADVISORY", "url": "http://a.example/x"}, {"type": "WEB", "url": "https://w"}])),
        None
    );
    assert_eq!(with(json!([{"type": "ADVISORY", "url": "https://a.example/x y"}])), None);
    assert_eq!(with(json!([{"type": "REPORT", "url": "https://r.example"}])), None);
    assert_eq!(with(json!("nonsense")), None);
    assert_eq!(link(&json!({"id": "X"})), None);
}

/// Risk: a path that is a file, or a folder that is gone, wipes the last
/// good load or panics. Oracle: the reason is kept, the records stay, and
/// with no good load the source is reported.
#[test]
fn a_missing_folder_or_a_file_keeps_the_last_good_load() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    put(&dir, "a.json", rec("TEAM-1", "npm", "a", "1.0.1").to_string());
    let s = dir_source("t-dir-gone", &dir, "");
    assert!(run(&c, &s).is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(run(&c, &s).is_empty(), "a last good load is in use");
    assert_eq!(held(&c, "t-dir-gone"), ["TEAM-1"]);
    assert!(fetch::last_error(&s.id).unwrap().contains("advisories"), "{:?}", fetch::last_error(&s.id));
    let file = d.path().join("one.json");
    put(d.path(), "one.json", rec("TEAM-2", "npm", "a", "1.0.1").to_string());
    let f = dir_source("t-dir-file", &file, "");
    let failed = run(&c, &f);
    assert_eq!(failed.len(), 1);
    assert!(failed[0].1.contains("not a folder"), "{failed:?}");
}

/// Every meta key a source's load leaves behind.
fn keys_of(c: &Cache, id: &str) -> Vec<String> {
    let mut stmt = c.conn.prepare("SELECT key FROM meta WHERE key LIKE ? ORDER BY key").unwrap();
    stmt.query_map([format!("user:{id}_%")], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap()
}

/// Risk: a source whose load succeeded with no valid records keeps its
/// fingerprint and counts after it is taken out of the sources file,
/// because removal only finds sources that hold a record. Oracle: after
/// removal no meta key and no row for the id is left, read straight from
/// the store; the other source's keys stay.
#[test]
fn removing_a_source_that_loaded_no_records_leaves_no_metadata() {
    let (d, c) = cache();
    let (empty, full) = (d.path().join("empty"), d.path().join("full"));
    put(&empty, "junk.json", "{\"not\": \"an advisory\"}");
    put(&full, "a.json", rec("FULL-1", "npm", "a", "1.0.1").to_string());
    let (e, f) = (dir_source("t-dir-empty", &empty, ""), dir_source("t-dir-full", &full, ""));
    let both = [e.clone(), f.clone()];
    assert!(load(&c, &both, &both).unwrap().is_empty());
    assert_eq!(counts(&c, "t-dir-empty").unwrap(), Some((0, 1)));
    assert!(held(&c, "t-dir-empty").is_empty());
    assert!(!keys_of(&c, "t-dir-empty").is_empty(), "a load with no records still writes keys");
    assert!(load(&c, std::slice::from_ref(&f), std::slice::from_ref(&f)).unwrap().is_empty());
    assert_eq!(keys_of(&c, "t-dir-empty"), Vec::<String>::new());
    assert!(c.get("user:t-dir-empty_fp").unwrap().is_none());
    assert!(c.get("user:t-dir-empty_osv").unwrap().is_none());
    assert!(!keys_of(&c, "t-dir-full").is_empty());
}

/// Risk: the same id added again with its folder gone is treated as having
/// a last good copy (a stale fingerprint), so the user is not told it
/// could not be checked. Oracle: after removing an empty source and adding
/// the id back with a missing folder, the load reports the id as failed
/// with a reason, and records the error.
#[test]
fn an_empty_source_removed_and_added_again_with_its_folder_gone_is_reported() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    put(&dir, "junk.json", "[]");
    let s = dir_source("t-dir-readd-empty", &dir, "");
    assert!(run(&c, &s).is_empty());
    assert!(load(&c, &[], &[]).unwrap().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
    let failed = run(&c, &s);
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0].0, "t-dir-readd-empty");
    assert!(fetch::last_error(&s.id).is_some());
}

/// Risk: the fix breaks the ordinary case. Oracle: a source with records,
/// removed and added again with its folder gone, is reported and holds no
/// records, where before the removal it was kept as the last good load.
#[test]
fn a_source_with_records_removed_and_added_again_with_its_folder_gone_is_reported() {
    let (d, c) = cache();
    let dir = d.path().join("advisories");
    put(&dir, "a.json", rec("TEAM-1", "npm", "a", "1.0.1").to_string());
    let s = dir_source("t-dir-readd-full", &dir, "");
    assert!(run(&c, &s).is_empty());
    assert_eq!(held(&c, "t-dir-readd-full"), ["TEAM-1"]);
    assert!(load(&c, &[], &[]).unwrap().is_empty());
    assert!(held(&c, "t-dir-readd-full").is_empty());
    assert!(keys_of(&c, "t-dir-readd-full").is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
    let failed = run(&c, &s);
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert!(held(&c, "t-dir-readd-full").is_empty());
}

/// Risk: a database an earlier build wrote (metadata for an empty load, no
/// records) is never cleaned. Oracle: with those keys written directly and
/// the source not configured, a load deletes them, and a rules folder's
/// fingerprint key for another id is untouched.
#[test]
fn stale_metadata_with_no_records_is_cleaned_when_the_source_is_not_configured() {
    let (_d, c) = cache();
    c.set("user:t-dir-stale_fp", "abc 0").unwrap();
    c.set("user:t-dir-stale_osv", "0 0").unwrap();
    c.set("user:t-rules-other_fp", "def 0").unwrap();
    assert!(load(&c, &[], &[]).unwrap().is_empty());
    assert!(keys_of(&c, "t-dir-stale").is_empty());
    assert_eq!(c.get("user:t-rules-other_fp").unwrap().as_deref(), Some("def 0"));
}

/// A record for the `acme-widget` npm package (every version from 0, to
/// `fixed` when it has one) with `severity` as OSV's database label
/// ("" for none), as a download from OSV would be.
fn upstream(id: &str, severity: &str, fixed: Option<&str>) -> Value {
    let mut events = vec![json!({"introduced": "0"})];
    events.extend(fixed.map(|f| json!({"fixed": f})));
    let mut r = json!({"id": id, "summary": format!("{id} upstream"),
        "affected": [{"package": {"ecosystem": "npm", "name": "acme-widget"},
                      "ranges": [{"type": "SEMVER", "events": events}]}]});
    if !severity.is_empty() {
        r["database_specific"] = json!({"severity": severity});
    }
    r
}

/// The same record as `osv_dir::matching` returns it: marked with its source.
fn mine(mut r: Value) -> Value {
    r[SOURCE_KEY] = json!("t-src");
    r
}

fn aliased(mut r: Value, aliases: &[&str]) -> Value {
    r["aliases"] = json!(aliases);
    r
}

/// The findings (and the unfixed count) `Scan::advisories` makes of `recs`
/// for `acme-widget` 1.0.0, grouped as every check groups them.
fn advise(d: &TempDir, recs: &[Value]) -> (Vec<crate::finding::Finding>, i64) {
    let net = Fake::offline();
    let mut scan = crate::checks::Scan::new(crate::checks::Options::default(), cache_in_new(d), &net, &|_| {}, &|_| {});
    let mut comp = crate::component::Component::new("project", "acme-widget", "1.0.0", "/w/package-lock.json");
    comp.osv = Some(item("npm", "acme-widget", "1.0.0"));
    scan.advisories(&comp, &[], None, "fail", Some(osv::group_by_alias(recs)));
    (scan.findings, scan.unfixed)
}

/// Risk: a record from the user's folder that names an upstream advisory as
/// an alias becomes the group's main record, so its empty severity fails the
/// high-impact test and an unfixed upstream Critical drops to the unfixed
/// count with no finding. Oracle: `Scan::advisories` (what every check
/// calls): the finding is still there, with the upstream id, severity and
/// status; the local record only adds its note.
#[test]
fn a_local_alias_cannot_lower_an_upstream_critical() {
    let d = TempDir::new("osv-dir-peer").unwrap();
    let up = upstream("GHSA-aaaa-bbbb-cccc", "CRITICAL", None);
    let local = mine(aliased(upstream("TEAM-1", "", None), &["GHSA-aaaa-bbbb-cccc", "CVE-2026-1111"]));
    let (findings, unfixed) = advise(&d, &[up, local]);
    assert_eq!(unfixed, 1);
    assert_eq!(findings.len(), 1, "an unfixed upstream Critical stays a finding: {findings:?}");
    let f = &findings[0];
    assert_eq!(
        (f.vuln_id.as_str(), f.severity.as_str(), f.status.as_str()),
        ("GHSA-aaaa-bbbb-cccc", "CRITICAL", "warn")
    );
    assert!(f.note.ends_with("(also in your source t-src)"), "{}", f.note);
}

/// Risk: a local record's `fixed` event wins the group's fix, so an
/// upstream advisory with no fix is treated as repaired by a version nobody
/// released. Oracle: the finding has no fix (the unfixed path, a warning),
/// and no `fixed` version; nor does the local fix hide it when upstream does
/// name one that is newer than the installed version.
#[test]
fn a_local_fixed_event_never_marks_an_upstream_advisory_fixed() {
    let d = TempDir::new("osv-dir-fix").unwrap();
    let up = upstream("GHSA-aaaa-bbbb-cccc", "CRITICAL", None);
    let local = mine(aliased(upstream("TEAM-1", "", Some("999.0.0")), &["GHSA-aaaa-bbbb-cccc"]));
    let (findings, unfixed) = advise(&d, &[up, local.clone()]);
    assert_eq!((findings.len(), unfixed), (1, 1), "{findings:?}");
    assert_eq!((findings[0].fixed.as_str(), findings[0].status.as_str()), ("", "warn"));
    // Upstream's own fix is the one suggested, not the local record's.
    let up = upstream("GHSA-aaaa-bbbb-cccc", "HIGH", Some("1.2.0"));
    let (findings, _) = advise(&d, &[up, local]);
    assert_eq!(findings.len(), 1);
    assert_eq!((findings[0].fixed.as_str(), findings[0].status.as_str()), ("1.2.0", "fail"), "{findings:?}");
}

/// Risk: a local record claims an upstream advisory is malicious (or is a
/// stand-in that reads as one). Oracle: no MALICIOUS finding for a group
/// that has an upstream record that isn't; a group of only local records is
/// judged as ever (a local MAL- record is malicious).
#[test]
fn a_local_record_cannot_make_an_upstream_advisory_malicious() {
    let d = TempDir::new("osv-dir-mal").unwrap();
    let up = upstream("GHSA-aaaa-bbbb-cccc", "HIGH", Some("1.2.0"));
    let local = mine(aliased(upstream("MAL-2026-1", "", None), &["GHSA-aaaa-bbbb-cccc"]));
    let (findings, _) = advise(&d, &[up, local.clone()]);
    assert_eq!(findings.len(), 1);
    assert_eq!((findings[0].severity.as_str(), findings[0].vuln_id.as_str()), ("HIGH", "GHSA-aaaa-bbbb-cccc"));
    let (alone, _) = advise(&d, &[local]);
    assert_eq!(alone.len(), 1);
    assert_eq!(alone[0].severity, "MALICIOUS", "a local-only group behaves as before");
}

/// Oracle: a group of only local records behaves as it always did, and a
/// local record may still add a finding for a package upstream says nothing
/// of (adding is allowed): its own id, severity and fix are used.
#[test]
fn local_only_groups_are_judged_by_their_own_records() {
    let d = TempDir::new("osv-dir-only").unwrap();
    let fixed = mine(upstream("TEAM-2", "HIGH", Some("2.0.0")));
    let (findings, _) = advise(&d, &[fixed]);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(
        (f.vuln_id.as_str(), f.severity.as_str(), f.fixed.as_str(), f.status.as_str()),
        ("TEAM-2", "HIGH", "2.0.0", "fail")
    );
    assert!(f.note.contains("(from your source t-src"), "{}", f.note);
    let open = mine(upstream("TEAM-3", "CRITICAL", None));
    let (findings, unfixed) = advise(&d, &[open]);
    assert_eq!((findings.len(), unfixed), (1, 1));
    assert_eq!((findings[0].vuln_id.as_str(), findings[0].status.as_str()), ("TEAM-3", "warn"));
}

/// Risk: a local record that names two unrelated upstream advisories as
/// aliases joins them into one group, and one of the two findings is
/// deduplicated away (an upstream finding hidden). Oracle: the groups and
/// the findings: two upstream advisories stay two, the local record is shown
/// beside the first it names, and a local record naming only another local
/// one follows it.
#[test]
fn a_local_record_cannot_join_two_upstream_advisories_into_one() {
    let d = TempDir::new("osv-dir-bridge").unwrap();
    let a = upstream("GHSA-aaaa-aaaa-aaaa", "CRITICAL", Some("1.5.0"));
    let b = upstream("GHSA-bbbb-bbbb-bbbb", "HIGH", Some("1.6.0"));
    let bridge = mine(aliased(upstream("TEAM-1", "", None), &["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"]));
    let follower = mine(aliased(upstream("TEAM-2", "", None), &["TEAM-1"]));
    let recs = [follower.clone(), a.clone(), b.clone(), bridge.clone()];
    let ids = |g: &Vec<Value>| g.iter().map(|r| str_at(r, "id").to_string()).collect::<Vec<_>>();
    let groups = osv::group_by_alias(&recs);
    assert_eq!(
        groups.iter().map(ids).collect::<Vec<_>>(),
        [vec!["TEAM-2", "GHSA-aaaa-aaaa-aaaa", "TEAM-1"], vec!["GHSA-bbbb-bbbb-bbbb"]]
    );
    let (findings, _) = advise(&d, &[a, b, bridge]);
    let mut got: Vec<&str> = findings.iter().map(|f| f.vuln_id.as_str()).collect();
    got.sort();
    assert_eq!(got, ["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"], "both upstream findings stay");
}

/// The query plan SQLite gives `sql` with two bound parameters, as text.
fn plan(c: &Cache, sql: &str) -> String {
    let mut stmt = c.conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    let rows: Vec<String> =
        stmt.query_map(["s", "i"], |r| r.get::<_, String>(3)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    rows.join(" | ")
}

/// Risk: the delete that runs once per record scans `local_vuln_names`,
/// whose only index is on `name`, so a load is quadratic (measured by the
/// reviewer: 5k records 1.5 s, 40k 82 s). Oracle: the plan SQLite gives the
/// statement the load runs names the `(source, id)` index and does not scan
/// the table; the plan is deterministic where a timing is not. The same
/// index serves the join in `matching` and the delete in `forget`.
#[test]
fn the_per_record_delete_uses_the_source_and_id_index() {
    let (_d, c) = cache();
    let p = plan(&c, DELETE_NAMES);
    assert!(p.contains("local_vuln_names_source_id"), "the (source, id) index is used: {p}");
    assert!(!p.contains("SCAN"), "and the table is not scanned: {p}");
    let join = plan(
        &c,
        "SELECT DISTINCT v.source, v.id, v.record FROM local_vuln_names n \
         JOIN local_vulns v ON v.source = n.source AND v.id = n.id WHERE n.name = ? AND ? IS NOT NULL",
    );
    assert!(join.contains("local_vuln_names_name"), "a lookup by name keeps its own index: {join}");
}

/// Risk: a cache an earlier release made (the table and the name index, no
/// `(source, id)` index) is left slow, because only a new database gets the
/// index. Oracle: opening that file with the current build adds the index
/// (the schema statements are `IF NOT EXISTS`, run on every open), keeps the
/// rows, and the delete's plan then names it.
#[test]
fn a_cache_from_an_earlier_release_gains_the_index_and_keeps_its_rows() {
    let d = TempDir::new("osv-dir-upgrade").unwrap();
    let file = d.path().join("old.db");
    {
        let old = rusqlite::Connection::open(&file).unwrap();
        old.execute_batch(
            "CREATE TABLE local_vulns (source TEXT, id TEXT, file TEXT, aliases TEXT, url TEXT, record TEXT,
               PRIMARY KEY (source, id));
             CREATE TABLE local_vuln_names (source TEXT, id TEXT, name TEXT);
             CREATE INDEX local_vuln_names_name ON local_vuln_names (name);
             INSERT INTO local_vuln_names VALUES ('t-old', 'TEAM-1', 'acme-widget');",
        )
        .unwrap();
        let before: i64 = old
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = 'local_vuln_names_source_id'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(before, 0, "the fixture is the old shape");
    }
    let c = Cache::open(Some(&file)).unwrap();
    let after: i64 = c
        .conn
        .query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = 'local_vuln_names_source_id'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(after, 1, "the index is added to an existing database");
    let kept: String = c
        .conn
        .query_row("SELECT name FROM local_vuln_names WHERE source = 't-old' AND id = 'TEAM-1'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(kept, "acme-widget");
    assert!(plan(&c, DELETE_NAMES).contains("local_vuln_names_source_id"));
}

/// Risk: a report finds the record's source and link by reading `note`,
/// which starts with an advisory's free text, so an upstream summary that
/// imitates the marker re-points a link. Oracle: the finding's own fields
/// (`local_source`, `local_link`) and its JSON and cache row: set from a
/// local record's own https link or none; empty for an upstream finding
/// whatever its summary says and for one a local record is only listed
/// beside; the fields survive the cache the report reads.
#[test]
fn a_local_finding_carries_its_source_and_https_link_as_fields() {
    let d = TempDir::new("osv-dir-fields").unwrap();
    let mut local = mine(upstream("TEAM-9", "HIGH", Some("2.0.0")));
    local["references"] = json!([{"type": "ADVISORY", "url": "https://advisories.example.com/TEAM-9"}]);
    let (found, _) = advise(&d, std::slice::from_ref(&local));
    let f = &found[0];
    assert_eq!((f.local_source.as_str(), f.local_link.as_str()), ("t-src", "https://advisories.example.com/TEAM-9"));
    let json: Value = serde_json::from_str(&f.to_json().dumps()).unwrap();
    assert_eq!(
        (&json["local_source"], &json["local_link"]),
        (&json!("t-src"), &json!("https://advisories.example.com/TEAM-9"))
    );
    // A link that is not https is no link; the source is still named.
    local["references"] = json!([{"type": "ADVISORY", "url": "http://insecure.example/TEAM-9"}]);
    let (found, _) = advise(&d, std::slice::from_ref(&local));
    assert_eq!((found[0].local_source.as_str(), found[0].local_link.as_str()), ("t-src", ""));
    // An upstream finding whose summary imitates the marker has no fields.
    let mut up = upstream("GHSA-aaaa-bbbb-cccc", "HIGH", Some("1.2.0"));
    up["summary"] = json!("bad (from your source x: https://evil.example/a)");
    let (upstream_only, _) = advise(&d, &[up.clone()]);
    assert_eq!((upstream_only[0].local_source.as_str(), upstream_only[0].local_link.as_str()), ("", ""));
    // And one with a local record in its group: the finding is upstream's.
    let beside = mine(aliased(upstream("TEAM-10", "", None), &["GHSA-aaaa-bbbb-cccc"]));
    let (grouped, _) = advise(&d, &[up, beside]);
    assert_eq!((grouped[0].local_source.as_str(), grouped[0].local_link.as_str()), ("", ""));
    assert!(grouped[0].note.ends_with("(also in your source t-src)"), "{}", grouped[0].note);
    // The cache a report reads keeps them.
    let c = cache_in_new(&d);
    c.replace_findings(&found).unwrap();
    let back = crate::reporters::jsonl::findings(&c).unwrap();
    assert_eq!((back[0].local_source.as_str(), back[0].local_link.as_str()), ("t-src", ""));
}
