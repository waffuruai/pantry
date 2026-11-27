use super::*;
use crate::sources::testing::cache;
use crate::utils::net::{Fake, Response};

fn csv(rows: usize) -> String {
    let mut t = String::from("#model_version:v2026.06.15,score_date:2026-11-05T12:03:04Z\ncve,epss,percentile\n");
    for i in 0..rows {
        t.push_str(&format!("CVE-2026-{i},0.{:05},0.{:05}\n", i % 100_000, (i * 7) % 100_000));
    }
    t.push_str("CVE-2024-3094,0.85,0.99\nnot,a,row\nCVE-1999-1,2.0,0.5\n");
    t
}

#[test]
fn the_daily_file_is_read_and_a_bad_copy_keeps_the_last() {
    let copy = parse(&csv(3)).unwrap();
    assert_eq!((copy.date.as_str(), copy.model.as_str()), ("2026-11-05T12:03:04Z", "v2026.06.15"));
    assert_eq!(copy.rows.len(), 4, "a score outside 0..1 and a malformed line are skipped");
    assert!(parse("cve,score\nCVE-1,0.1\n").is_none(), "not EPSS's header");
    let (_d, c) = cache();
    let good = crate::utils::archive::gzip::tests::stored(csv(MIN_ROWS).as_bytes(), None);
    let net = Fake::new(move |_| Ok(Response::ok(good.clone())));
    assert_eq!(refresh(&c, &net, false).unwrap(), MIN_ROWS + 1);
    assert_eq!(lookup(&c, "CVE-2024-3094").unwrap(), Some((0.85, 0.99)));
    assert_eq!(lookup(&c, "CVE-1900-1").unwrap(), None);
    assert_eq!(edition(&c).unwrap(), ("2026-11-05T12:03:04Z".to_string(), "v2026.06.15".to_string()));
    // A later copy that is short or isn't EPSS is refused; the scores stay.
    c.unset("epss_at").unwrap();
    let short = Fake::new(|_| Ok(Response::ok(csv(5))));
    assert_eq!(refresh(&c, &short, false).unwrap(), MIN_ROWS + 1);
    c.unset("epss_at").unwrap();
    let html = Fake::new(|_| Ok(Response::ok("<html>maintenance</html>")));
    assert_eq!(refresh(&c, &html, false).unwrap(), MIN_ROWS + 1);
    let (_e, empty) = cache();
    assert!(refresh(&empty, &Fake::offline(), false).is_err(), "nothing kept and nothing reached");
}

/// A scan's cache (autocommit between its writes) with `rows` scores loaded.
fn scan_cache_with(rows: usize) -> (crate::utils::temp::TempDir, Cache) {
    let d = crate::utils::temp::TempDir::new("epss-load").unwrap();
    let c = Cache::open_for_scan(Some(&d.path().join("w.db")), &|_| {}).unwrap();
    let body = csv(rows);
    assert_eq!(refresh(&c, &Fake::new(move |_| Ok(Response::ok(body.clone()))), false).unwrap(), rows + 1);
    (d, c)
}

/// Risk: a scan's cache is in autocommit, so the delete that starts a load and
/// each insert after it are seen by another command as they happen: a
/// `report` or `search` during the load reads an empty or half-filled table.
/// Oracle: a reader that counts the scores over and over while a load of
/// 60 000 replaces 1 001 only ever sees 1 001 or 60 001.
/// Known bad: the load outside one transaction (the counts in between show up).
#[test]
fn a_reader_during_a_load_sees_the_old_scores_or_the_new_never_part() {
    let (d, c) = scan_cache_with(MIN_ROWS);
    let file = d.path().join("w.db");
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = {
        let done = done.clone();
        std::thread::spawn(move || {
            let r = Cache::open(Some(&file)).unwrap();
            let mut seen = std::collections::BTreeSet::new();
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                let n: i64 = r.conn.query_row("SELECT COUNT(*) FROM epss", [], |r| r.get(0)).unwrap();
                seen.insert(n);
                r.commit().unwrap(); // a fresh snapshot for the next count
            }
            seen
        })
    };
    std::thread::sleep(std::time::Duration::from_millis(50));
    c.unset("epss_at").unwrap();
    let body = csv(60_000);
    assert_eq!(refresh(&c, &Fake::new(move |_| Ok(Response::ok(body.clone()))), false).unwrap(), 60_001);
    std::thread::sleep(std::time::Duration::from_millis(50));
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let seen = seen.join().unwrap();
    let part: Vec<&i64> = seen.iter().filter(|n| ![MIN_ROWS as i64 + 1, 60_001].contains(n)).collect();
    assert!(part.is_empty(), "a reader saw {} partial counts, such as {:?}", part.len(), &part[..part.len().min(5)]);
}

/// Risk: a load that fails or is killed part-way leaves the table it was
/// replacing empty or half-filled for every later command, since each write
/// committed on its own. Oracle: an insert that fails part-way (a trigger
/// stands in for the error or the kill) leaves every old score, and the
/// edition of the old copy.
/// Known bad: the delete and the inserts committed one by one.
#[test]
fn a_load_that_fails_part_way_leaves_the_old_scores() {
    let (_d, c) = scan_cache_with(MIN_ROWS);
    let before = edition(&c).unwrap();
    c.conn
        .execute_batch(
            "CREATE TRIGGER fail_part_way BEFORE INSERT ON epss WHEN NEW.cve = 'CVE-2026-1500'
             BEGIN SELECT RAISE(ABORT, 'interrupted'); END;",
        )
        .unwrap();
    c.unset("epss_at").unwrap();
    let body = csv(3000).replace("v2026.06.15", "v2026.12.01");
    assert!(refresh(&c, &Fake::new(move |_| Ok(Response::ok(body.clone()))), false).is_err());
    let n: i64 = c.conn.query_row("SELECT COUNT(*) FROM epss", [], |r| r.get(0)).unwrap();
    assert_eq!(n, MIN_ROWS as i64 + 1, "the old scores, all of them");
    assert!(lookup(&c, "CVE-2026-999").unwrap().is_some());
    assert_eq!(edition(&c).unwrap(), before);
}
