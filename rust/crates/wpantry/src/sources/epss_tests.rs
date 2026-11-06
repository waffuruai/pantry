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
    let (date, rows) = parse(&csv(3)).unwrap();
    assert_eq!(date, "2026-11-05T12:03:04Z");
    assert_eq!(rows.len(), 4, "a score outside 0..1 and a malformed line are skipped");
    assert!(parse("cve,score\nCVE-1,0.1\n").is_none(), "not EPSS's header");
    let (_d, c) = cache();
    let good = crate::utils::archive::gzip::tests::stored(csv(MIN_ROWS).as_bytes(), None);
    let net = Fake::new(move |_| Ok(Response::ok(good.clone())));
    assert_eq!(refresh(&c, &net, false).unwrap(), MIN_ROWS + 1);
    assert_eq!(lookup(&c, "CVE-2024-3094").unwrap(), Some((0.85, 0.99)));
    assert_eq!(lookup(&c, "CVE-1900-1").unwrap(), None);
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
