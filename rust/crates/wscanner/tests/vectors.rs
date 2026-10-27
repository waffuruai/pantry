//! Comparator vectors too long to keep inline (F10).

use std::cmp::Ordering;
use wscanner::compare::Comparator;

fn check(file: &str, c: Comparator) -> usize {
    let mut n = 0;
    for line in file.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let w: Vec<&str> = line.split(' ').collect();
        let [a, op, b] = w.as_slice() else { panic!("bad vector line: {line}") };
        let want = match *op {
            "<" => Ordering::Less,
            "=" => Ordering::Equal,
            ">" => Ordering::Greater,
            _ => panic!("bad op in {line}"),
        };
        assert_eq!(c.cmp(a, b), want, "{a} {op} {b}");
        n += 1;
    }
    n
}

#[test]
fn dpkg_compare_versions() {
    assert!(check(include_str!("vectors/dpkg.txt"), Comparator::Dpkg) > 600);
}

#[test]
fn packaging_versions_ascend() {
    let versions: Vec<&str> =
        include_str!("vectors/pep440.txt").lines().filter(|l| !l.starts_with('#') && !l.is_empty()).collect();
    assert!(versions.len() > 80);
    for (i, a) in versions.iter().enumerate() {
        for (j, b) in versions.iter().enumerate() {
            assert_eq!(Comparator::Pep440.cmp(a, b), i.cmp(&j), "{a} vs {b}");
        }
    }
}
