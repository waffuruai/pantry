use super::*;

fn t(string: u32) -> Target {
    Target { string, variant: 0, offset: 0 }
}

#[test]
fn finds_atoms_of_every_length_including_at_the_end() {
    let mut table = AtomTable::default();
    table.add(b"a", t(1));
    table.add(b"bc", t(2));
    table.add(b"def", t(3));
    table.add(b"ghij", t(4));
    assert_eq!(table.len(), 4);
    assert!(!table.is_empty());
    let mut hits = Vec::new();
    table.scan(b"xa-bc-def-ghij", |pos, t| hits.push((pos, t.string)));
    assert_eq!(hits, vec![(1, 1), (3, 2), (6, 3), (10, 4)]);
    hits.clear();
    table.scan(b"ghi", |pos, t| hits.push((pos, t.string)));
    assert!(hits.is_empty(), "a four-byte atom needs four bytes");
    table.scan(b"bc", |pos, t| hits.push((pos, t.string)));
    assert_eq!(hits, vec![(0, 2)]);
}

#[test]
fn several_targets_share_an_atom() {
    let mut table = AtomTable::default();
    table.add(b"\0\0\0\0", t(1));
    table.add(b"\0\0\0\0", t(2));
    let mut hits = 0;
    table.scan(&[0; 6], |_, _| hits += 1);
    assert_eq!(hits, 6, "three positions with four zero bytes, two targets each");
    assert!(AtomTable::default().is_empty());
}

#[test]
fn hasher_is_deterministic() {
    let mut a = FxHasher::default();
    let mut b = FxHasher::default();
    a.write(b"xy");
    b.write(b"xy");
    a.write_u16(1);
    b.write_u16(1);
    assert_eq!(a.finish(), b.finish());
}
