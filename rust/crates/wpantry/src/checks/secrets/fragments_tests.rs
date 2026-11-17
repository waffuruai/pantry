use super::*;

#[test]
fn a_small_file_is_one_fragment() {
    assert_eq!(split(b"a\nb\n"), vec![Fragment { range: 0..4, start_line: 1 }]);
    assert!(split(b"").is_empty());
}

#[test]
fn a_read_extends_to_the_next_blank_line_within_the_peek_limit() {
    // 100,000 bytes of one long line, then more of it, a blank line, and the rest.
    let mut data = vec![b'a'; READ + 10];
    data.extend_from_slice(b"\n\nnext\n");
    let frags = split(&data);
    assert_eq!(frags[0].range, 0..READ + 12);
    assert_eq!(frags[1], Fragment { range: READ + 12..data.len(), start_line: 3 });
}

#[test]
fn without_a_blank_line_the_cut_falls_at_the_peek_limit_and_leftovers_start_the_next() {
    let data = vec![b'a'; READ + PEEK + 3 * BUFFER];
    let frags = split(&data);
    assert_eq!(frags[0].range, 0..READ + PEEK);
    // The buffered bytes past the cut are the next read on their own.
    let next = frags[1].range.clone();
    assert_eq!(next.start, READ + PEEK);
    assert!(next.len() <= BUFFER + PEEK);
    assert_eq!(frags.iter().map(|f| f.range.len()).sum::<usize>(), data.len());
}

#[test]
fn a_read_ending_in_a_blank_line_isnt_extended() {
    let mut data = vec![b'a'; READ - 2];
    data.extend_from_slice(b"\n\nrest");
    assert_eq!(split(&data)[0].range, 0..READ);
}

#[test]
fn binary_files_are_known_by_signature_or_a_nul() {
    assert!(binary(b"PK\x03\x04rest"));
    assert!(binary(b"%PDF-1.7"));
    assert!(binary(b"\x7fELF\x02"));
    assert!(binary(b"text\x00more"));
    assert!(!binary(b"key = \"value\"\n"));
    let mut tar = vec![b' '; 300];
    tar[257..262].copy_from_slice(b"ustar");
    assert!(binary(&tar));
}
