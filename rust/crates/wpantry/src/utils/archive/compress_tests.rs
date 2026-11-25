use super::*;
use crate::utils::archive::deflate::inflate;

fn round_trip(data: &[u8]) -> Vec<u8> {
    let packed = deflate(data);
    assert_eq!(inflate(&packed, data.len() + 1).as_deref(), Some(data), "{} bytes", data.len());
    packed
}

/// What the inflater reads back is what went in: empty, short, the longest
/// match, the farthest distance, past the window, and bytes that never
/// repeat.
#[test]
fn deflate_round_trips_through_inflate() {
    round_trip(b"");
    round_trip(b"a");
    round_trip(b"ab");
    round_trip(b"abcabcabcabc xyz");
    round_trip(&[0u8; 1000]);
    let mut far = vec![b'x'; 10];
    far.extend((0..WINDOW - 10).map(|i| (i * 7 % 251) as u8));
    far.extend_from_within(..300);
    round_trip(&far);
    // A small LCG: bytes with no structure, and so no matches worth having.
    let mut x = 1u32;
    let noise: Vec<u8> = (0..70_000)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect();
    round_trip(&noise);
    let mut both = noise[..WINDOW + 5].to_vec();
    both.extend_from_slice(&noise[..WINDOW + 5]);
    round_trip(&both);
    // The only earlier copy a byte past the window: literals, never a
    // distance DEFLATE can't write.
    let mut beyond = noise[..300].to_vec();
    beyond.resize(WINDOW + 1, 0);
    beyond.extend_from_slice(&noise[..300]);
    round_trip(&beyond);
}

/// Repeats cost next to nothing: a row repeated a thousand times is a few
/// bytes per repeat. Fails if matches are never found (all literals) or
/// only within the row.
#[test]
fn deflate_finds_repeats() {
    let row = br#"{"kind": "project", "component": "vite", "vuln_id": "GHSA-8g5g-mxqh-grgj", "status": "fail"}, "#;
    let text = row.repeat(1000);
    let packed = round_trip(&text);
    assert!(packed.len() < text.len() / 50, "{} of {} bytes", packed.len(), text.len());
}
