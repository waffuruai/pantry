use super::*;

/// Encode an element (for building test certificates).
pub fn enc(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match body.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(body);
    out
}

pub fn oid_bytes(dotted: &str) -> Vec<u8> {
    let parts: Vec<u64> = dotted.split('.').map(|p| p.parse().unwrap()).collect();
    let mut out = vec![(parts[0] * 40 + parts[1]) as u8];
    for p in &parts[2..] {
        let mut stack = vec![(*p & 0x7F) as u8];
        let mut v = *p >> 7;
        while v > 0 {
            stack.push((v & 0x7F) as u8 | 0x80);
            v >>= 7;
        }
        out.extend(stack.iter().rev());
    }
    out
}

#[test]
fn reads_elements_and_lengths() {
    let long = enc(OCTET_STRING, &[7; 300]);
    let mut r = Reader::new(&long);
    let e = r.next().unwrap();
    assert_eq!((e.tag, e.body.len(), e.raw.len()), (OCTET_STRING, 300, 304));
    assert!(r.next().is_none());
    assert!(Reader::new(&[0x30, 0x80]).next().is_none(), "indefinite length");
    assert!(Reader::new(&[0x30, 0x05, 1]).next().is_none(), "past the end");
    let two = [enc(INTEGER, &[1]), enc(OID, &[1])].concat();
    let mut r = Reader::new(&two);
    assert!(r.optional(OID).is_none());
    assert!(r.expect(INTEGER).is_some());
    assert!(r.optional(OID).is_some());
}

#[test]
fn oids_names_serials_and_times() {
    assert_eq!(oid(&oid_bytes("1.2.840.113549.1.1.11")), "1.2.840.113549.1.1.11");
    assert_eq!(algorithm_name("1.2.840.113549.1.1.11"), "sha256WithRSAEncryption");
    assert_eq!(algorithm_name("1.2.3"), "1.2.3");
    let attr = |o: &str, tag: u8, v: &[u8]| enc(SET, &enc(SEQUENCE, &[enc(OID, &oid_bytes(o)), enc(tag, v)].concat()));
    let n = enc(
        SEQUENCE,
        &[
            attr("2.5.4.6", 0x13, b"US"),
            attr("2.5.4.3", 0x0C, "Zoë".as_bytes()),
            attr("2.5.4.10", BMP_STRING, &[0, b'A', 0, b'B']),
        ]
        .concat(),
    );
    let e = Reader::new(&n).next().unwrap();
    assert_eq!(name(&e), "/C=US/CN=Zo\\xC3\\xAB/O=AB");
    assert_eq!(serial(&[0x00, 0x0b, 0x96]), "0b:96");
    assert_eq!(serial(&[0x00]), "00");
    let t = enc(UTC_TIME, b"110615000000Z");
    assert_eq!(time(&Reader::new(&t).next().unwrap()), Some(1_308_096_000));
    let g = enc(GENERALIZED_TIME, b"20500101000000Z");
    assert_eq!(time(&Reader::new(&g).next().unwrap()), Some(2_524_608_000));
    let bad = enc(UTC_TIME, b"111315000000Z");
    assert_eq!(time(&Reader::new(&bad).next().unwrap()), None);
    assert_eq!(time(&Reader::new(&enc(INTEGER, b"1")).next().unwrap()), None);
}
