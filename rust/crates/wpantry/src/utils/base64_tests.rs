use super::*;

#[test]
fn encode_pads_and_decode_reads_it_back() {
    for (plain, coded) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foobar", "Zm9vYmFy")] {
        assert_eq!(encode(plain.as_bytes()), coded);
        assert_eq!(decode(coded).unwrap(), plain.as_bytes());
    }
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(decode(&encode(&all)).unwrap(), all);
    assert_eq!(decode("aGVs\nbG8gd29ybGQ=").unwrap(), b"hello world", "PEM's line breaks");
    assert!(decode("a*b").is_none());
}
