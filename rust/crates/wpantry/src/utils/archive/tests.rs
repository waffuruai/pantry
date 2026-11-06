use super::*;

#[test]
fn byte_helpers() {
    assert_eq!(rfind(b"abcabc", b"ab"), Some(3));
    assert_eq!(u16le(&[0x34, 0x12], 0), Some(0x1234));
    assert_eq!(u32le(&[0x78, 0x56, 0x34, 0x12], 0), Some(0x1234_5678));
    assert_eq!(u32le(&[0x78, 0x56, 0x34], 0), None, "short reads are None, not panics");
}
