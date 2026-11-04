//! Archives the in-tree readers open: zip members, inflated by [`deflate`],
//! and the little-endian and search helpers they share.

pub mod deflate;
pub mod zip;

/// A zip member is read only up to this much once inflated (a bomb guard);
/// RTF and SVG text is lowercased up to the same bound.
pub(crate) const MAX_MEMBER: usize = 16 << 20;

pub(crate) fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

pub(crate) fn u16le(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]) as usize)
}

pub(crate) fn u32le(b: &[u8], i: usize) -> Option<usize> {
    Some(u32::from_le_bytes([*b.get(i)?, *b.get(i + 1)?, *b.get(i + 2)?, *b.get(i + 3)?]) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_helpers() {
        assert_eq!(rfind(b"abcabc", b"ab"), Some(3));
        assert_eq!(u16le(&[0x34, 0x12], 0), Some(0x1234));
        assert_eq!(u32le(&[0x78, 0x56, 0x34, 0x12], 0), Some(0x1234_5678));
        assert_eq!(u32le(&[0x78, 0x56, 0x34], 0), None, "short reads are None, not panics");
    }
}
