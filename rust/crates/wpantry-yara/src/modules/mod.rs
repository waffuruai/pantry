//! Modules: structured data about a file that conditions can read (`pe`,
//! `elf`) and functions over its bytes (`math`, `hash`).
//!
//! A module declares its shape once ([`Module::schema`]) and fills it per
//! file ([`Module::parse`]), lazily: a file is parsed as a PE only when a rule
//! that got that far asks for `pe`. Anything outside this crate (pantry's
//! `wallet`, `card` and `decode`) plugs in through the same trait with
//! [`crate::Compiler::add_module`].

use crate::value::{StructType, Value};
use std::sync::Arc;

pub mod elf;
pub mod hash;
pub mod math;
pub mod pe;

pub trait Module: Send + Sync {
    /// The name rules import it by.
    fn name(&self) -> &'static str;
    /// Its fields, constants and functions.
    fn schema(&self) -> Arc<StructType>;
    /// Its data for one file: a structure of `schema`'s shape.
    fn parse(&self, data: &[u8]) -> Value;
}

/// The modules every compiler starts with.
pub fn builtin() -> Vec<Arc<dyn Module>> {
    vec![Arc::new(math::Math::new()), Arc::new(hash::Hash::new()), Arc::new(pe::Pe::new()), Arc::new(elf::Elf::new())]
}

/// The file offset execution starts at (`entrypoint`): a PE's or an ELF's.
pub fn entry_point(data: &[u8]) -> Value {
    pe::entry_offset(data).or_else(|| elf::entry_offset(data)).map_or(Value::Undef, |o| Value::Int(o as i64))
}

/// `data[offset..offset + size]`, when both are in range: the window most
/// module functions take.
pub fn window<'d>(data: &'d [u8], offset: &Value, size: &Value) -> Option<&'d [u8]> {
    let (o, s) = (offset.as_int()?, size.as_int()?);
    let (o, s) = (usize::try_from(o).ok()?, usize::try_from(s).ok()?);
    data.get(o..o.checked_add(s)?)
}

/// Little-endian readers that never panic.
pub fn u16le(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

pub fn u32le(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

pub fn u64le(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

pub fn u16be(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(d.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

pub fn u32be(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

pub fn u64be(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(d.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

/// A NUL-terminated string at `at`, at most `max` bytes.
pub fn cstr(d: &[u8], at: usize, max: usize) -> Option<&[u8]> {
    let rest = d.get(at..)?;
    let rest = &rest[..rest.len().min(max)];
    Some(&rest[..rest.iter().position(|b| *b == 0).unwrap_or(rest.len())])
}

/// Lowercase hex of some bytes.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_stay_in_bounds() {
        let d = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(u16le(&d, 0), Some(0x0201));
        assert_eq!(u32be(&d, 0), Some(0x01020304));
        assert_eq!(u64le(&d, 0), Some(0x0807060504030201));
        assert_eq!(u64be(&d, 0), Some(0x0102030405060708));
        assert_eq!(u16be(&d, 6), Some(0x0708));
        assert_eq!(u32le(&d, 6), None);
        assert_eq!(u16le(&d, usize::MAX), None);
        assert_eq!(cstr(b"ab\0cd", 0, 10), Some(&b"ab"[..]));
        assert_eq!(cstr(b"abcd", 1, 2), Some(&b"bc"[..]));
        assert_eq!(cstr(b"ab", 5, 2), None);
        assert_eq!(hex(&[0, 255]), "00ff");
        assert_eq!(window(b"abcd", &Value::Int(1), &Value::Int(2)), Some(&b"bc"[..]));
        assert_eq!(window(b"abcd", &Value::Int(3), &Value::Int(2)), None);
        assert_eq!(window(b"abcd", &Value::Int(-1), &Value::Int(2)), None);
        assert_eq!(window(b"abcd", &Value::Undef, &Value::Int(2)), None);
        assert!(entry_point(b"plain text").is_undef());
        assert_eq!(builtin().iter().map(|m| m.name()).collect::<Vec<_>>(), ["math", "hash", "pe", "elf"]);
    }
}
