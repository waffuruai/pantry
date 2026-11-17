//! A PE's resource tree (type, name, language) and its version information.

use crate::modules::{u16le, u32le};
use crate::value::{StructType, Value, array};
use std::sync::Arc;

/// `RT_VERSION`
const RT_VERSION: u32 = 16;
/// YARA's caps: resources listed, and depth of the tree walked.
const MAX_RESOURCES: usize = 65_536;
const MAX_DEPTH: usize = 3;

pub fn resource_type() -> StructType {
    StructType::new()
        .int("rva")
        .int("offset")
        .int("length")
        .int("type")
        .int("id")
        .int("language")
        .string("type_string")
        .string("name_string")
        .string("language_string")
}

/// One resource: its data entry and the three directory levels above it.
pub struct Resource {
    pub rva: u32,
    pub offset: Option<usize>,
    pub length: u32,
    /// For each level, a numeric id or a name (UTF-16LE as stored).
    pub path: [Result<u32, Vec<u8>>; 3],
}

pub struct Tree {
    pub resources: Vec<Resource>,
    pub timestamp: u32,
    pub major: u16,
    pub minor: u16,
}

/// Walk the resource directory at file offset `base`.
pub fn walk(data: &[u8], base: usize, rva_to_offset: &dyn Fn(u32) -> Option<usize>) -> Option<Tree> {
    let timestamp = u32le(data, base + 4)?;
    let (major, minor) = (u16le(data, base + 8)?, u16le(data, base + 10)?);
    let mut resources = Vec::new();
    let mut path: Vec<Result<u32, Vec<u8>>> = Vec::new();
    dir(data, base, base, 0, &mut path, &mut resources, rva_to_offset);
    Some(Tree { resources, timestamp, major, minor })
}

#[allow(clippy::too_many_arguments)]
fn dir(
    data: &[u8],
    base: usize,
    at: usize,
    depth: usize,
    path: &mut Vec<Result<u32, Vec<u8>>>,
    out: &mut Vec<Resource>,
    rva_to_offset: &dyn Fn(u32) -> Option<usize>,
) {
    let (Some(named), Some(ids)) = (u16le(data, at + 12), u16le(data, at + 14)) else { return };
    for i in 0..(named as usize + ids as usize) {
        if out.len() >= MAX_RESOURCES {
            return;
        }
        let entry = at + 16 + 8 * i;
        let (Some(name), Some(target)) = (u32le(data, entry), u32le(data, entry + 4)) else { return };
        let id = if name & 0x8000_0000 != 0 {
            // A counted UTF-16LE name, relative to the resource section.
            let off = base + (name & 0x7FFF_FFFF) as usize;
            let len = u16le(data, off).unwrap_or(0) as usize;
            Err(data.get(off + 2..off + 2 + 2 * len).unwrap_or_default().to_vec())
        } else {
            Ok(name)
        };
        path.push(id);
        let child = base + (target & 0x7FFF_FFFF) as usize;
        if target & 0x8000_0000 != 0 {
            if depth + 1 < MAX_DEPTH && child != at {
                dir(data, base, child, depth + 1, path, out, rva_to_offset);
            }
        } else if path.len() == 3
            && let (Some(rva), Some(length)) = (u32le(data, child), u32le(data, child + 4))
        {
            let p = |i: usize| path[i].clone();
            out.push(Resource { rva, offset: rva_to_offset(rva), length, path: [p(0), p(1), p(2)] });
        }
        path.pop();
    }
}

pub fn values(tree: &Tree, ty: &Arc<StructType>) -> Vec<Value> {
    tree.resources
        .iter()
        .map(|r| {
            let mut v = ty.value();
            v.int("rva", r.rva).int("length", r.length);
            if let Some(o) = r.offset {
                v.int("offset", o as i64);
            }
            for (i, (num, text)) in [("type", "type_string"), ("id", "name_string"), ("language", "language_string")]
                .into_iter()
                .enumerate()
            {
                match &r.path[i] {
                    Ok(n) => v.int(num, *n),
                    Err(s) => v.string(text, s),
                };
            }
            v.build()
        })
        .collect()
}

/// Version information: the `StringFileInfo` key/value pairs, in order.
pub fn version_info(data: &[u8], tree: &Tree) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for r in tree.resources.iter().filter(|r| r.path[0] == Ok(RT_VERSION)) {
        let Some(block) = r.offset.and_then(|o| data.get(o..o + r.length as usize)) else { continue };
        let Some((key, children)) = vs_block(block, 0) else { continue };
        if key != b"VS_VERSION_INFO" {
            continue;
        }
        for (k, sfi) in children_of(block, children) {
            if k != b"StringFileInfo" {
                continue;
            }
            let Some((_, tables)) = vs_block(block, sfi) else { continue };
            for (_, table) in children_of(block, tables) {
                let Some((_, strings)) = vs_block(block, table) else { continue };
                for (_, s) in children_of(block, strings) {
                    if let Some(pair) = string_pair(block, s) {
                        out.push(pair);
                    }
                }
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

/// A version block at `at`: its key (narrowed to bytes) and where its
/// children start (after the key and value, 4-byte aligned), up to its end.
fn vs_block(d: &[u8], at: usize) -> Option<(Vec<u8>, (usize, usize))> {
    let len = u16le(d, at)? as usize;
    let value_len = u16le(d, at + 2)? as usize;
    let kind = u16le(d, at + 4)?;
    let (key, after_key) = wide_cstr(d, at + 6)?;
    let value_start = align4(after_key);
    let value_bytes = if kind == 1 { value_len * 2 } else { value_len };
    let children = align4(value_start + value_bytes);
    let end = (at + len).min(d.len());
    Some((key, (children.min(end), end)))
}

/// The blocks between `start` and `end`, each with its key.
fn children_of(d: &[u8], (start, end): (usize, usize)) -> Vec<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut at = start;
    while at + 6 < end && out.len() < 1024 {
        let Some(len) = u16le(d, at).map(usize::from) else { break };
        if len == 0 {
            break;
        }
        if let Some((key, _)) = vs_block(d, at) {
            out.push((key, at));
        }
        at = align4(at + len);
    }
    out
}

/// A `String` block: key and value, both narrowed from UTF-16 by dropping
/// the high byte, as YARA does.
fn string_pair(d: &[u8], at: usize) -> Option<(Vec<u8>, Vec<u8>)> {
    let (key, after_key) = wide_cstr(d, at + 6)?;
    let (value, _) = wide_cstr(d, align4(after_key)).unwrap_or_default();
    Some((key, value))
}

/// A NUL-terminated UTF-16LE string at `at`, narrowed; and the offset after it.
fn wide_cstr(d: &[u8], at: usize) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut i = at;
    loop {
        let c = u16le(d, i)?;
        i += 2;
        if c == 0 {
            return Some((out, i));
        }
        out.push(c as u8);
        if out.len() > 1024 {
            return None;
        }
    }
}

fn align4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

/// `version_info` as a dictionary and `version_info_list` as an array.
pub fn version_values(pairs: &[(Vec<u8>, Vec<u8>)], kv: &Arc<StructType>) -> (Value, Value) {
    let dict = pairs.iter().map(|(k, v)| (Arc::from(k.as_slice()), Value::str(v))).collect();
    let list = pairs
        .iter()
        .map(|(k, v)| {
            let mut b = kv.value();
            b.string("key", k).string("value", v);
            b.build()
        })
        .collect();
    (Value::Dict(Arc::new(dict)), array(list))
}

#[cfg(test)]
#[path = "resources_tests.rs"]
pub mod tests;
