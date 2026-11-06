//! YARA's `dotnet` module, the part rules use most: whether a PE is a .NET
//! assembly, its runtime version and its metadata streams. The metadata
//! tables (`assembly`, `resources`, …) aren't read yet; rules naming them are
//! rejected with "unknown field" rather than silently never matching.

use super::{Module, cstr, u16le, u32le};
use crate::value::{StructType, Type, Value, array};
use std::sync::{Arc, OnceLock};

/// The COM descriptor (CLI header) data directory.
const DIR_COM_DESCRIPTOR: usize = 14;
/// `BSJB`, the metadata root's signature.
const METADATA_MAGIC: u32 = 0x424A_5342;
const MAX_STREAMS: usize = 32;

struct Types {
    module: Arc<StructType>,
    stream: Arc<StructType>,
}

fn types() -> &'static Types {
    static T: OnceLock<Types> = OnceLock::new();
    T.get_or_init(|| {
        let stream = Arc::new(StructType::new().string("name").int("offset").int("size"));
        let module = Arc::new(
            StructType::new()
                .int("is_dotnet")
                .string("version")
                .int("number_of_streams")
                .array("streams", Type::Struct(stream.clone())),
        );
        Types { module, stream }
    })
}

pub struct Dotnet;

impl Dotnet {
    pub fn new() -> Self {
        Dotnet
    }
}

impl Default for Dotnet {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Dotnet {
    fn name(&self) -> &'static str {
        "dotnet"
    }

    fn schema(&self) -> Arc<StructType> {
        types().module.clone()
    }

    fn parse(&self, data: &[u8]) -> Value {
        let t = types();
        let mut v = t.module.value();
        match metadata(data) {
            Some(root) => {
                v.int("is_dotnet", 1);
                if let Some((version, streams)) = read_root(data, root) {
                    v.string("version", version);
                    let list: Vec<Value> = streams
                        .into_iter()
                        .map(|(name, offset, size)| {
                            let mut s = t.stream.value();
                            s.string("name", name).int("offset", offset as i64).int("size", size);
                            s.build()
                        })
                        .collect();
                    v.int("number_of_streams", list.len() as i64).set("streams", array(list));
                }
            }
            None => {
                v.int("is_dotnet", 0);
            }
        }
        v.build()
    }
}

/// The file offset of the metadata root, through the CLI header.
fn metadata(d: &[u8]) -> Option<usize> {
    if d.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32le(d, 0x3C)? as usize;
    if d.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let opt = pe + 24;
    let dirs = if u16le(d, opt)? == 0x20b { opt + 112 } else { opt + 96 };
    if (u32le(d, dirs - 4)? as usize) <= DIR_COM_DESCRIPTOR {
        return None;
    }
    let cli_rva = u32le(d, dirs + 8 * DIR_COM_DESCRIPTOR)?;
    let cli = rva_to_offset(d, pe, cli_rva)?;
    let meta = rva_to_offset(d, pe, u32le(d, cli + 8)?)?;
    (u32le(d, meta)? == METADATA_MAGIC).then_some(meta)
}

/// A plain RVA-to-offset through the section table (no alignment rounding:
/// .NET compilers align sections).
fn rva_to_offset(d: &[u8], pe: usize, rva: u32) -> Option<usize> {
    let sections = pe + 24 + u16le(d, pe + 20)? as usize;
    for i in 0..u16le(d, pe + 6)?.min(96) as usize {
        let at = sections + 40 * i;
        let (vsize, va, raw_size, raw) =
            (u32le(d, at + 8)?, u32le(d, at + 12)?, u32le(d, at + 16)?, u32le(d, at + 20)?);
        if rva >= va && rva < va.saturating_add(vsize.max(raw_size)) {
            let off = raw as usize + (rva - va) as usize;
            return (off < d.len()).then_some(off);
        }
    }
    None
}

/// The runtime version string and the `(name, offset, size)` of each stream.
#[allow(clippy::type_complexity)]
fn read_root(d: &[u8], root: usize) -> Option<(Vec<u8>, Vec<(Vec<u8>, usize, u32)>)> {
    let len = u32le(d, root + 12)? as usize;
    let version = cstr(d, root + 16, len.min(255))?.to_vec();
    let after = root + 16 + len;
    let count = u16le(d, after + 2)? as usize;
    let mut at = after + 4;
    let mut streams = Vec::new();
    for _ in 0..count.min(MAX_STREAMS) {
        let (offset, size) = (u32le(d, at)?, u32le(d, at + 4)?);
        let name = cstr(d, at + 8, 32)?.to_vec();
        at += 8 + (name.len() + 1).div_ceil(4) * 4;
        streams.push((name, root + offset as usize, size));
    }
    Some((version, streams))
}

#[cfg(test)]
#[path = "dotnet_tests.rs"]
mod tests;
