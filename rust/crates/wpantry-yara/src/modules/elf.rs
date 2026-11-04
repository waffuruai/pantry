//! YARA's `elf` module: the header, sections, segments, dynamic entries and
//! symbols of an ELF file, 32- or 64-bit, either byte order.

use super::{Module, cstr, u16be, u16le, u32be, u32le, u64be, u64le};
use crate::modules::hash::md5;
use crate::modules::hex;
use crate::value::{FieldKind, FnCtx, StructType, Type, Value, array};
use std::sync::{Arc, OnceLock};

/// YARA's caps on what a hostile file can make it list.
const MAX_SECTIONS: usize = 32_768;
const MAX_SEGMENTS: usize = 32_768;
const MAX_SYMBOLS: usize = 1 << 16;
const MAX_NAME: usize = 1024;

const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const SHN_UNDEF: u16 = 0;

struct Types {
    module: Arc<StructType>,
    section: Arc<StructType>,
    segment: Arc<StructType>,
    dynamic: Arc<StructType>,
    symbol: Arc<StructType>,
}

fn types() -> &'static Types {
    static T: OnceLock<Types> = OnceLock::new();
    T.get_or_init(|| {
        let section = Arc::new(
            StructType::new().int("type").int("flags").int("address").string("name").int("size").int("offset"),
        );
        let segment = Arc::new(
            StructType::new()
                .int("type")
                .int("flags")
                .int("offset")
                .int("virtual_address")
                .int("physical_address")
                .int("file_size")
                .int("memory_size")
                .int("alignment"),
        );
        let dynamic = Arc::new(StructType::new().int("type").int("val"));
        let symbol = Arc::new(
            StructType::new()
                .string("name")
                .int("value")
                .int("size")
                .int("type")
                .int("bind")
                .int("shndx")
                .int("visibility"),
        );
        let s = |t: &Arc<StructType>| Type::Struct(t.clone());
        let mut m = StructType::new();
        for f in [
            "type",
            "machine",
            "entry_point",
            "number_of_sections",
            "sh_offset",
            "sh_entry_size",
            "number_of_segments",
            "ph_offset",
            "ph_entry_size",
            "dynamic_section_entries",
            "symtab_entries",
            "dynsym_entries",
        ] {
            m = m.int(f);
        }
        m = m
            .array("sections", s(&section))
            .array("segments", s(&segment))
            .array("dynamic", s(&dynamic))
            .array("symtab", s(&symbol))
            .array("dynsym", s(&symbol));
        for (name, v) in CONSTANTS {
            m = m.constant(name, *v);
        }
        let module = Arc::new(m.func("import_md5", "", Type::Str, |c, _| symbol_md5(c, true)).func(
            "export_md5",
            "",
            Type::Str,
            |c, _| symbol_md5(c, false),
        ));
        Types { module, section, segment, dynamic, symbol }
    })
}

const CONSTANTS: &[(&str, i64)] = &[
    ("ET_NONE", 0),
    ("ET_REL", 1),
    ("ET_EXEC", 2),
    ("ET_DYN", 3),
    ("ET_CORE", 4),
    ("EM_NONE", 0),
    ("EM_M32", 1),
    ("EM_SPARC", 2),
    ("EM_386", 3),
    ("EM_68K", 4),
    ("EM_88K", 5),
    ("EM_860", 7),
    ("EM_MIPS", 8),
    ("EM_MIPS_RS3_LE", 10),
    ("EM_PPC", 20),
    ("EM_PPC64", 21),
    ("EM_ARM", 40),
    ("EM_X86_64", 62),
    ("EM_AARCH64", 183),
    ("SHT_NULL", 0),
    ("SHT_PROGBITS", 1),
    ("SHT_SYMTAB", 2),
    ("SHT_STRTAB", 3),
    ("SHT_RELA", 4),
    ("SHT_HASH", 5),
    ("SHT_DYNAMIC", 6),
    ("SHT_NOTE", 7),
    ("SHT_NOBITS", 8),
    ("SHT_REL", 9),
    ("SHT_SHLIB", 10),
    ("SHT_DYNSYM", 11),
    ("SHF_WRITE", 1),
    ("SHF_ALLOC", 2),
    ("SHF_EXECINSTR", 4),
    ("PT_NULL", 0),
    ("PT_LOAD", 1),
    ("PT_DYNAMIC", 2),
    ("PT_INTERP", 3),
    ("PT_NOTE", 4),
    ("PT_SHLIB", 5),
    ("PT_PHDR", 6),
    ("PT_TLS", 7),
    ("PT_GNU_EH_FRAME", 0x6474_e550),
    ("PT_GNU_STACK", 0x6474_e551),
    ("PT_GNU_RELRO", 0x6474_e552),
    ("PF_X", 1),
    ("PF_W", 2),
    ("PF_R", 4),
    ("DT_NULL", 0),
    ("DT_NEEDED", 1),
    ("DT_PLTRELSZ", 2),
    ("DT_PLTGOT", 3),
    ("DT_HASH", 4),
    ("DT_STRTAB", 5),
    ("DT_SYMTAB", 6),
    ("DT_RELA", 7),
    ("DT_RELASZ", 8),
    ("DT_RELAENT", 9),
    ("DT_STRSZ", 10),
    ("DT_SYMENT", 11),
    ("DT_INIT", 12),
    ("DT_FINI", 13),
    ("DT_SONAME", 14),
    ("DT_RPATH", 15),
    ("DT_SYMBOLIC", 16),
    ("DT_REL", 17),
    ("DT_RELSZ", 18),
    ("DT_RELENT", 19),
    ("DT_PLTREL", 20),
    ("DT_DEBUG", 21),
    ("DT_TEXTREL", 22),
    ("DT_JMPREL", 23),
    ("DT_BIND_NOW", 24),
    ("DT_INIT_ARRAY", 25),
    ("DT_FINI_ARRAY", 26),
    ("DT_INIT_ARRAYSZ", 27),
    ("DT_FINI_ARRAYSZ", 28),
    ("DT_RUNPATH", 29),
    ("DT_FLAGS", 30),
    ("DT_ENCODING", 32),
    ("STT_NOTYPE", 0),
    ("STT_OBJECT", 1),
    ("STT_FUNC", 2),
    ("STT_SECTION", 3),
    ("STT_FILE", 4),
    ("STT_COMMON", 5),
    ("STT_TLS", 6),
    ("STB_LOCAL", 0),
    ("STB_GLOBAL", 1),
    ("STB_WEAK", 2),
    ("STV_DEFAULT", 0),
    ("STV_INTERNAL", 1),
    ("STV_HIDDEN", 2),
    ("STV_PROTECTED", 3),
];

pub struct Elf;

impl Elf {
    pub fn new() -> Self {
        Elf
    }
}

impl Default for Elf {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Elf {
    fn name(&self) -> &'static str {
        "elf"
    }

    fn schema(&self) -> Arc<StructType> {
        types().module.clone()
    }

    fn parse(&self, data: &[u8]) -> Value {
        let t = types();
        let mut v = t.module.value();
        if let Some(r) = Reader::new(data) {
            r.fill(t, &mut v);
        }
        v.build()
    }
}

/// Reads fields in the file's byte order and word size.
struct Reader<'d> {
    d: &'d [u8],
    big: bool,
    wide: bool,
}

struct Section {
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    name: u32,
    link: u32,
    entsize: u64,
}

struct Segment {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

impl<'d> Reader<'d> {
    fn new(d: &'d [u8]) -> Option<Self> {
        if d.get(..4)? != b"\x7fELF" {
            return None;
        }
        let wide = match d.get(4)? {
            1 => false,
            2 => true,
            _ => return None,
        };
        let big = match d.get(5)? {
            1 => false,
            2 => true,
            _ => return None,
        };
        Some(Reader { d, big, wide })
    }

    fn u16(&self, at: usize) -> Option<u16> {
        if self.big { u16be(self.d, at) } else { u16le(self.d, at) }
    }

    fn u32(&self, at: usize) -> Option<u32> {
        if self.big { u32be(self.d, at) } else { u32le(self.d, at) }
    }

    fn u64(&self, at: usize) -> Option<u64> {
        if self.big { u64be(self.d, at) } else { u64le(self.d, at) }
    }

    /// A word: 4 bytes in a 32-bit file, 8 in a 64-bit one.
    fn word(&self, at: usize) -> Option<u64> {
        if self.wide { self.u64(at) } else { self.u32(at).map(u64::from) }
    }

    /// The header fields that differ in position between the two classes.
    fn header(&self) -> Option<(u64, u64, u64, u16, u16, u16, u16)> {
        let (entry, phoff, shoff, rest) = if self.wide { (24, 32, 40, 52) } else { (24, 28, 32, 40) };
        Some((
            self.word(entry)?,
            self.word(phoff)?,
            self.word(shoff)?,
            self.u16(rest + 2)?,
            self.u16(rest + 4)?,
            self.u16(rest + 6)?,
            self.u16(rest + 8)?,
        ))
    }

    fn sections(&self, shoff: u64, entsize: u16, count: u16) -> Vec<Section> {
        let mut out = Vec::new();
        for i in 0..(count as usize).min(MAX_SECTIONS) {
            let at = shoff as usize + i * entsize as usize;
            let s = if self.wide {
                (|| {
                    Some(Section {
                        name: self.u32(at)?,
                        kind: self.u32(at + 4)?,
                        flags: self.u64(at + 8)?,
                        addr: self.u64(at + 16)?,
                        offset: self.u64(at + 24)?,
                        size: self.u64(at + 32)?,
                        link: self.u32(at + 40)?,
                        entsize: self.u64(at + 56)?,
                    })
                })()
            } else {
                (|| {
                    Some(Section {
                        name: self.u32(at)?,
                        kind: self.u32(at + 4)?,
                        flags: u64::from(self.u32(at + 8)?),
                        addr: u64::from(self.u32(at + 12)?),
                        offset: u64::from(self.u32(at + 16)?),
                        size: u64::from(self.u32(at + 20)?),
                        link: self.u32(at + 24)?,
                        entsize: u64::from(self.u32(at + 36)?),
                    })
                })()
            };
            match s {
                Some(s) => out.push(s),
                None => break,
            }
        }
        out
    }

    fn segments(&self, phoff: u64, entsize: u16, count: u16) -> Vec<Segment> {
        let mut out = Vec::new();
        for i in 0..(count as usize).min(MAX_SEGMENTS) {
            let at = phoff as usize + i * entsize as usize;
            let s = if self.wide {
                (|| {
                    Some(Segment {
                        kind: self.u32(at)?,
                        flags: self.u32(at + 4)?,
                        offset: self.u64(at + 8)?,
                        vaddr: self.u64(at + 16)?,
                        paddr: self.u64(at + 24)?,
                        filesz: self.u64(at + 32)?,
                        memsz: self.u64(at + 40)?,
                        align: self.u64(at + 48)?,
                    })
                })()
            } else {
                (|| {
                    Some(Segment {
                        kind: self.u32(at)?,
                        offset: u64::from(self.u32(at + 4)?),
                        vaddr: u64::from(self.u32(at + 8)?),
                        paddr: u64::from(self.u32(at + 12)?),
                        filesz: u64::from(self.u32(at + 16)?),
                        memsz: u64::from(self.u32(at + 20)?),
                        flags: self.u32(at + 24)?,
                        align: u64::from(self.u32(at + 28)?),
                    })
                })()
            };
            match s {
                Some(s) => out.push(s),
                None => break,
            }
        }
        out
    }

    fn fill(&self, t: &Types, v: &mut crate::value::StructBuilder) {
        let (Some(kind), Some(machine)) = (self.u16(16), self.u16(18)) else { return };
        v.int("type", kind).int("machine", machine);
        let Some((entry, phoff, shoff, phentsize, phnum, shentsize, shnum)) = self.header() else { return };
        let shstrndx = self.u16(if self.wide { 62 } else { 50 }).unwrap_or(0) as usize;
        v.int("sh_offset", shoff as i64).int("sh_entry_size", shentsize).int("number_of_sections", shnum);
        v.int("ph_offset", phoff as i64).int("ph_entry_size", phentsize).int("number_of_segments", phnum);
        let sections = if shoff != 0 { self.sections(shoff, shentsize, shnum) } else { Vec::new() };
        let segments = if phoff != 0 { self.segments(phoff, phentsize, phnum) } else { Vec::new() };
        if let Some(o) = entry_file_offset(entry, kind, &segments, &sections) {
            v.int("entry_point", o as i64);
        }
        let names = sections.get(shstrndx).map(|s| s.offset as usize);
        let list = sections
            .iter()
            .map(|s| {
                let mut b = t.section.value();
                b.int("type", s.kind)
                    .int("flags", s.flags as i64)
                    .int("address", s.addr as i64)
                    .int("size", s.size as i64)
                    .int("offset", s.offset as i64);
                if let Some(n) = names.and_then(|base| cstr(self.d, base + s.name as usize, MAX_NAME)) {
                    b.string("name", n);
                }
                b.build()
            })
            .collect();
        v.set("sections", array(list));
        let list = segments
            .iter()
            .map(|s| {
                let mut b = t.segment.value();
                b.int("type", s.kind)
                    .int("flags", s.flags)
                    .int("offset", s.offset as i64)
                    .int("virtual_address", s.vaddr as i64)
                    .int("physical_address", s.paddr as i64)
                    .int("file_size", s.filesz as i64)
                    .int("memory_size", s.memsz as i64)
                    .int("alignment", s.align as i64);
                b.build()
            })
            .collect();
        v.set("segments", array(list));
        let dynamic = self.dynamic(&segments);
        v.int("dynamic_section_entries", dynamic.len() as i64).set(
            "dynamic",
            array(
                dynamic
                    .iter()
                    .map(|(tag, val)| {
                        let mut b = t.dynamic.value();
                        b.int("type", *tag as i64).int("val", *val as i64);
                        b.build()
                    })
                    .collect(),
            ),
        );
        for (kind, list, count) in [(SHT_SYMTAB, "symtab", "symtab_entries"), (SHT_DYNSYM, "dynsym", "dynsym_entries")]
        {
            if let Some(s) = sections.iter().find(|s| s.kind == kind) {
                let syms = self.symbols(s, &sections, t);
                v.int(count, syms.len() as i64).set(list, array(syms));
            }
        }
    }

    /// `(tag, value)` pairs of the PT_DYNAMIC segment, up to DT_NULL.
    fn dynamic(&self, segments: &[Segment]) -> Vec<(u64, u64)> {
        let Some(seg) = segments.iter().find(|s| s.kind == PT_DYNAMIC) else { return Vec::new() };
        let size = if self.wide { 16 } else { 8 };
        let mut out = Vec::new();
        for i in 0..(seg.filesz as usize / size).min(MAX_SYMBOLS) {
            let at = seg.offset as usize + i * size;
            let (Some(tag), Some(val)) = (self.word(at), self.word(at + size / 2)) else { break };
            out.push((tag, val));
            if tag == 0 {
                break;
            }
        }
        out
    }

    fn symbols(&self, s: &Section, sections: &[Section], t: &Types) -> Vec<Value> {
        let entsize = if s.entsize > 0 {
            s.entsize as usize
        } else if self.wide {
            24
        } else {
            16
        };
        let strtab = sections.get(s.link as usize).map(|st| st.offset as usize);
        let mut out = Vec::new();
        for i in 0..(s.size as usize / entsize).min(MAX_SYMBOLS) {
            let at = s.offset as usize + i * entsize;
            let parsed = if self.wide {
                (|| {
                    Some((
                        self.u32(at)?,
                        *self.d.get(at + 4)?,
                        *self.d.get(at + 5)?,
                        self.u16(at + 6)?,
                        self.u64(at + 8)?,
                        self.u64(at + 16)?,
                    ))
                })()
            } else {
                (|| {
                    Some((
                        self.u32(at)?,
                        *self.d.get(at + 12)?,
                        *self.d.get(at + 13)?,
                        self.u16(at + 14)?,
                        u64::from(self.u32(at + 4)?),
                        u64::from(self.u32(at + 8)?),
                    ))
                })()
            };
            let Some((name, info, other, shndx, value, size)) = parsed else { break };
            let mut b = t.symbol.value();
            b.int("value", value as i64)
                .int("size", size as i64)
                .int("type", info & 0xF)
                .int("bind", info >> 4)
                .int("shndx", shndx)
                .int("visibility", other & 0x3);
            if let Some(n) = strtab.and_then(|base| cstr(self.d, base + name as usize, MAX_NAME)) {
                b.string("name", n);
            }
            out.push(b.build());
        }
        out
    }
}

/// The file offset of a virtual address: through the load segment that maps
/// it, or (in an object file) the section that holds it.
fn entry_file_offset(entry: u64, kind: u16, segments: &[Segment], sections: &[Section]) -> Option<u64> {
    const ET_REL: u16 = 1;
    if kind != ET_REL
        && let Some(s) = segments.iter().find(|s| s.kind == PT_LOAD && s.vaddr <= entry && entry < s.vaddr + s.memsz)
    {
        return Some(s.offset + (entry - s.vaddr));
    }
    sections
        .iter()
        .find(|s| s.addr <= entry && entry < s.addr + s.size && s.kind != 8)
        .map(|s| s.offset + (entry - s.addr))
}

/// The file offset of an ELF's entry point, for `entrypoint`.
pub fn entry_offset(data: &[u8]) -> Option<u64> {
    let r = Reader::new(data)?;
    let kind = r.u16(16)?;
    let (entry, phoff, shoff, phentsize, phnum, shentsize, shnum) = r.header()?;
    let segments = if phoff != 0 { r.segments(phoff, phentsize, phnum) } else { Vec::new() };
    let sections = if shoff != 0 { r.sections(shoff, shentsize, shnum) } else { Vec::new() };
    entry_file_offset(entry, kind, &segments, &sections)
}

/// MD5 of the sorted, lowercased, comma-joined names of the dynamic symbols
/// that are imported (undefined) or exported (defined, global or weak).
fn symbol_md5(c: &FnCtx, imports: bool) -> Value {
    let t = types();
    let Some(FieldKind::Value { slot, .. }) = t.module.lookup("dynsym") else { return Value::Undef };
    let Value::Array(syms) = c.this.field(*slot) else { return Value::Undef };
    let get = |s: &Value, name: &str| match t.symbol.lookup(name) {
        Some(FieldKind::Value { slot, .. }) => s.field(*slot),
        _ => Value::Undef,
    };
    let mut names: Vec<Vec<u8>> = syms
        .iter()
        .filter(|s| {
            let undefined = get(s, "shndx").as_int() == Some(i64::from(SHN_UNDEF));
            let global = matches!(get(s, "bind").as_int(), Some(1 | 2));
            let func_or_object = matches!(get(s, "type").as_int(), Some(1 | 2));
            if imports { undefined && func_or_object } else { !undefined && global && func_or_object }
        })
        .filter_map(|s| get(s, "name").as_bytes().map(<[u8]>::to_ascii_lowercase))
        .filter(|n| !n.is_empty())
        .collect();
    if names.is_empty() {
        return Value::Undef;
    }
    names.sort();
    names.dedup();
    Value::str(hex(&md5(&names.join(&b","[..]))))
}

#[cfg(test)]
mod tests {
    use crate::{Compiler, ScanOptions, Syntax};

    /// A 64-bit little-endian executable: one load segment, a dynamic
    /// segment, `.text`, `.dynsym`, `.dynstr` and `.shstrtab`.
    pub fn sample_elf() -> Vec<u8> {
        let mut f = vec![0u8; 0x400];
        let put = |f: &mut Vec<u8>, at: usize, b: &[u8]| f[at..at + b.len()].copy_from_slice(b);
        put(&mut f, 0, b"\x7fELF\x02\x01\x01");
        put(&mut f, 16, &2u16.to_le_bytes());
        put(&mut f, 18, &62u16.to_le_bytes());
        put(&mut f, 24, &0x400100u64.to_le_bytes());
        put(&mut f, 32, &64u64.to_le_bytes());
        put(&mut f, 40, &0x200u64.to_le_bytes());
        put(&mut f, 54, &56u16.to_le_bytes());
        put(&mut f, 56, &2u16.to_le_bytes());
        put(&mut f, 58, &64u16.to_le_bytes());
        put(&mut f, 60, &5u16.to_le_bytes());
        put(&mut f, 62, &4u16.to_le_bytes());
        // PT_LOAD: file 0 = vaddr 0x400000, 0x400 bytes, R-X.
        let ph = |f: &mut Vec<u8>, at: usize, kind: u32, flags: u32, off: u64, vaddr: u64, size: u64| {
            put(f, at, &kind.to_le_bytes());
            put(f, at + 4, &flags.to_le_bytes());
            put(f, at + 8, &off.to_le_bytes());
            put(f, at + 16, &vaddr.to_le_bytes());
            put(f, at + 32, &size.to_le_bytes());
            put(f, at + 40, &size.to_le_bytes());
        };
        ph(&mut f, 64, 1, 5, 0, 0x400000, 0x400);
        ph(&mut f, 120, 2, 6, 0x1C0, 0x4001C0, 32);
        // Dynamic: DT_NEEDED 1, DT_NULL.
        put(&mut f, 0x1C0, &1u64.to_le_bytes());
        put(&mut f, 0x1C8, &1u64.to_le_bytes());
        // Sections: null, .text, .dynsym, .dynstr, .shstrtab.
        let sh = |f: &mut Vec<u8>,
                  i: usize,
                  name: u32,
                  kind: u32,
                  flags: u64,
                  addr: u64,
                  off: u64,
                  size: u64,
                  link: u32,
                  entsize: u64| {
            let at = 0x200 + 64 * i;
            put(f, at, &name.to_le_bytes());
            put(f, at + 4, &kind.to_le_bytes());
            put(f, at + 8, &flags.to_le_bytes());
            put(f, at + 16, &addr.to_le_bytes());
            put(f, at + 24, &off.to_le_bytes());
            put(f, at + 32, &size.to_le_bytes());
            put(f, at + 40, &link.to_le_bytes());
            put(f, at + 56, &entsize.to_le_bytes());
        };
        sh(&mut f, 1, 1, 1, 6, 0x400100, 0x100, 0x40, 0, 0);
        sh(&mut f, 2, 7, 11, 2, 0, 0x140, 72, 3, 24);
        sh(&mut f, 3, 15, 3, 0, 0, 0x1A0, 0x20, 0, 0);
        sh(&mut f, 4, 23, 3, 0, 0, 0x180, 0x20, 0, 0);
        put(&mut f, 0x180, b"\0.text\0.dynsym\0.dynstr\0.shstrtab\0");
        put(&mut f, 0x1A0, b"\0puts\0Evil\0");
        // Symbols: null, puts (undefined func, global), Evil (defined func, global).
        let sym = |f: &mut Vec<u8>, i: usize, name: u32, info: u8, shndx: u16| {
            let at = 0x140 + 24 * i;
            put(f, at, &name.to_le_bytes());
            f[at + 4] = info;
            put(f, at + 6, &shndx.to_le_bytes());
        };
        sym(&mut f, 1, 1, 0x12, 0);
        sym(&mut f, 2, 6, 0x12, 1);
        f
    }

    fn holds(cond: &str, data: &[u8]) -> bool {
        let mut c = Compiler::new();
        assert_eq!(
            c.add_source("t", &format!("import \"elf\" rule r {{ condition: {cond} }}"), Syntax::Relaxed),
            1,
            "{cond}"
        );
        !c.build().scan(data, &ScanOptions::default()).matches.is_empty()
    }

    #[test]
    fn reads_an_executable() {
        let d = sample_elf();
        for cond in [
            "elf.type == elf.ET_EXEC and elf.machine == elf.EM_X86_64 and elf.entry_point == 0x100 and entrypoint == 0x100",
            "elf.number_of_sections == 5 and elf.sections[1].name == \".text\" and elf.sections[1].flags & elf.SHF_EXECINSTR",
            "elf.number_of_segments == 2 and elf.segments[0].type == elf.PT_LOAD and elf.segments[0].flags & elf.PF_X",
            "elf.dynamic_section_entries == 2 and elf.dynamic[0].type == elf.DT_NEEDED",
            "elf.dynsym_entries == 3 and elf.dynsym[1].name == \"puts\" and elf.dynsym[2].bind == elf.STB_GLOBAL",
            "for any s in elf.sections : (s.name == \".dynstr\")",
            "not defined elf.symtab_entries",
        ] {
            assert!(holds(cond, &d), "{cond}");
        }
        let imports = crate::modules::hex(&crate::modules::hash::md5(b"puts"));
        let exports = crate::modules::hex(&crate::modules::hash::md5(b"evil"));
        assert!(holds(&format!("elf.import_md5() == \"{imports}\" and elf.export_md5() == \"{exports}\""), &d));
    }

    #[test]
    fn big_endian_32_bit_header() {
        let mut f = vec![0u8; 64];
        f[..7].copy_from_slice(b"\x7fELF\x01\x02\x01");
        f[16..18].copy_from_slice(&1u16.to_be_bytes());
        f[18..20].copy_from_slice(&8u16.to_be_bytes());
        assert!(holds("elf.type == elf.ET_REL and elf.machine == elf.EM_MIPS and elf.number_of_sections == 0", &f));
        assert!(holds("not defined elf.entry_point and not defined elf.import_md5()", &f));
    }

    #[test]
    fn not_an_elf() {
        for d in [&b"\x7fELF\x03\x01"[..], b"\x7fELF\x01\x03", b"MZ", b""] {
            assert!(holds("not defined elf.type", d));
        }
    }
}
