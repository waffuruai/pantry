//! YARA's `pe` module: headers, sections, imports, exports, resources,
//! version information, the Rich header and Authenticode signatures of a
//! Windows executable, with YARA's field names and its limits.
//!
//! Every read is bounds-checked: a malformed or truncated file leaves the
//! fields it can't fill undefined, the way YARA does, and never panics.

mod der;
mod resources;
mod sign;

use super::{Module, cstr, u16le, u32le, u64le};
use crate::matcher;
use crate::modules::hash::md5;
use crate::modules::hex;
use crate::value::{FieldKind, FnCtx, StructType, Type, Value, array};
use std::sync::{Arc, OnceLock};

/// YARA's caps on what a hostile file can make it list.
const MAX_SECTIONS: usize = 96;
const MAX_IMPORTS: usize = 16_384;
const MAX_EXPORTS: usize = 16_384;
const MAX_NAME: usize = 512;
const MAX_DATA_DIRECTORIES: usize = 16;

/// Data directory indexes.
const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_RESOURCE: usize = 2;
const DIR_SECURITY: usize = 4;
const DIR_DEBUG: usize = 6;
const DIR_DELAY_IMPORT: usize = 13;

const IMPORT_STANDARD: i64 = 1;
const IMPORT_DELAYED: i64 = 2;

/// The types of the module and its nested structures, built once.
struct Types {
    module: Arc<StructType>,
    section: Arc<StructType>,
    directory: Arc<StructType>,
    function: Arc<StructType>,
    import: Arc<StructType>,
    export: Arc<StructType>,
    resource: Arc<StructType>,
    signature: Arc<StructType>,
    kv: Arc<StructType>,
    version: Arc<StructType>,
    rich: Arc<StructType>,
    overlay: Arc<StructType>,
}

fn types() -> &'static Types {
    static TYPES: OnceLock<Types> = OnceLock::new();
    TYPES.get_or_init(build_types)
}

fn build_types() -> Types {
    let section = Arc::new(
        StructType::new()
            .string("name")
            .string("full_name")
            .int("characteristics")
            .int("virtual_address")
            .int("virtual_size")
            .int("raw_data_offset")
            .int("raw_data_size")
            .int("pointer_to_relocations")
            .int("pointer_to_line_numbers")
            .int("number_of_relocations")
            .int("number_of_line_numbers"),
    );
    let directory = Arc::new(StructType::new().int("virtual_address").int("size"));
    let function = Arc::new(StructType::new().string("name").int("ordinal").int("rva"));
    let import = Arc::new(
        StructType::new()
            .string("library_name")
            .int("number_of_functions")
            .array("functions", Type::Struct(function.clone())),
    );
    let export =
        Arc::new(StructType::new().int("offset").string("name").string("forward_name").int("ordinal").int("rva"));
    let resource = Arc::new(resources::resource_type());
    let signature = Arc::new(sign::signature_type());
    let kv = Arc::new(StructType::new().string("key").string("value"));
    let version = Arc::new(StructType::new().int("major").int("minor"));
    let rich = Arc::new(
        StructType::new()
            .int("offset")
            .int("length")
            .int("key")
            .string("raw_data")
            .string("clear_data")
            .func("version", "i", Type::Int, |c, a| rich_count(c, Some(&a[0]), None))
            .func("version", "ii", Type::Int, |c, a| rich_count(c, Some(&a[0]), Some(&a[1])))
            .func("toolid", "i", Type::Int, |c, a| rich_count(c, None, Some(&a[0])))
            .func("toolid", "ii", Type::Int, |c, a| rich_count(c, Some(&a[1]), Some(&a[0]))),
    );
    let overlay = Arc::new(StructType::new().int("offset").int("size"));
    let module = Arc::new(module_type(
        &section, &directory, &import, &export, &resource, &signature, &kv, &version, &rich, &overlay,
    ));
    Types { module, section, directory, function, import, export, resource, signature, kv, version, rich, overlay }
}

#[allow(clippy::too_many_arguments)]
fn module_type(
    section: &Arc<StructType>,
    directory: &Arc<StructType>,
    import: &Arc<StructType>,
    export: &Arc<StructType>,
    resource: &Arc<StructType>,
    signature: &Arc<StructType>,
    kv: &Arc<StructType>,
    version: &Arc<StructType>,
    rich: &Arc<StructType>,
    overlay: &Arc<StructType>,
) -> StructType {
    let s = |t: &Arc<StructType>| Type::Struct(t.clone());
    let mut t = StructType::new();
    for name in [
        "is_pe",
        "machine",
        "number_of_sections",
        "timestamp",
        "pointer_to_symbol_table",
        "number_of_symbols",
        "size_of_optional_header",
        "characteristics",
        "entry_point",
        "entry_point_raw",
        "image_base",
        "number_of_rva_and_sizes",
        "number_of_version_infos",
        "opthdr_magic",
        "size_of_code",
        "size_of_initialized_data",
        "size_of_uninitialized_data",
        "base_of_code",
        "base_of_data",
        "section_alignment",
        "file_alignment",
        "win32_version_value",
        "size_of_image",
        "size_of_headers",
        "checksum",
        "subsystem",
        "dll_characteristics",
        "size_of_stack_reserve",
        "size_of_stack_commit",
        "size_of_heap_reserve",
        "size_of_heap_commit",
        "loader_flags",
        "number_of_imports",
        "number_of_imported_functions",
        "number_of_delayed_imports",
        "number_of_delayed_imported_functions",
        "export_timestamp",
        "number_of_exports",
        "number_of_resources",
        "resource_timestamp",
        "number_of_signatures",
        "is_signed",
    ] {
        t = t.int(name);
    }
    t = t
        .string("dll_name")
        .string("pdb_path")
        .dict("version_info", Type::Str)
        .array("version_info_list", s(kv))
        .field("linker_version", s(version))
        .field("os_version", s(version))
        .field("image_version", s(version))
        .field("subsystem_version", s(version))
        .field("resource_version", s(version))
        .array("data_directories", s(directory))
        .array("sections", s(section))
        .field("overlay", s(overlay))
        .field("rich_signature", s(rich))
        .array("import_details", s(import))
        .array("delayed_import_details", s(import))
        .array("export_details", s(export))
        .array("resources", s(resource))
        .array("signatures", s(signature));
    for (name, value) in CONSTANTS {
        t = t.constant(name, *value);
    }
    t.func("imphash", "", Type::Str, imphash)
        .func("imports", "ss", Type::Int, |c, a| imports_fn(c, IMPORT_STANDARD, &a[0], Some(&a[1])))
        .func("imports", "si", Type::Int, |c, a| imports_fn(c, IMPORT_STANDARD, &a[0], Some(&a[1])))
        .func("imports", "s", Type::Int, |c, a| imports_fn(c, IMPORT_STANDARD, &a[0], None))
        .func("imports", "rr", Type::Int, |c, a| imports_fn(c, IMPORT_STANDARD, &a[0], Some(&a[1])))
        .func("imports", "iss", Type::Int, |c, a| imports_fn(c, a[0].as_int().unwrap_or(0), &a[1], Some(&a[2])))
        .func("imports", "isi", Type::Int, |c, a| imports_fn(c, a[0].as_int().unwrap_or(0), &a[1], Some(&a[2])))
        .func("imports", "is", Type::Int, |c, a| imports_fn(c, a[0].as_int().unwrap_or(0), &a[1], None))
        .func("imports", "irr", Type::Int, |c, a| imports_fn(c, a[0].as_int().unwrap_or(0), &a[1], Some(&a[2])))
        .func("exports", "s", Type::Int, |c, a| exports_fn(c, &a[0]).map_or(Value::Int(0), |_| Value::Int(1)))
        .func("exports", "i", Type::Int, |c, a| exports_fn(c, &a[0]).map_or(Value::Int(0), |_| Value::Int(1)))
        .func("exports", "r", Type::Int, |c, a| exports_fn(c, &a[0]).map_or(Value::Int(0), |_| Value::Int(1)))
        .func("exports_index", "s", Type::Int, |c, a| {
            exports_fn(c, &a[0]).map_or(Value::Undef, |i| Value::Int(i as i64))
        })
        .func("exports_index", "i", Type::Int, |c, a| {
            exports_fn(c, &a[0]).map_or(Value::Undef, |i| Value::Int(i as i64))
        })
        .func("exports_index", "r", Type::Int, |c, a| {
            exports_fn(c, &a[0]).map_or(Value::Undef, |i| Value::Int(i as i64))
        })
        .func("section_index", "s", Type::Int, section_index)
        .func("section_index", "i", Type::Int, section_index)
        .func("is_dll", "", Type::Int, |c, _| flag(c, "characteristics", 0x2000))
        .func("is_32bit", "", Type::Int, |c, _| {
            get(c.this, "opthdr_magic").as_int().map_or(Value::Undef, |m| Value::Int(i64::from(m == 0x10b)))
        })
        .func("is_64bit", "", Type::Int, |c, _| {
            get(c.this, "opthdr_magic").as_int().map_or(Value::Undef, |m| Value::Int(i64::from(m == 0x20b)))
        })
        .func("rva_to_offset", "i", Type::Int, |c, a| {
            let Some(h) = Headers::read(c.data) else { return Value::Undef };
            a[0].as_int()
                .and_then(|r| u32::try_from(r).ok())
                .and_then(|r| h.rva_to_offset(c.data, r))
                .map_or(Value::Undef, |o| Value::Int(o as i64))
        })
        .func("locale", "i", Type::Int, |c, a| resource_language(c, &a[0], 0xFFFF))
        .func("language", "i", Type::Int, |c, a| resource_language(c, &a[0], 0xFF))
        .func("calculate_checksum", "", Type::Int, |c, _| {
            Headers::read(c.data).map_or(Value::Undef, |h| Value::Int(checksum(c.data, h.opt + 64)))
        })
}

/// The constants YARA's `pe` module defines.
const CONSTANTS: &[(&str, i64)] = &[
    ("MACHINE_UNKNOWN", 0x0),
    ("MACHINE_AM33", 0x1d3),
    ("MACHINE_AMD64", 0x8664),
    ("MACHINE_ARM", 0x1c0),
    ("MACHINE_ARMNT", 0x1c4),
    ("MACHINE_ARM64", 0xaa64),
    ("MACHINE_EBC", 0xebc),
    ("MACHINE_I386", 0x14c),
    ("MACHINE_IA64", 0x200),
    ("MACHINE_M32R", 0x9041),
    ("MACHINE_MIPS16", 0x266),
    ("MACHINE_MIPSFPU", 0x366),
    ("MACHINE_MIPSFPU16", 0x466),
    ("MACHINE_POWERPC", 0x1f0),
    ("MACHINE_POWERPCFP", 0x1f1),
    ("MACHINE_R4000", 0x166),
    ("MACHINE_SH3", 0x1a2),
    ("MACHINE_SH3DSP", 0x1a3),
    ("MACHINE_SH4", 0x1a6),
    ("MACHINE_SH5", 0x1a8),
    ("MACHINE_THUMB", 0x1c2),
    ("MACHINE_WCEMIPSV2", 0x169),
    ("MACHINE_RISCV32", 0x5032),
    ("MACHINE_RISCV64", 0x5064),
    ("MACHINE_RISCV128", 0x5128),
    ("SUBSYSTEM_UNKNOWN", 0),
    ("SUBSYSTEM_NATIVE", 1),
    ("SUBSYSTEM_WINDOWS_GUI", 2),
    ("SUBSYSTEM_WINDOWS_CUI", 3),
    ("SUBSYSTEM_OS2_CUI", 5),
    ("SUBSYSTEM_POSIX_CUI", 7),
    ("SUBSYSTEM_NATIVE_WINDOWS", 8),
    ("SUBSYSTEM_WINDOWS_CE_GUI", 9),
    ("SUBSYSTEM_EFI_APPLICATION", 10),
    ("SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", 11),
    ("SUBSYSTEM_EFI_RUNTIME_DRIVER", 12),
    ("SUBSYSTEM_EFI_ROM_IMAGE", 13),
    ("SUBSYSTEM_XBOX", 14),
    ("SUBSYSTEM_WINDOWS_BOOT_APPLICATION", 16),
    ("RELOCS_STRIPPED", 0x1),
    ("EXECUTABLE_IMAGE", 0x2),
    ("LINE_NUMS_STRIPPED", 0x4),
    ("LOCAL_SYMS_STRIPPED", 0x8),
    ("AGGRESIVE_WS_TRIM", 0x10),
    ("LARGE_ADDRESS_AWARE", 0x20),
    ("BYTES_REVERSED_LO", 0x80),
    ("MACHINE_32BIT", 0x100),
    ("DEBUG_STRIPPED", 0x200),
    ("REMOVABLE_RUN_FROM_SWAP", 0x400),
    ("NET_RUN_FROM_SWAP", 0x800),
    ("SYSTEM", 0x1000),
    ("DLL", 0x2000),
    ("UP_SYSTEM_ONLY", 0x4000),
    ("BYTES_REVERSED_HI", 0x8000),
    ("HIGH_ENTROPY_VA", 0x20),
    ("DYNAMIC_BASE", 0x40),
    ("FORCE_INTEGRITY", 0x80),
    ("NX_COMPAT", 0x100),
    ("NO_ISOLATION", 0x200),
    ("NO_SEH", 0x400),
    ("NO_BIND", 0x800),
    ("APPCONTAINER", 0x1000),
    ("WDM_DRIVER", 0x2000),
    ("GUARD_CF", 0x4000),
    ("TERMINAL_SERVER_AWARE", 0x8000),
    ("SECTION_NO_PAD", 0x8),
    ("SECTION_CNT_CODE", 0x20),
    ("SECTION_CNT_INITIALIZED_DATA", 0x40),
    ("SECTION_CNT_UNINITIALIZED_DATA", 0x80),
    ("SECTION_LNK_OTHER", 0x100),
    ("SECTION_LNK_INFO", 0x200),
    ("SECTION_LNK_REMOVE", 0x800),
    ("SECTION_LNK_COMDAT", 0x1000),
    ("SECTION_NO_DEFER_SPEC_EXC", 0x4000),
    ("SECTION_GPREL", 0x8000),
    ("SECTION_MEM_PURGEABLE", 0x20000),
    ("SECTION_MEM_16BIT", 0x20000),
    ("SECTION_MEM_LOCKED", 0x40000),
    ("SECTION_MEM_PRELOAD", 0x80000),
    ("SECTION_LNK_NRELOC_OVFL", 0x0100_0000),
    ("SECTION_MEM_DISCARDABLE", 0x0200_0000),
    ("SECTION_MEM_NOT_CACHED", 0x0400_0000),
    ("SECTION_MEM_NOT_PAGED", 0x0800_0000),
    ("SECTION_MEM_SHARED", 0x1000_0000),
    ("SECTION_MEM_EXECUTE", 0x2000_0000),
    ("SECTION_MEM_READ", 0x4000_0000),
    ("SECTION_MEM_WRITE", 0x8000_0000),
    ("SECTION_SCALE_INDEX", 0x1),
    ("IMAGE_DIRECTORY_ENTRY_EXPORT", 0),
    ("IMAGE_DIRECTORY_ENTRY_IMPORT", 1),
    ("IMAGE_DIRECTORY_ENTRY_RESOURCE", 2),
    ("IMAGE_DIRECTORY_ENTRY_EXCEPTION", 3),
    ("IMAGE_DIRECTORY_ENTRY_SECURITY", 4),
    ("IMAGE_DIRECTORY_ENTRY_BASERELOC", 5),
    ("IMAGE_DIRECTORY_ENTRY_DEBUG", 6),
    ("IMAGE_DIRECTORY_ENTRY_ARCHITECTURE", 7),
    ("IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 7),
    ("IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 8),
    ("IMAGE_DIRECTORY_ENTRY_TLS", 9),
    ("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 10),
    ("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 11),
    ("IMAGE_DIRECTORY_ENTRY_IAT", 12),
    ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 13),
    ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 14),
    ("IMAGE_NT_OPTIONAL_HDR32_MAGIC", 0x10b),
    ("IMAGE_NT_OPTIONAL_HDR64_MAGIC", 0x20b),
    ("IMAGE_ROM_OPTIONAL_HDR_MAGIC", 0x107),
    ("RESOURCE_TYPE_CURSOR", 1),
    ("RESOURCE_TYPE_BITMAP", 2),
    ("RESOURCE_TYPE_ICON", 3),
    ("RESOURCE_TYPE_MENU", 4),
    ("RESOURCE_TYPE_DIALOG", 5),
    ("RESOURCE_TYPE_STRING", 6),
    ("RESOURCE_TYPE_FONTDIR", 7),
    ("RESOURCE_TYPE_FONT", 8),
    ("RESOURCE_TYPE_ACCELERATOR", 9),
    ("RESOURCE_TYPE_RCDATA", 10),
    ("RESOURCE_TYPE_MESSAGETABLE", 11),
    ("RESOURCE_TYPE_GROUP_CURSOR", 12),
    ("RESOURCE_TYPE_GROUP_ICON", 14),
    ("RESOURCE_TYPE_VERSION", 16),
    ("RESOURCE_TYPE_DLGINCLUDE", 17),
    ("RESOURCE_TYPE_PLUGPLAY", 19),
    ("RESOURCE_TYPE_VXD", 20),
    ("RESOURCE_TYPE_ANICURSOR", 21),
    ("RESOURCE_TYPE_ANIICON", 22),
    ("RESOURCE_TYPE_HTML", 23),
    ("RESOURCE_TYPE_MANIFEST", 24),
    ("IMPORT_STANDARD", IMPORT_STANDARD),
    ("IMPORT_DELAYED", IMPORT_DELAYED),
    ("IMPORT_ANY", -1),
];

/// A field of `this` by name (functions only get the value, not its type).
fn get(this: &Value, name: &str) -> Value {
    field_of(&types().module, this, name)
}

fn field_of(ty: &StructType, v: &Value, name: &str) -> Value {
    match ty.lookup(name) {
        Some(FieldKind::Value { slot, .. }) => v.field(*slot),
        _ => Value::Undef,
    }
}

fn flag(c: &FnCtx, field: &str, bit: i64) -> Value {
    get(c.this, field).as_int().map_or(Value::Undef, |v| Value::Int(i64::from(v & bit != 0)))
}

pub struct Pe;

impl Pe {
    pub fn new() -> Self {
        Pe
    }
}

impl Default for Pe {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Pe {
    fn name(&self) -> &'static str {
        "pe"
    }

    fn schema(&self) -> Arc<StructType> {
        types().module.clone()
    }

    fn parse(&self, data: &[u8]) -> Value {
        let t = types();
        let mut v = t.module.value();
        match Headers::read(data) {
            None => {
                v.int("is_pe", 0);
            }
            Some(h) => h.fill(data, t, &mut v),
        }
        v.build()
    }
}

/// Where a PE's headers are, read once.
struct Headers {
    /// The `PE\0\0` signature.
    pe: usize,
    /// The optional header.
    opt: usize,
    magic: u16,
    sections: usize,
    nsections: usize,
    file_alignment: u32,
    image_base: u64,
}

struct Section {
    va: u32,
    vsize: u32,
    raw_off: u32,
    raw_size: u32,
}

impl Headers {
    fn read(d: &[u8]) -> Option<Headers> {
        if d.get(..2)? != b"MZ" {
            return None;
        }
        let pe = u32le(d, 0x3C)? as usize;
        if d.get(pe..pe + 4)? != b"PE\0\0" {
            return None;
        }
        let opt = pe + 24;
        let magic = u16le(d, opt)?;
        let opt_size = u16le(d, pe + 20)? as usize;
        let nsections = (u16le(d, pe + 6)? as usize).min(MAX_SECTIONS);
        let pe64 = magic == 0x20b;
        let image_base = if pe64 { u64le(d, opt + 24)? } else { u64::from(u32le(d, opt + 28)?) };
        Some(Headers {
            pe,
            opt,
            magic,
            sections: opt + opt_size,
            nsections,
            file_alignment: u32le(d, opt + 36).unwrap_or(0),
            image_base,
        })
    }

    fn pe64(&self) -> bool {
        self.magic == 0x20b
    }

    fn section(&self, d: &[u8], i: usize) -> Option<Section> {
        let at = self.sections + 40 * i;
        Some(Section {
            vsize: u32le(d, at + 8)?,
            va: u32le(d, at + 12)?,
            raw_size: u32le(d, at + 16)?,
            raw_off: u32le(d, at + 20)?,
        })
    }

    fn all_sections(&self, d: &[u8]) -> Vec<Section> {
        (0..self.nsections).map_while(|i| self.section(d, i)).collect()
    }

    /// A data directory's `(virtual address, size)`.
    fn directory(&self, d: &[u8], index: usize) -> Option<(u32, u32)> {
        let base = if self.pe64() { self.opt + 112 } else { self.opt + 96 };
        let count = u32le(d, base - 4)? as usize;
        if index >= count.min(MAX_DATA_DIRECTORIES) {
            return None;
        }
        let (va, size) = (u32le(d, base + 8 * index)?, u32le(d, base + 8 * index + 4)?);
        (va != 0 && size != 0).then_some((va, size))
    }

    /// A relative virtual address to a file offset, by YARA's rules: the
    /// section with the highest start at or below it, its raw offset aligned
    /// down to the (at most 0x200) file alignment; addresses below the first
    /// section are in the headers.
    fn rva_to_offset(&self, d: &[u8], rva: u32) -> Option<usize> {
        let sections = self.all_sections(d);
        let lowest = sections.iter().map(|s| s.va).min().unwrap_or(u32::MAX);
        let (mut base_rva, mut base_off, mut raw_size, mut align) = (0u64, 0u64, d.len() as u64, 0u64);
        if rva >= lowest {
            for s in &sections {
                if rva >= s.va && base_rva <= u64::from(s.va) {
                    base_rva = u64::from(s.va);
                    base_off = u64::from(s.raw_off);
                    raw_size = u64::from(s.raw_size);
                    align = u64::from(self.file_alignment.min(0x200));
                }
            }
        }
        let delta = u64::from(rva) - base_rva;
        if delta >= raw_size {
            return None;
        }
        if align > 0 {
            base_off &= !(align - 1);
        }
        let off = base_off + delta;
        (off < d.len() as u64).then_some(off as usize)
    }

    fn fill(&self, d: &[u8], t: &Types, v: &mut crate::value::StructBuilder) {
        let (pe, opt) = (self.pe, self.opt);
        let r16 = |at: usize| u16le(d, at).map(i64::from);
        let r32 = |at: usize| u32le(d, at).map(i64::from);
        let mut set = |name: &str, x: Option<i64>| {
            if let Some(x) = x {
                v.int(name, x);
            }
        };
        set("is_pe", Some(1));
        set("machine", r16(pe + 4));
        set("number_of_sections", r16(pe + 6));
        set("timestamp", r32(pe + 8));
        set("pointer_to_symbol_table", r32(pe + 12));
        set("number_of_symbols", r32(pe + 16));
        set("size_of_optional_header", r16(pe + 20));
        set("characteristics", r16(pe + 22));
        set("opthdr_magic", Some(i64::from(self.magic)));
        set("size_of_code", r32(opt + 4));
        set("size_of_initialized_data", r32(opt + 8));
        set("size_of_uninitialized_data", r32(opt + 12));
        let entry = u32le(d, opt + 16);
        set("entry_point_raw", entry.map(i64::from));
        set("entry_point", entry.and_then(|e| self.rva_to_offset(d, e)).map(|o| o as i64));
        set("base_of_code", r32(opt + 20));
        set("image_base", Some(self.image_base as i64));
        set("section_alignment", r32(opt + 32));
        set("file_alignment", r32(opt + 36));
        set("win32_version_value", r32(opt + 52));
        set("size_of_image", r32(opt + 56));
        set("size_of_headers", r32(opt + 60));
        set("checksum", r32(opt + 64));
        set("subsystem", r16(opt + 68));
        set("dll_characteristics", r16(opt + 70));
        let wide = |at: usize| if self.pe64() { u64le(d, at).map(|x| x as i64) } else { r32(at) };
        if self.pe64() {
            set("size_of_stack_reserve", wide(opt + 72));
            set("size_of_stack_commit", wide(opt + 80));
            set("size_of_heap_reserve", wide(opt + 88));
            set("size_of_heap_commit", wide(opt + 96));
            set("loader_flags", r32(opt + 104));
            set("number_of_rva_and_sizes", r32(opt + 108));
        } else {
            set("base_of_data", r32(opt + 24));
            set("size_of_stack_reserve", wide(opt + 72));
            set("size_of_stack_commit", wide(opt + 76));
            set("size_of_heap_reserve", wide(opt + 80));
            set("size_of_heap_commit", wide(opt + 84));
            set("loader_flags", r32(opt + 88));
            set("number_of_rva_and_sizes", r32(opt + 92));
        }
        let pair = |major: Option<i64>, minor: Option<i64>| {
            let mut b = t.version.value();
            if let (Some(a), Some(b2)) = (major, minor) {
                b.int("major", a).int("minor", b2);
            }
            b.build()
        };
        let r8 = |at: usize| d.get(at).map(|b| i64::from(*b));
        v.set("linker_version", pair(r8(opt + 2), r8(opt + 3)));
        v.set("os_version", pair(r16(opt + 40), r16(opt + 42)));
        v.set("image_version", pair(r16(opt + 44), r16(opt + 46)));
        v.set("subsystem_version", pair(r16(opt + 48), r16(opt + 50)));
        self.fill_directories(d, t, v);
        self.fill_sections(d, t, v);
        self.fill_rich(d, t, v);
        self.fill_imports(d, t, v);
        self.fill_exports(d, t, v);
        self.fill_resources(d, t, v);
        self.fill_signatures(d, t, v);
        if let Some(path) = self.pdb_path(d) {
            v.string("pdb_path", path);
        }
    }

    fn fill_directories(&self, d: &[u8], t: &Types, v: &mut crate::value::StructBuilder) {
        let base = if self.pe64() { self.opt + 112 } else { self.opt + 96 };
        let count = u32le(d, base - 4).unwrap_or(0) as usize;
        let dirs = (0..count.min(MAX_DATA_DIRECTORIES))
            .map_while(|i| {
                let (va, size) = (u32le(d, base + 8 * i)?, u32le(d, base + 8 * i + 4)?);
                let mut b = t.directory.value();
                b.int("virtual_address", va).int("size", size);
                Some(b.build())
            })
            .collect();
        v.set("data_directories", array(dirs));
    }

    fn fill_sections(&self, d: &[u8], t: &Types, v: &mut crate::value::StructBuilder) {
        let symtab = u32le(d, self.pe + 12).unwrap_or(0) as usize;
        let nsyms = u32le(d, self.pe + 16).unwrap_or(0) as usize;
        let strtab = symtab.saturating_add(nsyms.saturating_mul(18));
        let mut list = Vec::new();
        let mut last_end = 0u64;
        for i in 0..self.nsections {
            let at = self.sections + 40 * i;
            let Some(s) = self.section(d, i) else { break };
            let raw_name = cstr(d, at, 8).unwrap_or_default();
            // `/123` names a string in the COFF string table.
            let full = std::str::from_utf8(raw_name.get(1..).unwrap_or_default())
                .ok()
                .filter(|n| raw_name.first() == Some(&b'/') && symtab != 0 && !n.is_empty())
                .and_then(|n| n.parse::<usize>().ok())
                .and_then(|off| cstr(d, strtab.saturating_add(off), MAX_NAME))
                .unwrap_or(raw_name);
            let mut b = t.section.value();
            b.string("name", raw_name)
                .string("full_name", full)
                .int("characteristics", u32le(d, at + 36).unwrap_or(0))
                .int("virtual_address", s.va)
                .int("virtual_size", s.vsize)
                .int("raw_data_offset", s.raw_off)
                .int("raw_data_size", s.raw_size)
                .int("pointer_to_relocations", u32le(d, at + 24).unwrap_or(0))
                .int("pointer_to_line_numbers", u32le(d, at + 28).unwrap_or(0))
                .int("number_of_relocations", u16le(d, at + 32).unwrap_or(0))
                .int("number_of_line_numbers", u16le(d, at + 34).unwrap_or(0));
            list.push(b.build());
            if s.raw_size > 0 {
                last_end = last_end.max(u64::from(s.raw_off) + u64::from(s.raw_size));
            }
        }
        v.set("sections", array(list));
        let mut o = t.overlay.value();
        let len = d.len() as u64;
        let (off, size) = if last_end > 0 && last_end < len { (last_end, len - last_end) } else { (0, 0) };
        o.int("offset", off as i64).int("size", size as i64);
        v.set("overlay", o.build());
    }

    /// The Rich header between the DOS stub and the PE header.
    fn fill_rich(&self, d: &[u8], t: &Types, v: &mut crate::value::StructBuilder) {
        let end = self.pe.min(d.len());
        let Some(rich) = (0x40..end.saturating_sub(8)).step_by(4).find(|i| d.get(*i..*i + 4) == Some(b"Rich")) else {
            return;
        };
        let Some(key) = u32le(d, rich + 4) else { return };
        let Some(dans) = (0x40..rich).step_by(4).rev().find(|i| u32le(d, *i).is_some_and(|w| w ^ key == 0x536E_6144))
        else {
            return;
        };
        let raw = &d[dans..rich];
        let clear: Vec<u8> = raw
            .chunks(4)
            .flat_map(|c| {
                let w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) ^ key;
                w.to_le_bytes()
            })
            .collect();
        let mut b = t.rich.value();
        b.int("offset", dans as i64)
            .int("length", raw.len() as i64)
            .int("key", key)
            .string("raw_data", raw)
            .string("clear_data", clear);
        v.set("rich_signature", b.build());
    }

    fn fill_imports(&self, d: &[u8], t: &Types, v: &mut crate::value::StructBuilder) {
        let thunk = if self.pe64() { 8 } else { 4 };
        let ord_flag: u64 = if self.pe64() { 1 << 63 } else { 1 << 31 };
        let read_thunk = |at: usize| if self.pe64() { u64le(d, at) } else { u32le(d, at).map(u64::from) };
        // One import table: (descriptor size, offsets of name, lookup table, address table).
        let table = |dir: usize, size: usize, fields: (usize, usize, usize), delayed: bool| -> (Vec<Value>, usize) {
            let mut dlls = Vec::new();
            let mut total = 0;
            let Some((va, _)) = self.directory(d, dir) else { return (dlls, total) };
            let Some(mut at) = self.rva_to_offset(d, va) else { return (dlls, total) };
            while total < MAX_IMPORTS {
                let (Some(name_rva), Some(lookup), Some(iat)) =
                    (u32le(d, at + fields.0), u32le(d, at + fields.1), u32le(d, at + fields.2))
                else {
                    break;
                };
                if name_rva == 0 && lookup == 0 && iat == 0 {
                    break;
                }
                // Old-style delayed descriptors (attribute bit 0 clear) hold
                // virtual addresses, not RVAs.
                let old_style = delayed && u32le(d, at).unwrap_or(1) & 1 == 0;
                let fix = |x: u32| if old_style { x.wrapping_sub(self.image_base as u32) } else { x };
                at += size;
                let Some(name) = self.rva_to_offset(d, fix(name_rva)).and_then(|o| cstr(d, o, 256)) else { continue };
                if name.is_empty() || !name.iter().all(|c| c.is_ascii_graphic()) {
                    continue;
                }
                let first = if lookup != 0 { fix(lookup) } else { fix(iat) };
                let Some(mut ta) = self.rva_to_offset(d, first) else { continue };
                let mut funcs = Vec::new();
                let mut i = 0u32;
                while total < MAX_IMPORTS {
                    let Some(entry) = read_thunk(ta) else { break };
                    if entry == 0 {
                        break;
                    }
                    let mut f = t.function.value();
                    if entry & ord_flag != 0 {
                        f.int("ordinal", (entry & 0xFFFF) as i64);
                    } else if let Some(fname) =
                        self.rva_to_offset(d, fix(entry as u32).wrapping_add(2)).and_then(|o| cstr(d, o, MAX_NAME))
                    {
                        f.string("name", fname);
                    }
                    f.int("rva", fix(iat).wrapping_add(i * thunk as u32));
                    funcs.push(f.build());
                    ta += thunk;
                    i += 1;
                    total += 1;
                }
                let mut b = t.import.value();
                b.string("library_name", name)
                    .int("number_of_functions", funcs.len() as i64)
                    .set("functions", array(funcs));
                dlls.push(b.build());
            }
            (dlls, total)
        };
        let (std, n) = table(DIR_IMPORT, 20, (12, 0, 16), false);
        v.int("number_of_imports", std.len() as i64)
            .int("number_of_imported_functions", n as i64)
            .set("import_details", array(std));
        let (delayed, n) = table(DIR_DELAY_IMPORT, 32, (4, 16, 12), true);
        v.int("number_of_delayed_imports", delayed.len() as i64)
            .int("number_of_delayed_imported_functions", n as i64)
            .set("delayed_import_details", array(delayed));
    }

    fn fill_exports(&self, d: &[u8], t: &Types, v: &mut crate::value::StructBuilder) {
        let Some((va, size)) = self.directory(d, DIR_EXPORT) else {
            v.int("number_of_exports", 0);
            return;
        };
        let Some(at) = self.rva_to_offset(d, va) else { return };
        let r = |o: usize| u32le(d, at + o);
        let (Some(stamp), Some(name), Some(base), Some(nfuncs), Some(nnames), Some(funcs), Some(names), Some(ords)) =
            (r(4), r(12), r(16), r(20), r(24), r(28), r(32), r(36))
        else {
            return;
        };
        v.int("export_timestamp", stamp);
        if let Some(n) = self.rva_to_offset(d, name).and_then(|o| cstr(d, o, MAX_NAME)) {
            v.string("dll_name", n);
        }
        let nfuncs = (nfuncs as usize).min(MAX_EXPORTS);
        let (names_off, ords_off, funcs_off) =
            (self.rva_to_offset(d, names), self.rva_to_offset(d, ords), self.rva_to_offset(d, funcs));
        let mut by_index: Vec<Option<&[u8]>> = vec![None; nfuncs];
        if let (Some(no), Some(oo)) = (names_off, ords_off) {
            for i in 0..(nnames as usize).min(MAX_EXPORTS) {
                let (Some(nrva), Some(idx)) = (u32le(d, no + 4 * i), u16le(d, oo + 2 * i)) else { break };
                if let (Some(slot), Some(n)) =
                    (by_index.get_mut(idx as usize), self.rva_to_offset(d, nrva).and_then(|o| cstr(d, o, MAX_NAME)))
                {
                    *slot = Some(n);
                }
            }
        }
        let mut list = Vec::new();
        for (i, name) in by_index.iter().enumerate() {
            let Some(rva) = funcs_off.and_then(|f| u32le(d, f + 4 * i)) else { break };
            let mut e = t.export.value();
            e.int("ordinal", i64::from(base) + i as i64).int("rva", rva);
            if let Some(n) = name {
                e.string("name", n);
            }
            if (va..va.saturating_add(size)).contains(&rva) {
                if let Some(fwd) = self.rva_to_offset(d, rva).and_then(|o| cstr(d, o, MAX_NAME)) {
                    e.string("forward_name", fwd);
                }
            } else if let Some(o) = self.rva_to_offset(d, rva) {
                e.int("offset", o as i64);
            }
            list.push(e.build());
        }
        v.int("number_of_exports", list.len() as i64).set("export_details", array(list));
    }

    fn fill_resources(&self, d: &[u8], t: &Types, v: &mut crate::value::StructBuilder) {
        let Some(tree) = self
            .directory(d, DIR_RESOURCE)
            .and_then(|(va, _)| self.rva_to_offset(d, va))
            .and_then(|base| resources::walk(d, base, &|rva| self.rva_to_offset(d, rva)))
        else {
            v.int("number_of_resources", 0);
            return;
        };
        v.int("resource_timestamp", tree.timestamp);
        let mut ver = t.version.value();
        ver.int("major", tree.major).int("minor", tree.minor);
        v.set("resource_version", ver.build());
        v.int("number_of_resources", tree.resources.len() as i64)
            .set("resources", array(resources::values(&tree, &t.resource)));
        let pairs = resources::version_info(d, &tree);
        let (dict, list) = resources::version_values(&pairs, &t.kv);
        v.int("number_of_version_infos", pairs.len() as i64).set("version_info", dict).set("version_info_list", list);
    }

    fn fill_signatures(&self, d: &[u8], t: &Types, v: &mut crate::value::StructBuilder) {
        // The security directory's address is a file offset, not an RVA.
        let sigs = self
            .directory(d, DIR_SECURITY)
            .map(|(off, size)| sign::signatures(d, off as usize, size as usize, &t.signature))
            .unwrap_or_default();
        v.int("number_of_signatures", sigs.len() as i64)
            .int("is_signed", i64::from(!sigs.is_empty()))
            .set("signatures", array(sigs));
    }

    /// The PDB path from a CodeView debug entry.
    fn pdb_path<'d>(&self, d: &'d [u8]) -> Option<&'d [u8]> {
        let (va, size) = self.directory(d, DIR_DEBUG)?;
        let at = self.rva_to_offset(d, va)?;
        for i in 0..(size as usize / 28).min(16) {
            let e = at + 28 * i;
            if u32le(d, e + 12)? != 2 {
                continue;
            }
            let raw = u32le(d, e + 24)? as usize;
            let cv = if raw != 0 && raw < d.len() { raw } else { self.rva_to_offset(d, u32le(d, e + 20)?)? };
            match d.get(cv..cv + 4)? {
                b"RSDS" => return cstr(d, cv + 24, MAX_NAME),
                b"NB10" => return cstr(d, cv + 16, MAX_NAME),
                _ => {}
            }
        }
        None
    }
}

/// The PE checksum algorithm, skipping the checksum field itself.
fn checksum(d: &[u8], field: usize) -> i64 {
    let mut sum: u64 = 0;
    for (i, c) in d.chunks(4).enumerate() {
        if i * 4 == field {
            continue;
        }
        let mut w = [0u8; 4];
        w[..c.len()].copy_from_slice(c);
        sum += u64::from(u32::from_le_bytes(w));
        sum = (sum & 0xFFFF_FFFF) + (sum >> 32);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += sum >> 16;
    (sum & 0xFFFF) as i64 + d.len() as i64
}

/// The file offset of a PE's entry point, for `entrypoint`.
pub fn entry_offset(d: &[u8]) -> Option<u64> {
    let h = Headers::read(d)?;
    h.rva_to_offset(d, u32le(d, h.opt + 16)?).map(|o| o as u64)
}

/// The library and function names of every import of `kind`, as values.
fn import_lists(this: &Value, flags: i64) -> Vec<Value> {
    let mut out = Vec::new();
    for (bit, field) in [(IMPORT_STANDARD, "import_details"), (IMPORT_DELAYED, "delayed_import_details")] {
        if flags & bit != 0
            && let Value::Array(a) = get(this, field)
        {
            out.extend(a.iter().cloned());
        }
    }
    out
}

fn name_matches(pattern: &Value, name: &[u8]) -> bool {
    match pattern {
        Value::Str(s) => s.eq_ignore_ascii_case(name),
        Value::Regex(re) => matcher::search(re, name),
        _ => false,
    }
}

/// `imports(...)`: with a function name or ordinal, whether (or for regexes,
/// how many times) it is imported; with only a library, how many of its
/// functions are.
fn imports_fn(c: &FnCtx, flags: i64, dll: &Value, func: Option<&Value>) -> Value {
    let t = types();
    let mut count = 0i64;
    let regex = matches!(dll, Value::Regex(_));
    for lib in import_lists(c.this, flags) {
        let Some(lib_name) = field_of(&t.import, &lib, "library_name").as_bytes().map(<[u8]>::to_vec) else { continue };
        if !name_matches(dll, &lib_name) {
            continue;
        }
        let Value::Array(funcs) = field_of(&t.import, &lib, "functions") else { continue };
        for f in funcs.iter() {
            let hit = match func {
                None => true,
                Some(Value::Int(ord)) => field_of(&t.function, f, "ordinal").as_int() == Some(*ord),
                Some(p) => field_of(&t.function, f, "name").as_bytes().is_some_and(|n| name_matches(p, n)),
            };
            if hit {
                count += 1;
                if func.is_some() && !regex {
                    return Value::Int(1);
                }
            }
        }
    }
    Value::Int(count)
}

/// The index of the first export named (case-insensitively), numbered or
/// matched as given.
fn exports_fn(c: &FnCtx, what: &Value) -> Option<usize> {
    let t = types();
    let Value::Array(list) = get(c.this, "export_details") else { return None };
    list.iter().position(|e| match what {
        Value::Int(ord) => field_of(&t.export, e, "ordinal").as_int() == Some(*ord),
        p => field_of(&t.export, e, "name").as_bytes().is_some_and(|n| name_matches(p, n)),
    })
}

fn section_index(c: &FnCtx, a: &[Value]) -> Value {
    let t = types();
    let Value::Array(list) = get(c.this, "sections") else { return Value::Undef };
    let found = list.iter().position(|s| match &a[0] {
        Value::Str(name) => field_of(&t.section, s, "name").as_bytes() == Some(name),
        Value::Int(addr) => {
            let (va, vs) =
                (field_of(&t.section, s, "virtual_address").as_int(), field_of(&t.section, s, "virtual_size").as_int());
            matches!((va, vs), (Some(va), Some(vs)) if (va..va + vs).contains(addr))
        }
        _ => false,
    });
    found.map_or(Value::Undef, |i| Value::Int(i as i64))
}

fn resource_language(c: &FnCtx, id: &Value, mask: i64) -> Value {
    let t = types();
    let Some(id) = id.as_int() else { return Value::Undef };
    let Value::Array(list) = get(c.this, "resources") else { return Value::Int(0) };
    Value::Int(i64::from(
        list.iter().any(|r| field_of(&t.resource, r, "language").as_int().is_some_and(|l| l & mask == id)),
    ))
}

/// The import hash: MD5 of `library.function` pairs, lowercased, library
/// extensions (`.dll`, `.ocx`, `.sys`) dropped, ordinals as `ordN`.
fn imphash(c: &FnCtx, _: &[Value]) -> Value {
    let t = types();
    let Value::Array(libs) = get(c.this, "import_details") else { return Value::Undef };
    let mut parts = Vec::new();
    for lib in libs.iter() {
        let Some(name) = field_of(&t.import, lib, "library_name").as_bytes().map(<[u8]>::to_ascii_lowercase) else {
            continue;
        };
        let stem = match name.iter().rposition(|b| *b == b'.') {
            Some(dot) if [&b"dll"[..], b"ocx", b"sys"].contains(&&name[dot + 1..]) => name[..dot].to_vec(),
            _ => name.clone(),
        };
        let Value::Array(funcs) = field_of(&t.import, lib, "functions") else { continue };
        for f in funcs.iter() {
            let func = match field_of(&t.function, f, "name").as_bytes() {
                Some(n) => n.to_ascii_lowercase(),
                None => format!("ord{}", field_of(&t.function, f, "ordinal").as_int().unwrap_or(0)).into_bytes(),
            };
            parts.push([stem.as_slice(), b".", &func].concat());
        }
    }
    if parts.is_empty() {
        return Value::Undef;
    }
    Value::str(hex(&md5(&parts.join(&b","[..]))))
}

/// How many times the Rich header counts a version and/or tool id.
fn rich_count(c: &FnCtx, version: Option<&Value>, tool: Option<&Value>) -> Value {
    let Some(clear) = field_of(&types().rich, c.this, "clear_data").as_bytes().map(<[u8]>::to_vec) else {
        return Value::Undef;
    };
    let (version, tool) = (version.and_then(Value::as_int), tool.and_then(Value::as_int));
    let mut total = 0i64;
    for e in clear.get(16..).unwrap_or_default().chunks_exact(8) {
        let id = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
        let times = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
        let (build, prod) = (i64::from(id & 0xFFFF), i64::from(id >> 16));
        if version.is_none_or(|v| v == build) && tool.is_none_or(|t| t == prod) {
            total += i64::from(times);
        }
    }
    Value::Int(total)
}

#[cfg(test)]
mod tests;
