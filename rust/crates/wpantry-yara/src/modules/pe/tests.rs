//! The `pe` module against a hand-built DLL with every structure it reads.

use super::resources::tests::{resource_section, version_resource};
use super::sign::tests::{signed_data, win_certificate};
use crate::{Compiler, ScanOptions, Syntax};

const RICH_KEY: u32 = 0x1122_3344;

fn put(f: &mut [u8], at: usize, bytes: &[u8]) {
    f[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put32(f: &mut [u8], at: usize, v: u32) {
    put(f, at, &v.to_le_bytes());
}

fn put16(f: &mut [u8], at: usize, v: u16) {
    put(f, at, &v.to_le_bytes());
}

/// A 32-bit DLL: Rich header, `.text`/`.rdata`/`.rsrc`, imports (by name and
/// ordinal, plus a delayed one), exports (one forwarded), version info, a
/// CodeView PDB path and an Authenticode signature in the overlay.
pub fn sample_dll() -> Vec<u8> {
    let mut f = vec![0u8; 0xE00];
    put(&mut f, 0, b"MZ");
    put32(&mut f, 0x3C, 0x100);
    // Rich header: DanS, three padding words, one (compid, count) entry, Rich, key.
    let compid = 0x0104 << 16 | 30729;
    for (i, w) in [0x536E_6144, 0, 0, 0, compid, 5].iter().enumerate() {
        put32(&mut f, 0x80 + 4 * i, w ^ RICH_KEY);
    }
    put(&mut f, 0x98, b"Rich");
    put32(&mut f, 0x9C, RICH_KEY);
    // File header.
    put(&mut f, 0x100, b"PE\0\0");
    put16(&mut f, 0x104, 0x14c);
    put16(&mut f, 0x106, 3);
    put32(&mut f, 0x108, 0x5F00_0000);
    put16(&mut f, 0x114, 0xE0);
    put16(&mut f, 0x116, 0x2102);
    // Optional header.
    let opt = 0x118;
    put16(&mut f, opt, 0x10b);
    f[opt + 2] = 14;
    put32(&mut f, opt + 16, 0x1010);
    put32(&mut f, opt + 28, 0x40_0000);
    put32(&mut f, opt + 32, 0x1000);
    put32(&mut f, opt + 36, 0x200);
    put16(&mut f, opt + 40, 6);
    put16(&mut f, opt + 68, 2);
    put32(&mut f, opt + 92, 16);
    let rsrc = resource_section(0x3000, &version_resource(&[("CompanyName", "Evil Corp")]));
    let dirs =
        [(0, 0x2100, 0xC0), (1, 0x2000, 0x28), (2, 0x3000, rsrc.len() as u32), (6, 0x2200, 28), (13, 0x2300, 0x40)];
    for (i, va, size) in dirs {
        put32(&mut f, opt + 96 + 8 * i, va);
        put32(&mut f, opt + 100 + 8 * i, size);
    }
    // Sections.
    for (i, (name, va, raw)) in
        [(&b".text"[..], 0x1000u32, 0x400u32), (b".rdata", 0x2000, 0x600), (b".rsrc", 0x3000, 0xA00)].iter().enumerate()
    {
        let at = 0x1F8 + 40 * i;
        put(&mut f, at, name);
        put32(&mut f, at + 8, 0x400);
        put32(&mut f, at + 12, *va);
        put32(&mut f, at + 16, 0x400);
        put32(&mut f, at + 20, *raw);
        put32(&mut f, at + 36, 0x6000_0020);
    }
    // .rdata at file 0x600 = RVA 0x2000.
    let r = |rva: u32| (rva - 0x2000 + 0x600) as usize;
    put32(&mut f, r(0x2000), 0x2040);
    put32(&mut f, r(0x200C), 0x2080);
    put32(&mut f, r(0x2010), 0x2060);
    for table in [0x2040, 0x2060] {
        put32(&mut f, r(table), 0x2090);
        put32(&mut f, r(table) + 4, 0x8000_0005);
    }
    put(&mut f, r(0x2080), b"KERNEL32.dll\0");
    put(&mut f, r(0x2092), b"VirtualAlloc\0");
    // Exports.
    put32(&mut f, r(0x2104), 0x1234);
    put32(&mut f, r(0x210C), 0x2140);
    put32(&mut f, r(0x2110), 1);
    put32(&mut f, r(0x2114), 2);
    put32(&mut f, r(0x2118), 2);
    put32(&mut f, r(0x211C), 0x2160);
    put32(&mut f, r(0x2120), 0x2170);
    put32(&mut f, r(0x2124), 0x2180);
    put(&mut f, r(0x2140), b"evil.dll\0");
    put(&mut f, r(0x2150), b"DoEvil\0");
    put32(&mut f, r(0x2160), 0x1000);
    put32(&mut f, r(0x2164), 0x21A0);
    put32(&mut f, r(0x2170), 0x2150);
    put32(&mut f, r(0x2174), 0x2190);
    put16(&mut f, r(0x2182), 1);
    put(&mut f, r(0x2190), b"Fwd\0");
    put(&mut f, r(0x21A0), b"NTDLL.RtlFoo\0");
    // Debug directory with a CodeView RSDS record.
    put32(&mut f, r(0x2200) + 12, 2);
    put32(&mut f, r(0x2200) + 20, 0x2220);
    put32(&mut f, r(0x2200) + 24, r(0x2220) as u32);
    put(&mut f, r(0x2220), b"RSDS");
    put(&mut f, r(0x2220) + 24, b"C:\\evil.pdb\0");
    // A delayed import of user32!MessageBoxA (RVA-based: attribute bit 0).
    put32(&mut f, r(0x2300), 1);
    put32(&mut f, r(0x2304), 0x2340);
    put32(&mut f, r(0x230C), 0x2360);
    put32(&mut f, r(0x2310), 0x2350);
    put(&mut f, r(0x2340), b"user32.dll\0");
    put32(&mut f, r(0x2350), 0x2370);
    put(&mut f, r(0x2372), b"MessageBoxA\0");
    // .rsrc at file 0xA00.
    put(&mut f, 0xA00, &rsrc);
    // The signature, past the last section: the security directory names a file offset.
    let sig = win_certificate(&signed_data("Evil Signer", &[0x05, 0xe2], None));
    put32(&mut f, opt + 96 + 8 * 4, 0xE00);
    put32(&mut f, opt + 100 + 8 * 4, sig.len() as u32);
    f.extend_from_slice(&sig);
    f
}

fn holds(cond: &str, data: &[u8]) -> bool {
    let mut c = Compiler::new();
    let src = format!("import \"pe\" rule r {{ condition: {cond} }}");
    assert_eq!(c.add_source("t", &src, Syntax::Relaxed), 1, "{cond}");
    !c.build().scan(data, &ScanOptions::default()).matches.is_empty()
}

#[test]
fn headers_and_sections() {
    let d = sample_dll();
    for cond in [
        "pe.is_pe == 1 and pe.machine == pe.MACHINE_I386 and pe.number_of_sections == 3",
        "pe.timestamp == 0x5F000000 and pe.characteristics & pe.DLL and pe.is_dll() and pe.is_32bit() and not pe.is_64bit()",
        "pe.entry_point == 0x410 and entrypoint == 0x410 and pe.entry_point_raw == 0x1010 and pe.image_base == 0x400000",
        "pe.linker_version.major == 14 and pe.os_version.major == 6 and pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI",
        "pe.sections[1].name == \".rdata\" and pe.sections[0].characteristics & pe.SECTION_CNT_CODE",
        "pe.section_index(\".rsrc\") == 2 and pe.section_index(0x1050) == 0 and not defined pe.section_index(\".nope\")",
        "pe.rva_to_offset(0x2000) == 0x600 and not defined pe.rva_to_offset(0x9000)",
        "pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address == 0x2000",
        "pe.overlay.offset == 0xE00 and pe.overlay.size > 0",
        "pe.number_of_rva_and_sizes == 16 and pe.opthdr_magic == pe.IMAGE_NT_OPTIONAL_HDR32_MAGIC",
        "pe.calculate_checksum() > 0",
        "for any s in pe.sections : (s.name == \".text\")",
    ] {
        assert!(holds(cond, &d), "{cond}");
    }
}

#[test]
fn imports_and_exports() {
    let d = sample_dll();
    for cond in [
        "pe.number_of_imports == 1 and pe.number_of_imported_functions == 2",
        "pe.imports(\"kernel32.dll\", \"virtualalloc\") and pe.imports(\"KERNEL32.DLL\", 5)",
        "pe.imports(\"kernel32.dll\") == 2 and pe.imports(/kernel/i, /Alloc$/) == 1",
        "not pe.imports(\"user32.dll\", \"MessageBoxA\") and pe.imports(pe.IMPORT_DELAYED, \"user32.dll\", \"MessageBoxA\")",
        "pe.imports(pe.IMPORT_ANY, \"user32.dll\") == 1 and pe.number_of_delayed_imports == 1",
        "pe.import_details[0].functions[0].name == \"VirtualAlloc\" and pe.import_details[0].functions[1].ordinal == 5",
        "pe.dll_name == \"evil.dll\" and pe.number_of_exports == 2 and pe.export_timestamp == 0x1234",
        "pe.exports(\"doevil\") and pe.exports(2) and pe.exports(/^Fw/) and not pe.exports(\"nope\")",
        "pe.exports_index(\"Fwd\") == 1 and pe.export_details[1].forward_name == \"NTDLL.RtlFoo\"",
        "pe.export_details[0].offset == 0x400 and not defined pe.exports_index(99)",
    ] {
        assert!(holds(cond, &d), "{cond}");
    }
}

#[test]
fn imphash_is_md5_of_the_import_list() {
    let d = sample_dll();
    let expected = crate::modules::hex(&crate::modules::hash::md5(b"kernel32.virtualalloc,kernel32.ord5"));
    assert!(holds(&format!("pe.imphash() == \"{expected}\""), &d));
}

#[test]
fn resources_version_info_rich_and_debug() {
    let d = sample_dll();
    for cond in [
        "pe.number_of_resources == 1 and pe.resources[0].type == pe.RESOURCE_TYPE_VERSION and pe.resources[0].language == 0x409",
        "pe.version_info[\"CompanyName\"] == \"Evil Corp\" and pe.version_info_list[0].key == \"CompanyName\"",
        "pe.number_of_version_infos == 1 and pe.resource_timestamp == 0x1234 and pe.resource_version.major == 4",
        "pe.locale(0x409) and pe.language(9) and not pe.locale(0x407)",
        "pe.rich_signature.key == 0x11223344 and pe.rich_signature.offset == 0x80 and pe.rich_signature.length == 24",
        "pe.rich_signature.toolid(0x104) == 5 and pe.rich_signature.version(30729) == 5",
        "pe.rich_signature.version(30729, 0x104) == 5 and pe.rich_signature.toolid(0x104, 1) == 0",
        "pe.rich_signature.clear_data startswith \"DanS\"",
        "pe.pdb_path == \"C:\\\\evil.pdb\"",
    ] {
        assert!(holds(cond, &d), "{cond}");
    }
}

#[test]
fn signatures() {
    let d = sample_dll();
    for cond in [
        "pe.number_of_signatures == 1 and pe.is_signed",
        "pe.signatures[0].subject == \"/CN=Evil Signer\" and pe.signatures[0].issuer contains \"Test CA\"",
        "pe.signatures[0].serial == \"05:e2\" and pe.signatures[0].not_after > 1308182400",
        "pe.signatures[0].valid_on(1500000000) and pe.signatures[0].number_of_certificates == 1",
        "for any i in (0 .. pe.number_of_signatures) : (pe.signatures[i].serial == \"05:e2\")",
    ] {
        assert!(holds(cond, &d), "{cond}");
    }
}

#[test]
fn not_a_pe() {
    for data in [&b"MZ"[..], b"MZ\0\0", b"ELF", b""] {
        assert!(holds("pe.is_pe == 0 and not defined pe.machine and not defined pe.entry_point", data));
        assert!(holds("not defined pe.imphash() and not defined entrypoint", data));
    }
    // A truncated PE keeps what it could read.
    let d = sample_dll();
    assert!(holds("pe.is_pe == 1 and pe.number_of_sections == 3", &d[..0x300]));
}
