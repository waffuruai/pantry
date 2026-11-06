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
