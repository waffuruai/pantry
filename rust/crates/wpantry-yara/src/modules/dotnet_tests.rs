use crate::{Compiler, ScanOptions, Syntax};

/// A PE32 with one section holding a CLI header and a metadata root with
/// two streams.
fn sample() -> Vec<u8> {
    let mut f = vec![0u8; 0x400];
    let put = |f: &mut Vec<u8>, at: usize, b: &[u8]| f[at..at + b.len()].copy_from_slice(b);
    put(&mut f, 0, b"MZ");
    put(&mut f, 0x3C, &0x80u32.to_le_bytes());
    put(&mut f, 0x80, b"PE\0\0");
    put(&mut f, 0x86, &1u16.to_le_bytes());
    put(&mut f, 0x94, &0xE0u16.to_le_bytes());
    put(&mut f, 0x98, &0x10bu16.to_le_bytes());
    put(&mut f, 0x98 + 92, &16u32.to_le_bytes());
    put(&mut f, 0x98 + 96 + 8 * 14, &0x2000u32.to_le_bytes());
    put(&mut f, 0x98 + 96 + 8 * 14 + 4, &0x48u32.to_le_bytes());
    // .text: RVA 0x2000 = file 0x200.
    let sec = 0x98 + 0xE0;
    put(&mut f, sec, b".text");
    put(&mut f, sec + 8, &0x200u32.to_le_bytes());
    put(&mut f, sec + 12, &0x2000u32.to_le_bytes());
    put(&mut f, sec + 16, &0x200u32.to_le_bytes());
    put(&mut f, sec + 20, &0x200u32.to_le_bytes());
    // CLI header: metadata at RVA 0x2050.
    put(&mut f, 0x208, &0x2050u32.to_le_bytes());
    put(&mut f, 0x250, &0x424A_5342u32.to_le_bytes());
    put(&mut f, 0x25C, &12u32.to_le_bytes());
    put(&mut f, 0x260, b"v4.0.30319\0\0");
    put(&mut f, 0x26E, &2u16.to_le_bytes());
    put(&mut f, 0x270, &0x6Cu32.to_le_bytes());
    put(&mut f, 0x274, &0x10u32.to_le_bytes());
    put(&mut f, 0x278, b"#~\0\0");
    put(&mut f, 0x27C, &0x7Cu32.to_le_bytes());
    put(&mut f, 0x280, &0x20u32.to_le_bytes());
    put(&mut f, 0x284, b"#Strings\0\0\0\0");
    f
}

fn holds(cond: &str, data: &[u8]) -> bool {
    let mut c = Compiler::new();
    assert_eq!(c.add_source("t", &format!("import \"dotnet\" rule r {{ condition: {cond} }}"), Syntax::Relaxed), 1);
    !c.build().scan(data, &ScanOptions::default()).matches.is_empty()
}

#[test]
fn reads_the_metadata_root() {
    let d = sample();
    assert!(holds("dotnet.is_dotnet == 1 and dotnet.version == \"v4.0.30319\"", &d));
    assert!(holds(
        "dotnet.number_of_streams == 2 and dotnet.streams[1].name == \"#Strings\" and dotnet.streams[0].size == 16",
        &d
    ));
    assert!(holds("dotnet.streams[0].offset == 0x250 + 0x6C", &d));
}

#[test]
fn other_files_are_not_dotnet() {
    let mut d = sample();
    d[0x250] = 0;
    assert!(holds("dotnet.is_dotnet == 0", &d));
    for other in [&b"MZ"[..], b"\x7fELF", b""] {
        assert!(holds("dotnet.is_dotnet == 0 and not defined dotnet.version", other));
    }
}
