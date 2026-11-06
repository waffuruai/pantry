//! Hostile input never panics or hangs: random and mutated files through
//! every module, and mangled rule text through the compiler. A small
//! deterministic generator stands in for a fuzzer (no dependencies).

use wpantry_yara::modules;
use wpantry_yara::{Compiler, ScanOptions, Syntax};

/// xorshift64*: reproducible pseudo-random bytes.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// A file that starts like a PE, ELF or Mach-O so parsers go deep, with the
/// rest random and some header words pointing back inside the file.
fn shaped(rng: &mut Rng) -> Vec<u8> {
    let len = 64 + rng.below(4096);
    let mut d = rng.bytes(len);
    match rng.below(3) {
        0 => {
            d[..2].copy_from_slice(b"MZ");
            let pe = rng.below(len - 4) as u32;
            d[0x3C..0x40].copy_from_slice(&pe.to_le_bytes());
            d[pe as usize..pe as usize + 4].copy_from_slice(b"PE\0\0");
        }
        1 => d[..4].copy_from_slice(b"\x7fELF"),
        _ => d[..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]),
    }
    // Sprinkle small offsets so tables and strings land inside the file.
    for _ in 0..32 {
        let at = rng.below(len - 4);
        let v = rng.below(len) as u32;
        d[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    d
}

#[test]
fn modules_survive_random_files() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mods = modules::builtin();
    for _ in 0..3000 {
        let d = shaped(&mut rng);
        for m in &mods {
            let _ = m.parse(&d);
        }
        let _ = modules::entry_point(&d);
    }
}

#[test]
fn every_module_function_survives_random_files() {
    // A rule set calling the functions with odd arguments, scanned over random files.
    let src = r#"
        import "pe" import "elf" import "math" import "hash" import "dotnet"
        rule r {
            condition:
                pe.imphash() == "x" or pe.imports("a.dll", "b") or pe.imports(/a/, /b/) or pe.exports(3) or
                pe.section_index(".text") == 1 or pe.rva_to_offset(0x1000) == 1 or pe.calculate_checksum() == 1 or
                pe.locale(1) or pe.language(1) or pe.rich_signature.toolid(1) == 1 or pe.is_dll() or
                for any s in pe.signatures : (s.valid_on(1)) or
                elf.import_md5() == "x" or elf.export_md5() == "x" or
                math.entropy(0, filesize) > 9 or math.monte_carlo_pi(0, filesize) > 9 or
                hash.md5(0, filesize) == "x" or hash.crc32(10, 20) == 1 or dotnet.version == "x" or
                entrypoint == 1
        }"#;
    let mut c = Compiler::new();
    assert_eq!(c.add_source("t", src, Syntax::Relaxed), 1);
    let rules = c.build();
    let mut rng = Rng(42);
    for _ in 0..500 {
        let _ = rules.scan(&shaped(&mut rng), &ScanOptions::default());
    }
}

#[test]
fn the_compiler_survives_mangled_rules() {
    let seed = r#"import "pe" rule a : t { meta: k = "v" strings: $a = "abc" nocase wide $h = { 4D 5A ?? [2-4] ( 01 | 02 ) } $r = /a[b-d]+e{2,3}/i condition: ($a and #h > 1) or for any i in (1..#r) : (@r[i] < 10) or pe.imports("k", "f") }"#;
    let mut rng = Rng(7);
    let bytes = seed.as_bytes();
    for _ in 0..3000 {
        let mut text = bytes.to_vec();
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(text.len());
            match rng.below(3) {
                0 => {
                    text.remove(at);
                }
                1 => text.insert(at, b"(){}[]$#@!\"/\\*.,:=0aZ?-~|"[rng.below(25)]),
                _ => {
                    let j = rng.below(text.len());
                    text.swap(at, j);
                }
            }
        }
        let src = String::from_utf8_lossy(&text);
        for syntax in [Syntax::Strict, Syntax::Relaxed] {
            let mut c = Compiler::new();
            c.add_source("t", &src, syntax);
            let _ = c.build().scan(b"xxabcabc\x4d\x5a\0\0\x01", &ScanOptions::default());
        }
    }
}
