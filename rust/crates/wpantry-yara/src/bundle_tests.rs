use crate::{Compiler, ScanOptions, Syntax};

/// Rules that use every kind of string, modifier and condition the format
/// writes, one of which doesn't compile.
const RULES: &str = r#"
import "math"
import "hash"

private rule tiny { condition: filesize < 4096 }

global rule not_empty { condition: filesize > 0 }

rule Linux_Miner_Text : miner linux {
    meta:
        author = "Example Security"
        score = 80
        hit = true
        ratio = -3
    strings:
        $a = "stratum+tcp" nocase wide ascii fullword
        $b = "xmrig" xor(1-3)
        $c = "pool" base64
        $d = { 4D 5A [2-4] ( 90 | 0? 00 ) ?? 50 }
        $e = /c3pool\.(com|org)[0-9]{1,3}/is
        $f = "plain" private
    condition:
        tiny and (any of ($a, $b, $c) or #d > 0 or $e at 0 or $e in (0..100))
        and !a[1] >= 0 and @a[1] >= 0 and math.entropy(0, filesize) >= 0.0
}

rule Windows_Trojan_Loops {
    strings:
        $x = "abc"
        $y = "xyz"
    condition:
        uint16(0) == 0x5A4D and
        (for any i in (1..#x) : (@x[i] < 10) or for all of them : (# > 0) or
         2 of them or 50% of them or none of ($y) or
         for any s in ("a", "b") : (s == "a") or
         with n = #x + 1 : (n > 1 and n % 2 == 0 and -n < 0 and ~n != 0 and n << 1 > n) or
         hash.md5(0, 3) == "x" or "Abc" icontains "b" or defined filesize or
         Linux_Miner_Text or any of (Linux_*) or 1 of (true, false))
}

rule broken { condition: no_such_module.x }
"#;

fn compiled(rules: &str) -> (crate::Rules, Vec<u8>) {
    let mut c = Compiler::new();
    c.record();
    c.add_source("t", rules, Syntax::Relaxed);
    let bundle = c.bundle().expect("recording");
    (c.build(), bundle)
}

fn hits(r: &crate::Rules, data: &[u8]) -> Vec<(String, Vec<(String, usize)>)> {
    r.scan(data, &ScanOptions::default()).matches.into_iter().map(|h| (h.rule, h.strings)).collect()
}

#[test]
fn a_bundle_reads_back_to_the_same_rules() {
    let (from_source, bundle) = compiled(RULES);
    let mut c = Compiler::new();
    assert_eq!(c.add_bundle(&bundle), Ok(4));
    let from_bundle = c.build();
    assert_eq!(from_bundle.stats(), from_source.stats());
    assert_eq!(from_bundle.rejected, from_source.rejected, "what didn't compile is kept");
    assert_eq!(from_bundle.rejected.len(), 1);
    for (a, b) in from_source.rules().iter().zip(from_bundle.rules()) {
        assert_eq!(
            (&a.name, a.os, a.category, a.score, &a.namespace, &a.tags, &a.meta, a.private, a.global, &a.strings),
            (&b.name, b.os, b.category, b.score, &b.namespace, &b.tags, &b.meta, b.private, b.global, &b.strings)
        );
    }
    let wide: Vec<u8> = "STRATUM+TCP".bytes().flat_map(|b| [b, 0]).collect();
    let xored: Vec<u8> = b"xmrig".iter().map(|b| b ^ 2).collect();
    let samples: Vec<Vec<u8>> = vec![
        b"MZ\x90\x00abc..abc..xyz".to_vec(),
        [b"c3pool.org42 ".as_slice(), &wide].concat(),
        [b"MZ..".as_slice(), &xored, b" cG9vbA== plain"].concat(),
        b"MZ\x00\x00\x01\x02\x00\x00\x50abc".to_vec(),
        b"nothing here".to_vec(),
        Vec::new(),
    ];
    for data in &samples {
        assert_eq!(hits(&from_bundle, data), hits(&from_source, data), "{:?}", String::from_utf8_lossy(data));
    }
    assert!(samples.iter().any(|d| !hits(&from_source, d).is_empty()), "the samples hit something");
    // Written again from the bundle, the same bytes.
    let mut again = Compiler::new();
    again.record();
    again.add_bundle(&bundle).unwrap();
    let rewritten = again.bundle().unwrap();
    assert!(rewritten == bundle, "{} bytes again, {} first", rewritten.len(), bundle.len());
}

#[test]
fn a_filter_applies_to_a_bundle_too() {
    let (_, bundle) = compiled(RULES);
    let mut c = Compiler::new();
    c.set_filter(|os, _| os != crate::Os::Windows);
    assert_eq!(c.add_bundle(&bundle), Ok(3));
    assert_eq!(c.build().stats().skipped, 1);
}

#[test]
fn a_bundle_that_doesnt_read_back_whole_is_refused() {
    let (_, bundle) = compiled(RULES);
    let refused = |b: &[u8]| Compiler::new().add_bundle(b).is_err();
    assert!(refused(b""));
    assert!(refused(b"WPYB"));
    assert!(refused(&[b"XXXX".as_slice(), &bundle[4..]].concat()), "another magic");
    let mut newer = bundle.clone();
    newer[4] = newer[4].wrapping_add(1);
    assert!(refused(&newer), "another format");
    for cut in [9, bundle.len() / 3, bundle.len() / 2, bundle.len() - 1] {
        assert!(refused(&bundle[..cut]), "cut at {cut}");
    }
    assert!(refused(&[bundle.as_slice(), &[9]].concat()), "a record of no kind");
    // Every single-byte change either reads back or is refused: never a panic.
    for i in 8..bundle.len() {
        let mut b = bundle.clone();
        b[i] ^= 0xff;
        let _ = Compiler::new().add_bundle(&b);
    }
}

#[test]
fn a_bundle_needs_its_modules() {
    let src = "import \"math\" rule r { condition: math.entropy(0, filesize) > 1.0 }";
    let (_, bundle) = compiled(src);
    assert_eq!(Compiler::new().add_bundle(&bundle), Ok(1));
    // The same rule importing a module this compiler doesn't have.
    let at = bundle.windows(4).position(|w| w == b"math").expect("its import");
    let mut other = bundle.clone();
    other[at + 1] = b'x';
    let err = Compiler::new().add_bundle(&other).unwrap_err();
    assert_eq!(err.0, "no module mxth");
}

/// The real rules (YARA Forge `full` and Elastic's, from a rules directory
/// in `RULES_DIR`): compiled from source and from their bundle, with time
/// and size. `cargo test --release -p wpantry-yara real_rules -- --ignored --nocapture`.
#[test]
#[ignore]
fn real_rules_bundle_round_trip() {
    let dir = std::env::var("RULES_DIR").expect("RULES_DIR");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yar"))
        .collect();
    files.sort();
    let t = std::time::Instant::now();
    let mut c = Compiler::new();
    c.record();
    for f in &files {
        c.add_source(&f.file_stem().unwrap().to_string_lossy(), &std::fs::read_to_string(f).unwrap(), Syntax::Relaxed);
    }
    let bundle = c.bundle().unwrap();
    let source = c.build();
    println!("from source: {:?}, {:?}; bundle {} MB", t.elapsed(), source.stats(), bundle.len() >> 20);
    let t = std::time::Instant::now();
    let mut c = Compiler::new();
    c.add_bundle(&bundle).unwrap();
    let back = c.build();
    println!("from bundle: {:?}, {:?}", t.elapsed(), back.stats());
    assert_eq!(back.stats(), source.stats());
    assert_eq!(back.rejected.len(), source.rejected.len());
}
