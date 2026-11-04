//! A rule's strings compiled to the variants the scanner looks for, each with
//! its atoms.
//!
//! A text string becomes one literal per form it can take: ASCII and wide,
//! every `xor` key, every `base64` alignment. A hex string or regex becomes a
//! pattern split at its best atom: the part from the atom on is matched
//! forwards from each atom hit, the part before it backwards, so a match is
//! found wherever it starts. An atom is at most four bytes, chosen for being
//! rare (no runs of zeros or spaces); a case-insensitive or nibble-masked atom
//! is expanded into every byte string it stands for.

use crate::ast::{Modifiers, StringDef, StringKind};
use crate::matcher::Matcher;
use crate::pattern::{ByteSet, Node};

/// The longest atom: atoms are looked up four bytes at a time.
pub const MAX_ATOM: usize = 4;

/// How many byte strings one atom may expand into (case or nibble masks).
const MAX_EXPANSIONS: usize = 64;

/// How far a regex may reach from its atom, either way, as in YARA.
pub const REGEX_REACH: usize = 4096;

/// How far a hex string may reach: hex jumps can be unbounded.
const HEX_REACH: usize = usize::MAX;

#[derive(Debug)]
pub struct CompiledString {
    pub id: String,
    pub private: bool,
    pub variants: Vec<Variant>,
}

#[derive(Debug)]
pub struct Variant {
    pub kind: VariantKind,
    /// Byte strings whose presence at `hit` means a match may start at
    /// `hit - offset`; empty when the variant has no usable atom and is
    /// tried at every position instead.
    pub atoms: Vec<(Vec<u8>, usize)>,
    pub fullword: Fullword,
}

#[derive(Debug)]
pub enum VariantKind {
    Literal {
        bytes: Vec<u8>,
        nocase: bool,
    },
    /// The pattern split at its atom: `rest` starts at the atom, `prefix`
    /// (reversed) is everything before it.
    Pattern {
        prefix: Option<Node>,
        rest: Node,
        reach: usize,
        first: Option<ByteSet>,
    },
}

/// Whether a match must stand alone as a word, and how its neighbours are read.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Fullword {
    No,
    /// The bytes either side, after undoing the variant's xor key.
    Ascii(u8),
    /// The UTF-16LE characters either side, after undoing the xor key.
    Wide(u8),
}

pub fn compile(def: &StringDef) -> CompiledString {
    let variants = match &def.kind {
        StringKind::Text(text) => text_variants(text, &def.mods),
        StringKind::Hex(node) => vec![pattern_variant(node.clone(), HEX_REACH, Fullword::No)],
        StringKind::Regex(node) => {
            let node = if def.mods.nocase { node.case_folded() } else { node.clone() };
            let mut out = Vec::new();
            if def.mods.ascii || !def.mods.wide {
                out.push(pattern_variant(node.clone(), REGEX_REACH, fullword(&def.mods, false, 0)));
            }
            if def.mods.wide {
                out.push(pattern_variant(node.widened().flatten(), REGEX_REACH, fullword(&def.mods, true, 0)));
            }
            out
        }
    };
    CompiledString { id: def.id.clone(), private: def.mods.private, variants }
}

fn fullword(mods: &Modifiers, wide: bool, key: u8) -> Fullword {
    match (mods.fullword, wide) {
        (false, _) => Fullword::No,
        (true, false) => Fullword::Ascii(key),
        (true, true) => Fullword::Wide(key),
    }
}

fn widen(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|b| [*b, 0]).collect()
}

fn text_variants(text: &[u8], mods: &Modifiers) -> Vec<Variant> {
    let mut forms: Vec<(Vec<u8>, bool)> = Vec::new();
    if mods.base64.is_some() || mods.base64wide.is_some() {
        if let Some(alphabet) = &mods.base64 {
            forms.extend(base64_forms(text, alphabet).into_iter().map(|f| (f, false)));
        }
        if let Some(alphabet) = &mods.base64wide {
            forms.extend(base64_forms(text, alphabet).into_iter().map(|f| (widen(&f), true)));
        }
        return forms.into_iter().map(|(bytes, _)| literal(bytes, false, Fullword::No)).collect();
    }
    if mods.ascii || !mods.wide {
        forms.push((text.to_vec(), false));
    }
    if mods.wide {
        forms.push((widen(text), true));
    }
    let mut out = Vec::new();
    for (bytes, wide) in forms {
        match mods.xor {
            None => out.push(literal(bytes, mods.nocase, fullword(mods, wide, 0))),
            Some((lo, hi)) => {
                for key in lo..=hi {
                    let xored = bytes.iter().map(|b| b ^ key).collect();
                    out.push(literal(xored, false, fullword(mods, wide, key)));
                }
            }
        }
    }
    out
}

/// The base64 encodings `text` can show up as inside a longer encoded
/// stream: one per alignment, keeping only the characters `text` alone decides.
pub fn base64_forms(text: &[u8], alphabet: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for pad in 0..3 {
        let mut input = vec![0u8; pad];
        input.extend_from_slice(text);
        let encoded = encode_base64(&input, alphabet);
        let start = (8 * pad).div_ceil(6);
        let end = 8 * input.len() / 6;
        if end > start {
            out.push(encoded[start..end].to_vec());
        }
    }
    out
}

fn encode_base64(input: &[u8], alphabet: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(alphabet[(n >> (18 - 6 * i) & 63) as usize]);
        }
    }
    out
}

/// How good a byte is as part of an atom: common filler bytes are poor.
fn byte_quality(b: u8) -> i32 {
    match b {
        0x00 => 2,
        0xFF | 0x20 | 0xCC | 0x90 | 0x0A | 0x0D | 0x09 => 8,
        b if b.is_ascii_lowercase() => 16,
        _ => 18,
    }
}

/// The quality of an atom made of these byte sets (one per position).
fn atom_quality(sets: &[ByteSet]) -> i32 {
    let mut q = 0;
    let mut distinct = Vec::new();
    for s in sets {
        let b = s.iter().next().expect("non-empty");
        q += match s.len() {
            1 => byte_quality(b),
            2 => byte_quality(b) - 2,
            _ => 4,
        };
        if !distinct.contains(&b) {
            distinct.push(b);
        }
    }
    // A run of one byte (00 00 00 00) is far commoner than its parts suggest.
    q + 4 * distinct.len() as i32 - if distinct.len() == 1 && sets.len() > 1 { 20 } else { 0 }
}

/// Every byte string the sets stand for (`[aA][bB]` → `ab`, `aB`, `Ab`, `AB`).
fn expand(sets: &[ByteSet]) -> Vec<Vec<u8>> {
    let mut out = vec![Vec::new()];
    for s in sets {
        out = out.into_iter().flat_map(|prefix| s.iter().map(move |b| [prefix.clone(), vec![b]].concat())).collect();
    }
    out
}

fn literal(bytes: Vec<u8>, nocase: bool, fullword: Fullword) -> Variant {
    let sets: Vec<ByteSet> =
        bytes.iter().map(|b| if nocase { ByteSet::one(*b).case_fold() } else { ByteSet::one(*b) }).collect();
    let len = sets.len().min(MAX_ATOM);
    let start = (0..=sets.len() - len)
        .max_by_key(|i| (atom_quality(&sets[*i..*i + len]), std::cmp::Reverse(*i)))
        .expect("non-empty");
    let atoms = expand(&sets[start..start + len]).into_iter().map(|a| (a, start)).collect();
    Variant { kind: VariantKind::Literal { bytes, nocase }, atoms, fullword }
}

/// Split a pattern at its best atom.
fn pattern_variant(node: Node, reach: usize, fullword: Fullword) -> Variant {
    let items = match node {
        Node::Seq(items) => items,
        other => vec![other],
    };
    // The best window of up to four single-byte positions with few expansions.
    let mut best: Option<(i32, usize, usize)> = None;
    for start in 0..items.len() {
        let mut sets = Vec::new();
        let mut expansions = 1usize;
        for item in &items[start..] {
            let Node::Set(s) = item else { break };
            if sets.len() == MAX_ATOM || expansions * s.len() as usize > MAX_EXPANSIONS {
                break;
            }
            expansions *= s.len() as usize;
            sets.push(*s);
        }
        // One position of a wide class (`[a-z]`) filters no better than
        // trying every position whose first byte fits, so it's no atom.
        if sets.is_empty() || (sets.len() == 1 && expansions > 2) {
            continue;
        }
        let q = atom_quality(&sets);
        if best.is_none_or(|(bq, _, _)| q > bq) {
            best = Some((q, start, sets.len()));
        }
    }
    // An alternation or repeat whose every way in starts with a good literal
    // is a candidate too: one atom per way in (`(eval|\\x65val)`).
    let mut best_atoms: Option<Vec<Vec<ByteSet>>> = None;
    for (start, item) in items.iter().enumerate() {
        if matches!(item, Node::Set(_)) {
            continue;
        }
        let Some(ways) = leading(item) else { continue };
        let expansions: usize = ways.iter().map(|w| w.iter().map(|s| s.len() as usize).product::<usize>()).sum();
        if expansions > MAX_ALT_ATOMS || ways.iter().any(|w| w.len() < 2) {
            continue;
        }
        let q = ways.iter().map(|w| atom_quality(w)).min().unwrap_or(0);
        if best.is_none_or(|(bq, _, _)| q > bq) {
            best = Some((q, start, 0));
            best_atoms = Some(ways);
        }
    }
    let first = first_set(&Node::Seq(items.clone()));
    let Some((_, start, len)) = best else {
        return Variant {
            kind: VariantKind::Pattern { prefix: None, rest: Node::Seq(items), reach, first },
            atoms: Vec::new(),
            fullword,
        };
    };
    let atoms = match best_atoms {
        Some(ways) => ways.iter().flat_map(|w| expand(w)).map(|a| (a, 0)).collect(),
        None => {
            let sets: Vec<ByteSet> = items[start..start + len]
                .iter()
                .map(|n| if let Node::Set(s) = n { *s } else { unreachable!() })
                .collect();
            expand(&sets).into_iter().map(|a| (a, 0)).collect()
        }
    };
    let prefix = (start > 0).then(|| Node::Seq(items[..start].to_vec()).reversed());
    let rest = Node::Seq(items[start..].to_vec());
    Variant { kind: VariantKind::Pattern { prefix, rest, reach, first }, atoms, fullword }
}

/// Atoms for one position of an alternation or repeat, across all its branches.
const MAX_ALT_ATOMS: usize = 256;

/// The literal starts (up to four positions) every match of `node` begins
/// with, one list per way into it; `None` when some way in has none.
fn leading(node: &Node) -> Option<Vec<Vec<ByteSet>>> {
    match node {
        Node::Set(s) => Some(vec![vec![*s]]),
        Node::Seq(items) => {
            // A zero-width assertion (`\b`) doesn't move the start.
            let items = &items[items.iter().take_while(|i| matches!(i, Node::Assert(_))).count()..];
            let sets: Vec<ByteSet> =
                items.iter().map_while(|i| if let Node::Set(s) = i { Some(*s) } else { None }).take(MAX_ATOM).collect();
            if sets.is_empty() { items.first().and_then(leading) } else { Some(vec![sets]) }
        }
        Node::Alt(branches) => {
            let mut out = Vec::new();
            for b in branches {
                out.extend(leading(b)?);
            }
            Some(out)
        }
        Node::Repeat { node, min, .. } if *min > 0 => leading(node),
        _ => None,
    }
}

/// The bytes a match must start with, when that's known.
fn first_set(node: &Node) -> Option<ByteSet> {
    match node {
        Node::Set(s) => Some(*s),
        Node::Seq(items) => items.first().and_then(first_set),
        Node::Alt(branches) => {
            branches.iter().try_fold(ByteSet::default(), |acc, b| first_set(b).map(|s| acc.union(s)))
        }
        Node::Repeat { node, min, .. } if *min > 0 => first_set(node),
        _ => None,
    }
}

impl Variant {
    /// Matches `(start, len)` of this variant given an atom hit at `hit`.
    pub fn verify(&self, data: &[u8], hit: usize, offset: usize, out: &mut Vec<(usize, usize)>) {
        let Some(start) = hit.checked_sub(offset) else { return };
        match &self.kind {
            VariantKind::Literal { bytes, nocase } => {
                let Some(window) = data.get(start..start + bytes.len()) else { return };
                let same = if *nocase { window.eq_ignore_ascii_case(bytes) } else { window == bytes.as_slice() };
                if same && self.whole_word(data, start, bytes.len()) {
                    out.push((start, bytes.len()));
                }
            }
            VariantKind::Pattern { prefix, rest, reach, .. } => {
                let Some(end) = Matcher::new(data, start, true, *reach).first(rest, start) else { return };
                let starts = match prefix {
                    None => vec![start],
                    Some(p) => Matcher::new(data, start, false, *reach).all(p, start),
                };
                for s in starts {
                    if self.whole_word(data, s, end - s) {
                        out.push((s, end - s));
                    }
                }
            }
        }
    }

    /// For a variant without atoms: try every position its first byte allows.
    pub fn scan_all(&self, data: &[u8], out: &mut Vec<(usize, usize)>) {
        let first = match &self.kind {
            VariantKind::Pattern { first, .. } => *first,
            VariantKind::Literal { .. } => None,
        };
        for pos in 0..=data.len() {
            if first.is_some_and(|f| data.get(pos).is_none_or(|b| !f.contains(*b))) {
                continue;
            }
            self.verify(data, pos, 0, out);
        }
    }

    fn whole_word(&self, data: &[u8], start: usize, len: usize) -> bool {
        let alnum = |b: u8| b.is_ascii_alphanumeric();
        match self.fullword {
            Fullword::No => true,
            Fullword::Ascii(key) => {
                let before = start.checked_sub(1).map(|i| data[i] ^ key);
                let after = data.get(start + len).map(|b| b ^ key);
                !before.is_some_and(alnum) && !after.is_some_and(alnum)
            }
            Fullword::Wide(key) => {
                let before = start.checked_sub(2).filter(|i| data[i + 1] ^ key == 0).map(|i| data[i] ^ key);
                let end = start + len;
                let after = data.get(end + 1).filter(|z| *z ^ key == 0).and_then(|_| data.get(end)).map(|b| b ^ key);
                !before.is_some_and(alnum) && !after.is_some_and(alnum)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::BASE64_STANDARD;
    use crate::pattern::{Syntax, parse_hex, parse_regex};

    fn def(kind: StringKind, mods: Modifiers) -> StringDef {
        StringDef { id: "a".into(), kind, mods, line: 1 }
    }

    fn find(s: &CompiledString, data: &[u8]) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for v in &s.variants {
            if v.atoms.is_empty() {
                v.scan_all(data, &mut out);
                continue;
            }
            for pos in 0..data.len() {
                for (atom, off) in &v.atoms {
                    if data[pos..].starts_with(atom) {
                        v.verify(data, pos, *off, &mut out);
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    #[test]
    fn text_ascii_wide_and_nocase() {
        let mods = Modifiers { wide: true, ascii: true, nocase: true, ..Default::default() };
        let s = compile(&def(StringKind::Text(b"Hi".to_vec()), mods));
        assert_eq!(s.variants.len(), 2);
        assert_eq!(find(&s, b"xhI H\0i\0"), vec![(1, 2), (4, 4)]);
        let plain = compile(&def(StringKind::Text(b"Hi".to_vec()), Modifiers::default()));
        assert_eq!(find(&plain, b"hi Hi"), vec![(3, 2)]);
    }

    #[test]
    fn xor_finds_every_key_and_fullword_decodes_neighbours() {
        let mods = Modifiers { xor: Some((0, 255)), fullword: true, ..Default::default() };
        let s = compile(&def(StringKind::Text(b"evil".to_vec()), mods));
        assert_eq!(s.variants.len(), 256);
        let key = 0x41;
        let mut data: Vec<u8> = b" evil ".iter().map(|b| b ^ key).collect();
        assert_eq!(find(&s, &data), vec![(1, 4)]);
        // "xevil" under the same key isn't a whole word.
        data = b"xevil ".iter().map(|b| b ^ key).collect();
        assert!(find(&s, &data).is_empty());
    }

    #[test]
    fn base64_alignments() {
        let forms = base64_forms(b"This program cannot", BASE64_STANDARD);
        assert_eq!(forms.len(), 3);
        assert_eq!(forms[0], b"VGhpcyBwcm9ncmFtIGNhbm5vd");
        assert_eq!(forms[1], b"RoaXMgcHJvZ3JhbSBjYW5ub3");
        assert_eq!(forms[2], b"UaGlzIHByb2dyYW0gY2Fubm90");
        let mods = Modifiers { base64: Some(BASE64_STANDARD.to_vec()), ..Default::default() };
        let s = compile(&def(StringKind::Text(b"This program cannot".to_vec()), mods));
        assert_eq!(find(&s, b"xxVGhpcyBwcm9ncmFtIGNhbm5vdA==").len(), 1);
        let wide = Modifiers { base64wide: Some(BASE64_STANDARD.to_vec()), ..Default::default() };
        let s = compile(&def(StringKind::Text(b"abc".to_vec()), wide));
        assert_eq!(find(&s, &widen(b"YWJj")).len(), 1);
    }

    #[test]
    fn wide_fullword() {
        let mods = Modifiers { wide: true, fullword: true, ..Default::default() };
        let s = compile(&def(StringKind::Text(b"ab".to_vec()), mods));
        assert_eq!(find(&s, &widen(b" ab ")), vec![(2, 4)]);
        assert!(find(&s, &widen(b"xab")).is_empty());
    }

    #[test]
    fn hex_strings_with_prefixes_find_every_start() {
        let s = compile(&def(StringKind::Hex(parse_hex("?? [0-2] 41 42 43 44", 1).unwrap()), Modifiers::default()));
        // The atom is ABCD; the prefix (one byte, then 0-2 more) can start at 1, 2 or 3.
        assert_eq!(find(&s, b"xxxxABCD"), vec![(1, 7), (2, 6), (3, 5)]);
        let masked = compile(&def(StringKind::Hex(parse_hex("4? 5A", 1).unwrap()), Modifiers::default()));
        assert_eq!(find(&masked, b"\x4dZ\x5dZ"), vec![(0, 2)]);
    }

    #[test]
    fn regexes_with_and_without_atoms() {
        let re = |s: &str| parse_regex(s.as_bytes(), false, false, Syntax::Relaxed, 1).unwrap();
        let s = compile(&def(StringKind::Regex(re("[0-9]+abc")), Modifiers::default()));
        assert_eq!(find(&s, b"x12abc"), vec![(1, 5), (2, 4)]);
        let wide = compile(&def(StringKind::Regex(re("ab")), Modifiers { wide: true, ..Default::default() }));
        assert_eq!(find(&wide, b"a\0b\0"), vec![(0, 4)]);
        let nocase = compile(&def(
            StringKind::Regex(re("ab")),
            Modifiers { nocase: true, fullword: true, ..Default::default() },
        ));
        assert_eq!(find(&nocase, b"AB xAB"), vec![(0, 2)]);
        // No position is a good atom: tried everywhere its first byte allows.
        let none = compile(&def(StringKind::Regex(re("[a-z][0-9][a-z][0-9][a-z]")), Modifiers::default()));
        assert!(none.variants[0].atoms.is_empty());
        assert_eq!(find(&none, b"..a1b2c.."), vec![(2, 5)]);
    }

    #[test]
    fn alternations_and_repeats_give_atoms() {
        let re = |s: &str| parse_regex(s.as_bytes(), false, false, Syntax::Relaxed, 1).unwrap();
        let s = compile(&def(StringKind::Regex(re(r"(e|\\x65)(\\x76|\\118)al")), Modifiers::default()));
        assert!(!s.variants[0].atoms.is_empty());
        assert_eq!(find(&s, br"x\x65\118al"), vec![(1, 10)]);
        let stack = compile(&def(StringKind::Regex(re(r"(\xC6\x45.{2}){3}")), Modifiers::default()));
        assert_eq!(stack.variants[0].atoms.len(), 1);
        assert_eq!(find(&stack, b"\xC6\x45ab\xC6\x45cd\xC6\x45ef"), vec![(0, 12)]);
        assert!(leading(&Node::Assert(crate::pattern::Assert::Start)).is_none());
        let bounded = compile(&def(StringKind::Regex(re(r"(\beval\(|\bassert\()")), Modifiers::default()));
        assert!(!bounded.variants[0].atoms.is_empty());
        assert_eq!(find(&bounded, b"x eval( xeval("), vec![(2, 5)]);
    }

    #[test]
    fn atoms_avoid_filler() {
        let s = compile(&def(StringKind::Text(b"\0\0\0\0\0evil".to_vec()), Modifiers::default()));
        assert_eq!(s.variants[0].atoms, vec![(b"evil".to_vec(), 5)]);
        assert_eq!(expand(&[ByteSet::one(b'a').case_fold(), ByteSet::one(b'b')]).len(), 2);
        assert_eq!(first_set(&Node::Assert(crate::pattern::Assert::Start)), None);
    }
}
