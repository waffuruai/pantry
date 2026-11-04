//! The byte-pattern tree hex strings and regular expressions both parse to.
//!
//! Every position a pattern can match is a [`ByteSet`]: a literal is a set of
//! one byte, `?A` in hex is the sixteen bytes ending in `A`, `[a-z]` is a
//! class, `.` is everything but `\n` (or everything, with `s`). Sequences,
//! alternations and bounded repeats complete the tree, so one matcher
//! ([`crate::matcher`]) serves both syntaxes, and a hex jump `[2-4]` is just a
//! repeat of the full set.

use crate::Error;

/// A set of bytes, one bit each.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct ByteSet([u64; 4]);

impl ByteSet {
    pub const FULL: ByteSet = ByteSet([u64::MAX; 4]);

    pub fn one(b: u8) -> Self {
        let mut s = ByteSet::default();
        s.insert(b);
        s
    }

    pub fn range(lo: u8, hi: u8) -> Self {
        let mut s = ByteSet::default();
        for b in lo..=hi {
            s.insert(b);
        }
        s
    }

    pub fn insert(&mut self, b: u8) {
        self.0[(b >> 6) as usize] |= 1 << (b & 63);
    }

    pub fn contains(&self, b: u8) -> bool {
        self.0[(b >> 6) as usize] & (1 << (b & 63)) != 0
    }

    pub fn len(&self) -> u32 {
        self.0.iter().map(|w| w.count_ones()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|w| *w == 0)
    }

    pub fn union(mut self, other: ByteSet) -> Self {
        for (a, b) in self.0.iter_mut().zip(other.0) {
            *a |= b;
        }
        self
    }

    pub fn complement(mut self) -> Self {
        for w in &mut self.0 {
            *w = !*w;
        }
        self
    }

    /// The set with every ASCII letter's other case added.
    pub fn case_fold(self) -> Self {
        let mut out = self;
        for b in self.iter() {
            if b.is_ascii_alphabetic() {
                out.insert(b ^ 0x20);
            }
        }
        out
    }

    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        (0..=255u8).filter(|b| self.contains(*b))
    }

    /// The bytes `b` with `b & mask == value & mask`: a hex nibble wildcard.
    pub fn masked(value: u8, mask: u8) -> Self {
        let mut s = ByteSet::default();
        for b in 0..=255u8 {
            if b & mask == value & mask {
                s.insert(b);
            }
        }
        s
    }
}

/// A zero-width assertion in a regular expression.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Assert {
    /// `^`: the start of the data.
    Start,
    /// `$`: the end of the data.
    End,
    /// `\b`
    WordBoundary,
    /// `\B`
    NotWordBoundary,
}

#[derive(Clone, PartialEq, Debug)]
pub enum Node {
    Set(ByteSet),
    Seq(Vec<Node>),
    Alt(Vec<Node>),
    Repeat { node: Box<Node>, min: u32, max: Option<u32>, greedy: bool },
    Assert(Assert),
}

impl Node {
    /// Nested sequences flattened into one, so the top level of a pattern is
    /// the list of its positions (atoms are chosen from it).
    pub fn flatten(self) -> Node {
        match self {
            Node::Seq(items) => {
                let mut out = Vec::new();
                for item in items {
                    match item.flatten() {
                        Node::Seq(inner) => out.extend(inner),
                        other => out.push(other),
                    }
                }
                if out.len() == 1 { out.pop().expect("one") } else { Node::Seq(out) }
            }
            Node::Alt(items) => Node::Alt(items.into_iter().map(Node::flatten).collect()),
            Node::Repeat { node, min, max, greedy } => {
                Node::Repeat { node: Box::new(node.flatten()), min, max, greedy }
            }
            other => other,
        }
    }

    /// The same pattern read right to left, for matching backwards from an atom.
    pub fn reversed(&self) -> Node {
        match self {
            Node::Seq(items) => Node::Seq(items.iter().rev().map(Node::reversed).collect()),
            Node::Alt(items) => Node::Alt(items.iter().map(Node::reversed).collect()),
            Node::Repeat { node, min, max, greedy } => {
                Node::Repeat { node: Box::new(node.reversed()), min: *min, max: *max, greedy: *greedy }
            }
            Node::Set(_) | Node::Assert(_) => self.clone(),
        }
    }

    /// The pattern as UTF-16LE text: every byte position followed by a zero.
    pub fn widened(&self) -> Node {
        match self {
            Node::Set(s) => Node::Seq(vec![Node::Set(*s), Node::Set(ByteSet::one(0))]),
            Node::Seq(items) => Node::Seq(items.iter().map(Node::widened).collect()),
            Node::Alt(items) => Node::Alt(items.iter().map(Node::widened).collect()),
            Node::Repeat { node, min, max, greedy } => {
                Node::Repeat { node: Box::new(node.widened()), min: *min, max: *max, greedy: *greedy }
            }
            Node::Assert(_) => self.clone(),
        }
    }

    /// Every letter matched in either case.
    pub fn case_folded(&self) -> Node {
        match self {
            Node::Set(s) => Node::Set(s.case_fold()),
            Node::Seq(items) => Node::Seq(items.iter().map(Node::case_folded).collect()),
            Node::Alt(items) => Node::Alt(items.iter().map(Node::case_folded).collect()),
            Node::Repeat { node, min, max, greedy } => {
                Node::Repeat { node: Box::new(node.case_folded()), min: *min, max: *max, greedy: *greedy }
            }
            Node::Assert(_) => self.clone(),
        }
    }
}

/// Upper bound on a hex jump or regex repeat count, as YARA's.
const MAX_REPEAT: u32 = 1 << 20;

// ---------------------------------------------------------------- hex strings

/// Parse the body of a hex string (`4D 5A ?? [2-4] ( 01 | 02 ) ~00 ?F`).
pub fn parse_hex(body: &str, line: usize) -> Result<Node, Error> {
    let err = |msg: String| Error::Syntax { line, msg: format!("hex string: {msg}") };
    let chars: Vec<char> = body.chars().filter(|c| !c.is_whitespace()).collect();
    let mut pos = 0;
    let node = hex_alt(&chars, &mut pos, 0, &err)?;
    if pos != chars.len() {
        return Err(err(format!("unexpected {:?}", chars[pos])));
    }
    let node = node.flatten();
    let items = match &node {
        Node::Seq(items) => items.as_slice(),
        other => std::slice::from_ref(other),
    };
    if matches!(items.first(), Some(Node::Repeat { .. })) || matches!(items.last(), Some(Node::Repeat { .. })) {
        return Err(err("a hex string can't start or end with a jump".into()));
    }
    Ok(node)
}

fn hex_alt(chars: &[char], pos: &mut usize, depth: usize, err: &dyn Fn(String) -> Error) -> Result<Node, Error> {
    let mut branches = vec![hex_seq(chars, pos, depth, err)?];
    while chars.get(*pos) == Some(&'|') {
        if depth == 0 {
            return Err(err("`|` outside parentheses".into()));
        }
        *pos += 1;
        branches.push(hex_seq(chars, pos, depth, err)?);
    }
    Ok(if branches.len() == 1 { branches.pop().expect("one") } else { Node::Alt(branches) })
}

fn hex_seq(chars: &[char], pos: &mut usize, depth: usize, err: &dyn Fn(String) -> Error) -> Result<Node, Error> {
    let mut items = Vec::new();
    while let Some(&c) = chars.get(*pos) {
        match c {
            '|' | ')' => break,
            '(' => {
                *pos += 1;
                let inner = hex_alt(chars, pos, depth + 1, err)?;
                if chars.get(*pos) != Some(&')') {
                    return Err(err("unclosed `(`".into()));
                }
                *pos += 1;
                items.push(inner);
            }
            '[' => {
                *pos += 1;
                let end = chars[*pos..].iter().position(|c| *c == ']').ok_or_else(|| err("unclosed `[`".into()))?;
                let text: String = chars[*pos..*pos + end].iter().collect();
                *pos += end + 1;
                let (min, max) = hex_jump(&text).ok_or_else(|| err(format!("bad jump [{text}]")))?;
                items.push(Node::Repeat { node: Box::new(Node::Set(ByteSet::FULL)), min, max, greedy: false });
            }
            '~' => {
                *pos += 1;
                let set = hex_byte(chars, pos, err)?;
                items.push(Node::Set(set.complement()));
            }
            _ => items.push(Node::Set(hex_byte(chars, pos, err)?)),
        }
    }
    if items.is_empty() {
        return Err(err("empty alternative or string".into()));
    }
    Ok(Node::Seq(items))
}

/// One byte: two hex digits, either of which may be `?`.
fn hex_byte(chars: &[char], pos: &mut usize, err: &dyn Fn(String) -> Error) -> Result<ByteSet, Error> {
    let pair = chars.get(*pos..*pos + 2).ok_or_else(|| err("odd number of hex digits".into()))?;
    *pos += 2;
    let nibble = |c: char| if c == '?' { Some((0u8, 0u8)) } else { c.to_digit(16).map(|d| (d as u8, 0xFu8)) };
    let (hi, hi_mask) = nibble(pair[0]).ok_or_else(|| err(format!("bad hex digit {:?}", pair[0])))?;
    let (lo, lo_mask) = nibble(pair[1]).ok_or_else(|| err(format!("bad hex digit {:?}", pair[1])))?;
    Ok(ByteSet::masked(hi << 4 | lo, hi_mask << 4 | lo_mask))
}

/// `[n]`, `[n-m]`, `[n-]`, `[-]`; bounds may be hex or octal, as yara-x allows.
fn hex_jump(text: &str) -> Option<(u32, Option<u32>)> {
    let num = |s: &str| -> Option<u32> {
        let s = s.trim();
        let v = if let Some(h) = s.strip_prefix("0x") {
            u32::from_str_radix(h, 16).ok()?
        } else if let Some(o) = s.strip_prefix("0o") {
            u32::from_str_radix(o, 8).ok()?
        } else {
            s.parse().ok()?
        };
        (v <= MAX_REPEAT).then_some(v)
    };
    match text.split_once('-') {
        None => num(text).map(|n| (n, Some(n))),
        Some((lo, hi)) => {
            let min = if lo.trim().is_empty() { 0 } else { num(lo)? };
            let max = if hi.trim().is_empty() { None } else { Some(num(hi)?) };
            if max.is_some_and(|m| m < min) {
                return None;
            }
            Some((min, max))
        }
    }
}

// ------------------------------------------------------- regular expressions

/// How strictly a regex is read: yara-x's rules for our own rules, classic
/// YARA's for fetched ones.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Syntax {
    /// An unescaped `{` that starts no repeat, and an unknown escape, are errors.
    Strict,
    /// Both are literal characters, as in classic YARA.
    Relaxed,
}

struct Re<'a> {
    src: &'a [u8],
    pos: usize,
    dotall: bool,
    syntax: Syntax,
    line: usize,
}

/// Parse a regex body (between the slashes). `nocase` folds every letter.
pub fn parse_regex(src: &[u8], nocase: bool, dotall: bool, syntax: Syntax, line: usize) -> Result<Node, Error> {
    let mut re = Re { src, pos: 0, dotall, syntax, line };
    let node = re.alt()?;
    if re.pos != src.len() {
        return Err(re.err("unbalanced `)`"));
    }
    let node = if nocase { node.case_folded() } else { node };
    Ok(node.flatten())
}

impl Re<'_> {
    fn err(&self, msg: &str) -> Error {
        Error::Syntax { line: self.line, msg: format!("regex: {msg}") }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn alt(&mut self) -> Result<Node, Error> {
        let mut branches = vec![self.seq()?];
        while self.peek() == Some(b'|') {
            self.pos += 1;
            branches.push(self.seq()?);
        }
        Ok(if branches.len() == 1 { branches.pop().expect("one") } else { Node::Alt(branches) })
    }

    fn seq(&mut self) -> Result<Node, Error> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == b'|' || c == b')' {
                break;
            }
            let atom = self.atom()?;
            items.push(self.quantified(atom)?);
        }
        Ok(Node::Seq(items))
    }

    /// The repeat after an atom, if any.
    fn quantified(&mut self, atom: Node) -> Result<Node, Error> {
        let (min, max) = match self.peek() {
            Some(b'*') => {
                self.pos += 1;
                (0, None)
            }
            Some(b'+') => {
                self.pos += 1;
                (1, None)
            }
            Some(b'?') => {
                self.pos += 1;
                (0, Some(1))
            }
            Some(b'{') => match self.braces() {
                Some(bounds) => bounds,
                None => return Ok(atom),
            },
            _ => return Ok(atom),
        };
        if matches!(atom, Node::Assert(_)) {
            return Err(self.err("nothing to repeat"));
        }
        let greedy = if self.peek() == Some(b'?') {
            self.pos += 1;
            false
        } else {
            true
        };
        Ok(Node::Repeat { node: Box::new(atom), min, max, greedy })
    }

    /// `{n}`, `{n,}`, `{,m}`, `{n,m}` at the cursor; `None` (cursor unmoved)
    /// when the brace starts no repeat, in which case it is read as a literal.
    fn braces(&mut self) -> Option<(u32, Option<u32>)> {
        let rest = &self.src[self.pos + 1..];
        let end = rest.iter().position(|c| *c == b'}')?;
        let inner = std::str::from_utf8(&rest[..end]).ok()?;
        let num = |s: &str| s.parse::<u32>().ok().filter(|n| *n <= MAX_REPEAT);
        let bounds = match inner.split_once(',') {
            None => {
                let n = num(inner)?;
                (n, Some(n))
            }
            Some((lo, hi)) => {
                if lo.is_empty() && hi.is_empty() {
                    return None;
                }
                let min = if lo.is_empty() { 0 } else { num(lo)? };
                let max = if hi.is_empty() { None } else { Some(num(hi)?) };
                if max.is_some_and(|m| m < min) {
                    return None;
                }
                (min, max)
            }
        };
        self.pos += end + 2;
        Some(bounds)
    }

    fn atom(&mut self) -> Result<Node, Error> {
        let c = self.peek().expect("caller checked");
        self.pos += 1;
        Ok(match c {
            b'(' => {
                if self.src[self.pos..].starts_with(b"?:") {
                    self.pos += 2;
                }
                let inner = self.alt()?;
                if self.peek() != Some(b')') {
                    return Err(self.err("unclosed `(`"));
                }
                self.pos += 1;
                inner
            }
            b'.' => Node::Set(if self.dotall { ByteSet::FULL } else { ByteSet::one(b'\n').complement() }),
            b'^' => Node::Assert(Assert::Start),
            b'$' => Node::Assert(Assert::End),
            b'[' => Node::Set(self.class()?),
            b'\\' => self.escape(false)?,
            b'*' | b'+' | b'?' => return Err(self.err("nothing to repeat")),
            b'{' => {
                if self.syntax == Syntax::Strict {
                    return Err(self.err("unescaped `{` (write `\\{`)"));
                }
                Node::Set(ByteSet::one(b'{'))
            }
            other => Node::Set(ByteSet::one(other)),
        })
    }

    /// After a `\`. Inside a class, `\b` is a backspace and assertions are errors.
    fn escape(&mut self, in_class: bool) -> Result<Node, Error> {
        let Some(c) = self.peek() else { return Err(self.err("trailing `\\`")) };
        self.pos += 1;
        let digit = ByteSet::range(b'0', b'9');
        let word = digit.union(ByteSet::range(b'a', b'z')).union(ByteSet::range(b'A', b'Z')).union(ByteSet::one(b'_'));
        let space = [b' ', b'\t', b'\n', b'\r', 0x0b, 0x0c]
            .into_iter()
            .fold(ByteSet::default(), |s, b| s.union(ByteSet::one(b)));
        Ok(Node::Set(match c {
            b'd' => digit,
            b'D' => digit.complement(),
            b'w' => word,
            b'W' => word.complement(),
            b's' => space,
            b'S' => space.complement(),
            b'b' if in_class => ByteSet::one(0x08),
            b'b' => return Ok(Node::Assert(Assert::WordBoundary)),
            b'B' if !in_class => return Ok(Node::Assert(Assert::NotWordBoundary)),
            b'n' => ByteSet::one(b'\n'),
            b't' => ByteSet::one(b'\t'),
            b'r' => ByteSet::one(b'\r'),
            b'f' => ByteSet::one(0x0c),
            b'v' => ByteSet::one(0x0b),
            b'a' => ByteSet::one(0x07),
            b'0' => ByteSet::one(0),
            b'x' => {
                let hex = self.src.get(self.pos..self.pos + 2).ok_or_else(|| self.err("bad \\x escape"))?;
                let b = std::str::from_utf8(hex)
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or_else(|| self.err("bad \\x escape"))?;
                self.pos += 2;
                ByteSet::one(b)
            }
            c if !c.is_ascii_alphanumeric() => ByteSet::one(c),
            c if self.syntax == Syntax::Relaxed => ByteSet::one(c),
            c => return Err(self.err(&format!("unknown escape \\{}", c as char))),
        }))
    }

    /// The body of `[...]` after the `[`.
    fn class(&mut self) -> Result<ByteSet, Error> {
        let negate = self.peek() == Some(b'^');
        if negate {
            self.pos += 1;
        }
        let mut set = ByteSet::default();
        let mut first = true;
        loop {
            let Some(c) = self.peek() else { return Err(self.err("unclosed `[`")) };
            if c == b']' && !first {
                self.pos += 1;
                break;
            }
            first = false;
            let lo = self.class_item()?;
            let is_range = self.peek() == Some(b'-') && self.src.get(self.pos + 1).is_some_and(|c| *c != b']');
            match (lo, is_range) {
                (Ok(lo), true) => {
                    self.pos += 1;
                    let Ok(hi) = self.class_item()? else { return Err(self.err("bad class range")) };
                    if hi < lo {
                        return Err(self.err("bad class range"));
                    }
                    set = set.union(ByteSet::range(lo, hi));
                }
                (Ok(b), false) => set.insert(b),
                (Err(class), _) => set = set.union(class),
            }
        }
        Ok(if negate { set.complement() } else { set })
    }

    /// One class member: a single byte (`Ok`) or a shorthand class like `\w` (`Err`).
    fn class_item(&mut self) -> Result<Result<u8, ByteSet>, Error> {
        let c = self.peek().ok_or_else(|| self.err("unclosed `[`"))?;
        self.pos += 1;
        if c != b'\\' {
            return Ok(Ok(c));
        }
        match self.escape(true)? {
            Node::Set(s) if s.len() == 1 => Ok(Ok(s.iter().next().expect("one"))),
            Node::Set(s) => Ok(Err(s)),
            _ => Err(self.err("assertion in a class")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(bytes: &[u8]) -> Node {
        let mut s = ByteSet::default();
        for b in bytes {
            s.insert(*b);
        }
        Node::Set(s)
    }

    #[test]
    fn byteset_basics() {
        let s = ByteSet::range(b'a', b'c');
        assert_eq!(s.len(), 3);
        assert!(s.contains(b'b') && !s.contains(b'd'));
        assert_eq!(s.case_fold().len(), 6);
        assert_eq!(s.complement().len(), 253);
        assert!(ByteSet::default().is_empty());
        assert_eq!(ByteSet::masked(0x4A, 0x0F).len(), 16);
        assert!(ByteSet::masked(0x4A, 0x0F).contains(0x7A));
    }

    #[test]
    fn hex_strings_parse_to_sets_jumps_and_alternatives() {
        let n = parse_hex("4D 5A ?? ?F [2-4] ( 01 | 02 03 ) ~00 [3] [5-]", 1).unwrap_err();
        assert!(n.to_string().contains("end with a jump"));
        let n = parse_hex("4D ?? [2-4] ( 01 | 02 03 ) ~00", 1).unwrap();
        let Node::Seq(items) = n else { panic!() };
        assert_eq!(items[0], set(&[0x4D]));
        assert_eq!(items[1], Node::Set(ByteSet::FULL));
        assert_eq!(
            items[2],
            Node::Repeat { node: Box::new(Node::Set(ByteSet::FULL)), min: 2, max: Some(4), greedy: false }
        );
        assert!(matches!(&items[3], Node::Alt(b) if b.len() == 2));
        let Node::Set(not0) = items[4] else { panic!() };
        assert_eq!(not0.len(), 255);
    }

    #[test]
    fn hex_jump_forms() {
        assert_eq!(hex_jump("4"), Some((4, Some(4))));
        assert_eq!(hex_jump("2-"), Some((2, None)));
        assert_eq!(hex_jump("-"), Some((0, None)));
        assert_eq!(hex_jump("0x10-0o20"), Some((16, Some(16))));
        assert_eq!(hex_jump("5-2"), None);
        assert_eq!(hex_jump("x"), None);
    }

    #[test]
    fn hex_errors() {
        for bad in ["4", "4G", "( 01", "01 | 02", "( )", "[2-4] 01", "01 [2", "01 )"] {
            assert!(parse_hex(bad, 1).is_err(), "{bad}");
        }
    }

    #[test]
    fn regexes_parse_classes_repeats_and_escapes() {
        let n = parse_regex(br"ab+[c-e\d]{2,3}?\x41.\b", false, false, Syntax::Strict, 1).unwrap();
        let Node::Seq(items) = n else { panic!() };
        assert_eq!(items[0], set(b"a"));
        assert!(matches!(&items[1], Node::Repeat { min: 1, max: None, greedy: true, .. }));
        assert!(matches!(&items[2], Node::Repeat { min: 2, max: Some(3), greedy: false, .. }));
        assert_eq!(items[3], set(b"A"));
        let Node::Set(dot) = items[4] else { panic!() };
        assert!(!dot.contains(b'\n'));
        assert_eq!(items[5], Node::Assert(Assert::WordBoundary));
    }

    #[test]
    fn regex_flags() {
        assert_eq!(parse_regex(b"a", true, false, Syntax::Strict, 1).unwrap(), set(b"aA"));
        let Node::Set(dot) = parse_regex(b".", false, true, Syntax::Strict, 1).unwrap() else { panic!() };
        assert_eq!(dot, ByteSet::FULL);
        assert!(matches!(parse_regex(b"a|b", false, false, Syntax::Strict, 1).unwrap(), Node::Alt(_)));
        assert!(matches!(parse_regex(b"(?:a)", false, false, Syntax::Strict, 1).unwrap(), Node::Set(_)));
    }

    #[test]
    fn strict_and_relaxed_differ_on_braces_and_escapes() {
        assert!(parse_regex(b"a{x", false, false, Syntax::Strict, 1).is_err());
        assert!(parse_regex(b"a{x", false, false, Syntax::Relaxed, 1).is_ok());
        assert!(parse_regex(br"\g", false, false, Syntax::Strict, 1).is_err());
        assert_eq!(parse_regex(br"\g", false, false, Syntax::Relaxed, 1).unwrap(), set(b"g"));
        // A brace that is a repeat is fine in both.
        assert!(parse_regex(b"a{2}", false, false, Syntax::Strict, 1).is_ok());
    }

    #[test]
    fn classes() {
        assert_eq!(
            parse_regex(b"[^a]", false, false, Syntax::Strict, 1).unwrap(),
            Node::Set(ByteSet::one(b'a').complement())
        );
        assert_eq!(parse_regex(b"[]a]", false, false, Syntax::Strict, 1).unwrap(), set(b"]a"));
        assert_eq!(parse_regex(b"[a-]", false, false, Syntax::Strict, 1).unwrap(), set(b"a-"));
        let Node::Set(w) = parse_regex(br"[\w.]", false, false, Syntax::Strict, 1).unwrap() else { panic!() };
        assert_eq!(w.len(), 64);
        assert_eq!(parse_regex(br"[\b]", false, false, Syntax::Strict, 1).unwrap(), set(&[8]));
        for bad in ["[a", "[z-a]", r"[\B]", "a)", "(a", "*a", r"\", r"\xZ", "^*"] {
            assert!(parse_regex(bad.as_bytes(), false, false, Syntax::Strict, 1).is_err(), "{bad}");
        }
    }

    #[test]
    fn reversed_widened_and_folded() {
        let n = parse_regex(b"ab", false, false, Syntax::Strict, 1).unwrap();
        assert_eq!(n.reversed(), Node::Seq(vec![set(b"b"), set(b"a")]));
        assert_eq!(n.widened().flatten(), Node::Seq(vec![set(b"a"), set(&[0]), set(b"b"), set(&[0])]));
        assert_eq!(n.case_folded(), Node::Seq(vec![set(b"aA"), set(b"bB")]));
    }
}
