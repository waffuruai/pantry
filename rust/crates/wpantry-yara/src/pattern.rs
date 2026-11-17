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
    /// `^` and `$` in RE2's multiline mode: a line's start or end.
    LineStart,
    LineEnd,
}

#[derive(Clone, PartialEq, Debug)]
pub enum Node {
    Set(ByteSet),
    Seq(Vec<Node>),
    Alt(Vec<Node>),
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
        greedy: bool,
    },
    Assert(Assert),
    /// Capture group `n` (from 1): only [`parse_regex_groups`] makes them,
    /// so rules' strings never hold one.
    Group(u32, Box<Node>),
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
            Node::Group(n, inner) => Node::Group(n, Box::new(inner.flatten())),
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
            Node::Group(n, inner) => Node::Group(*n, Box::new(inner.reversed())),
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
            Node::Group(n, inner) => Node::Group(*n, Box::new(inner.widened())),
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
            Node::Group(n, inner) => Node::Group(*n, Box::new(inner.case_folded())),
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
    /// Go's RE2, for patterns Pantry runs itself (never rules' strings):
    /// as relaxed, plus scoped inline flags (`(?i)`, `(?-i:…)`, `(?m)`,
    /// `(?s)`), multiline `^` and `$`, `\A` and `\z`, and POSIX classes.
    Re2,
}

struct Re<'a> {
    src: &'a [u8],
    pos: usize,
    dotall: bool,
    syntax: Syntax,
    line: usize,
    /// The capture groups seen so far, when they are kept ([`parse_regex_groups`]).
    groups: Option<u32>,
    /// RE2's flags in the current scope ([`Syntax::Re2`] only).
    nocase: bool,
    multiline: bool,
}

/// Parse a regex body (between the slashes). `nocase` folds every letter.
pub fn parse_regex(src: &[u8], nocase: bool, dotall: bool, syntax: Syntax, line: usize) -> Result<Node, Error> {
    Ok(parse(Re { src, pos: 0, dotall, syntax, line, groups: None, nocase: false, multiline: false }, nocase)?.0)
}

/// As [`parse_regex`], keeping each capturing `( )` as a [`Node::Group`]
/// numbered from 1 in the order its `(` appears; also returns how many there
/// are. For [`crate::matcher::Matcher::captures`], not for rules' strings.
pub fn parse_regex_groups(src: &[u8], nocase: bool, dotall: bool, syntax: Syntax) -> Result<(Node, u32), Error> {
    parse(Re { src, pos: 0, dotall, syntax, line: 0, groups: Some(0), nocase: false, multiline: false }, nocase)
}

fn parse(mut re: Re, nocase: bool) -> Result<(Node, u32), Error> {
    // RE2 folds case atom by atom, as its flags' scopes say; YARA all at once.
    let re2 = re.syntax == Syntax::Re2;
    re.nocase = nocase && re2;
    let node = re.alt()?;
    if re.pos != re.src.len() {
        return Err(re.err("unbalanced `)`"));
    }
    let node = if nocase && !re2 { node.case_folded() } else { node };
    Ok((node.flatten(), re.groups.unwrap_or(0)))
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
        let node = self.atom_unfolded()?;
        Ok(if self.nocase && !matches!(node, Node::Group(..) | Node::Seq(_) | Node::Alt(_)) {
            node.case_folded()
        } else {
            node
        })
    }

    /// RE2's `(?flags)` or `(?flags:` after a `(`: the flags set (or `-`
    /// cleared), and whether a group follows (`:`), the cursor past it.
    fn flags(&mut self) -> Result<Option<bool>, Error> {
        let rest = &self.src[self.pos..];
        let Some(body) = rest.strip_prefix(b"?") else { return Ok(None) };
        let len = body.iter().take_while(|c| matches!(c, b'i' | b'm' | b's' | b'U' | b'-')).count();
        let (flags, after) = body.split_at(len);
        let group = match after.first() {
            Some(b':') => true,
            Some(b')') => false,
            _ => return Ok(None),
        };
        if flags.is_empty() && !group {
            return Err(self.err("empty flags"));
        }
        let mut on = true;
        for &f in flags {
            match f {
                b'-' => on = false,
                b'i' => self.nocase = on,
                b'm' => self.multiline = on,
                b's' => self.dotall = on,
                _ => return Err(self.err("unsupported flag")),
            }
        }
        self.pos += 1 + len + 1;
        Ok(Some(group))
    }

    fn atom_unfolded(&mut self) -> Result<Node, Error> {
        let c = self.peek().expect("caller checked");
        self.pos += 1;
        Ok(match c {
            b'(' if self.syntax == Syntax::Re2
                && self.src[self.pos..].starts_with(b"?")
                && !self.src[self.pos..].starts_with(b"?:")
                && !self.src[self.pos..].starts_with(b"?P<")
                && !self.src[self.pos..].starts_with(b"?<") =>
            {
                let saved = (self.nocase, self.multiline, self.dotall);
                match self.flags()? {
                    // `(?i)`: the flags hold to the end of the enclosing group,
                    // whose `(` restores them.
                    Some(false) => Node::Seq(Vec::new()),
                    Some(true) => {
                        let inner = self.alt()?;
                        if self.peek() != Some(b')') {
                            return Err(self.err("unclosed `(`"));
                        }
                        self.pos += 1;
                        (self.nocase, self.multiline, self.dotall) = saved;
                        inner
                    }
                    None => return Err(self.err("unsupported group")),
                }
            }
            b'(' => {
                if self.syntax == Syntax::Re2 {
                    // A named group is a capturing group.
                    let rest = &self.src[self.pos..];
                    if let Some(name) = rest.strip_prefix(b"?P<").or_else(|| rest.strip_prefix(b"?<"))
                        && let Some(end) = name.iter().position(|c| *c == b'>')
                    {
                        self.pos += rest.len() - name.len() + end + 1;
                    }
                }
                let saved = (self.nocase, self.multiline, self.dotall);
                let capturing = !self.src[self.pos..].starts_with(b"?:");
                if !capturing {
                    self.pos += 2;
                }
                let group = match &mut self.groups {
                    Some(n) if capturing => {
                        *n += 1;
                        Some(*n)
                    }
                    _ => None,
                };
                let inner = self.alt()?;
                if self.peek() != Some(b')') {
                    return Err(self.err("unclosed `(`"));
                }
                self.pos += 1;
                (self.nocase, self.multiline, self.dotall) = saved;
                match group {
                    Some(n) => Node::Group(n, Box::new(inner)),
                    None => inner,
                }
            }
            b'.' => Node::Set(if self.dotall { ByteSet::FULL } else { ByteSet::one(b'\n').complement() }),
            b'^' if self.multiline => Node::Assert(Assert::LineStart),
            b'$' if self.multiline => Node::Assert(Assert::LineEnd),
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
            b'A' if !in_class && self.syntax == Syntax::Re2 => return Ok(Node::Assert(Assert::Start)),
            b'z' if !in_class && self.syntax == Syntax::Re2 => return Ok(Node::Assert(Assert::End)),
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
            c if self.syntax != Syntax::Strict => ByteSet::one(c),
            c => return Err(self.err(&format!("unknown escape \\{}", c as char))),
        }))
    }

    /// RE2's `[:alpha:]` and the like at the cursor, inside a class.
    fn posix_class(&mut self) -> Option<ByteSet> {
        let rest = self.src[self.pos..].strip_prefix(b"[:")?;
        let end = rest.windows(2).position(|w| w == b":]")?;
        let (negate, name) = match rest[..end].strip_prefix(b"^") {
            Some(n) => (true, n),
            None => (false, &rest[..end]),
        };
        let r = ByteSet::range;
        let set = match name {
            b"alnum" => r(b'0', b'9').union(r(b'A', b'Z')).union(r(b'a', b'z')),
            b"alpha" => r(b'A', b'Z').union(r(b'a', b'z')),
            b"ascii" => r(0, 0x7f),
            b"blank" => ByteSet::one(b' ').union(ByteSet::one(b'\t')),
            b"cntrl" => r(0, 0x1f).union(ByteSet::one(0x7f)),
            b"digit" => r(b'0', b'9'),
            b"graph" => r(b'!', b'~'),
            b"lower" => r(b'a', b'z'),
            b"print" => r(b' ', b'~'),
            b"punct" => r(b'!', b'/').union(r(b':', b'@')).union(r(b'[', b'`')).union(r(b'{', b'~')),
            b"space" => [b' ', b'\t', b'\n', b'\r', 0x0b, 0x0c]
                .into_iter()
                .fold(ByteSet::default(), |s, b| s.union(ByteSet::one(b))),
            b"upper" => r(b'A', b'Z'),
            b"word" => r(b'0', b'9').union(r(b'A', b'Z')).union(r(b'a', b'z')).union(ByteSet::one(b'_')),
            b"xdigit" => r(b'0', b'9').union(r(b'A', b'F')).union(r(b'a', b'f')),
            _ => return None,
        };
        self.pos += 2 + end + 2;
        Some(if negate { set.complement() } else { set })
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
            if self.syntax == Syntax::Re2
                && let Some(posix) = self.posix_class()
            {
                set = set.union(posix);
                continue;
            }
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
#[path = "pattern_tests.rs"]
mod tests;
