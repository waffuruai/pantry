//! Compiled rules, written out and read back ([`crate::Compiler::bundle`],
//! [`crate::Compiler::add_bundle`]): each rule's metadata, its condition's
//! syntax tree and its strings already compiled to patterns and atoms. Read
//! back, only the conditions' closures and the atom table are built again,
//! so nothing is parsed and no string is compiled twice.
//!
//! The format is this crate's own: a magic and version, then records of
//! tagged, length-free fields (unsigned LEB128 for counts, zigzag for
//! signed). Every enum is written and read through an exhaustive `match`,
//! so a new variant doesn't compile until it has a tag. Anything that
//! doesn't read back exactly (wrong magic or version, a bad tag, a short
//! read, bytes left over) fails the whole bundle: the caller compiles from
//! source instead.

use crate::ast::*;
use crate::classify::Os;
use crate::pattern::{Assert, ByteSet, Node};
use crate::strings::{CompiledString, Fullword, Variant, VariantKind};

/// The first bytes of a bundle.
pub const MAGIC: &[u8; 4] = b"WPYB";
/// Bumped whenever anything written here changes shape.
pub const FORMAT: u32 = 1;

/// Why a bundle didn't read back.
#[derive(Debug, Clone, PartialEq)]
pub struct BadBundle(pub String);

pub type Read<T> = Result<T, BadBundle>;

fn bad<T>(what: &str) -> Read<T> {
    Err(BadBundle(what.to_string()))
}

/// Record tags.
pub(crate) const RULE: u8 = 1;
pub(crate) const REJECTED: u8 = 2;
pub(crate) const SKIPPED: u8 = 3;

/// A byte set of up to this many bytes is written as its bytes.
const SET_LISTED: u32 = 16;
const SET_WORDS: u8 = 254;
const SET_FULL: u8 = 255;

/// One compiled rule as read back: everything [`crate::Compiler`] needs to
/// push it again without its source.
pub(crate) struct RuleRecord {
    pub namespace: String,
    /// The modules its file imports, by name.
    pub imports: Vec<String>,
    pub name: String,
    pub os: Os,
    pub category: String,
    pub score: i64,
    pub tags: Vec<String>,
    pub meta: Vec<(String, Meta)>,
    pub private: bool,
    pub global: bool,
    pub line: usize,
    pub condition: Expr,
    pub strings: Vec<CompiledString>,
}

/// One compiled rule as written, borrowed from the compiler.
pub(crate) struct RuleRef<'a> {
    pub namespace: &'a str,
    pub imports: Vec<&'a str>,
    pub name: &'a str,
    pub os: Os,
    pub category: &'a str,
    pub score: i64,
    pub tags: &'a [String],
    pub meta: &'a [(String, Meta)],
    pub private: bool,
    pub global: bool,
    pub line: usize,
    pub condition: &'a Expr,
    pub strings: &'a [CompiledString],
}

#[derive(Default)]
pub(crate) struct Enc {
    pub out: Vec<u8>,
}

impl Enc {
    pub fn new() -> Self {
        let mut e = Enc { out: Vec::new() };
        e.out.extend_from_slice(MAGIC);
        e.out.extend_from_slice(&FORMAT.to_le_bytes());
        e
    }

    fn u8(&mut self, b: u8) {
        self.out.push(b);
    }

    pub fn uint(&mut self, mut n: u64) {
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                self.out.push(b);
                return;
            }
            self.out.push(b | 0x80);
        }
    }

    fn int(&mut self, n: i64) {
        self.uint(((n << 1) ^ (n >> 63)) as u64);
    }

    fn bool(&mut self, b: bool) {
        self.u8(b as u8);
    }

    fn bytes(&mut self, b: &[u8]) {
        self.uint(b.len() as u64);
        self.out.extend_from_slice(b);
    }

    pub fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    fn strs(&mut self, v: &[String]) {
        self.uint(v.len() as u64);
        for s in v {
            self.str(s);
        }
    }

    fn opt<T>(&mut self, v: &Option<T>, mut f: impl FnMut(&mut Self, &T)) {
        match v {
            None => self.u8(0),
            Some(x) => {
                self.u8(1);
                f(self, x);
            }
        }
    }

    pub fn rule(&mut self, r: &RuleRef) {
        self.u8(RULE);
        self.str(r.namespace);
        self.uint(r.imports.len() as u64);
        for m in &r.imports {
            self.str(m);
        }
        self.str(r.name);
        self.u8(match r.os {
            Os::Windows => 0,
            Os::Linux => 1,
            Os::MacOS => 2,
            Os::Any => 3,
        });
        self.str(r.category);
        self.int(r.score);
        self.strs(r.tags);
        self.uint(r.meta.len() as u64);
        for (k, m) in r.meta {
            self.str(k);
            self.meta(m);
        }
        self.bool(r.private);
        self.bool(r.global);
        self.uint(r.line as u64);
        self.expr(r.condition);
        self.uint(r.strings.len() as u64);
        for s in r.strings {
            self.string(s);
        }
    }

    pub fn rejected(&mut self, namespace: &str, rule: &str, e: &crate::Error) {
        self.u8(REJECTED);
        self.str(namespace);
        self.str(rule);
        let (kind, line, msg) = match e {
            crate::Error::Syntax { line, msg } => (0, line, msg),
            crate::Error::Semantic { line, msg } => (1, line, msg),
        };
        self.u8(kind);
        self.uint(*line as u64);
        self.str(msg);
    }

    pub fn skipped(&mut self, n: usize) {
        self.u8(SKIPPED);
        self.uint(n as u64);
    }

    fn meta(&mut self, m: &Meta) {
        match m {
            Meta::Str(s) => {
                self.u8(0);
                self.bytes(s);
            }
            Meta::Int(i) => {
                self.u8(1);
                self.int(*i);
            }
            Meta::Bool(b) => {
                self.u8(2);
                self.bool(*b);
            }
        }
    }

    fn string(&mut self, s: &CompiledString) {
        self.str(&s.id);
        self.bool(s.private);
        self.uint(s.variants.len() as u64);
        for v in &s.variants {
            self.variant(v);
        }
        self.opt(&s.captures, |e, (n, k)| {
            e.node(n);
            e.uint(*k as u64);
        });
    }

    fn variant(&mut self, v: &Variant) {
        match &v.kind {
            VariantKind::Literal { bytes, nocase } => {
                self.u8(0);
                self.bytes(bytes);
                self.bool(*nocase);
            }
            VariantKind::Pattern { prefix, rest, reach, first } => {
                self.u8(1);
                self.opt(prefix, |e, n| e.node(n));
                self.node(rest);
                self.uint(*reach as u64);
                self.opt(first, |e, s| e.set(s));
            }
        }
        self.uint(v.atoms.len() as u64);
        for (a, off) in &v.atoms {
            self.bytes(a);
            self.uint(*off as u64);
        }
        match v.fullword {
            Fullword::No => self.u8(0),
            Fullword::Ascii(k) => {
                self.u8(1);
                self.u8(k);
            }
            Fullword::Wide(k) => {
                self.u8(2);
                self.u8(k);
            }
        }
    }

    /// A set as its bytes when it holds few (most hold one), all of them
    /// as one tag, else its four words.
    fn set(&mut self, s: &ByteSet) {
        match s.len() {
            256 => self.u8(SET_FULL),
            n @ 0..=SET_LISTED => {
                self.u8(n as u8);
                self.out.extend(s.iter());
            }
            _ => {
                self.u8(SET_WORDS);
                for w in s.words() {
                    self.out.extend_from_slice(&w.to_le_bytes());
                }
            }
        }
    }

    fn node(&mut self, n: &Node) {
        match n {
            Node::Set(s) => {
                self.u8(0);
                self.set(s);
            }
            Node::Seq(v) => {
                self.u8(1);
                self.nodes(v);
            }
            Node::Alt(v) => {
                self.u8(2);
                self.nodes(v);
            }
            Node::Repeat { node, min, max, greedy } => {
                self.u8(3);
                self.node(node);
                self.uint(*min as u64);
                self.opt(max, |e, m| e.uint(*m as u64));
                self.bool(*greedy);
            }
            Node::Assert(a) => {
                self.u8(4);
                self.u8(match a {
                    Assert::Start => 0,
                    Assert::End => 1,
                    Assert::WordBoundary => 2,
                    Assert::NotWordBoundary => 3,
                    Assert::LineStart => 4,
                    Assert::LineEnd => 5,
                });
            }
            Node::Group(k, node) => {
                self.u8(5);
                self.uint(*k as u64);
                self.node(node);
            }
            Node::Lit(bytes) => {
                self.u8(6);
                self.bytes(bytes);
            }
        }
    }

    fn nodes(&mut self, v: &[Node]) {
        self.uint(v.len() as u64);
        for n in v {
            self.node(n);
        }
    }

    fn exprs(&mut self, v: &[Expr]) {
        self.uint(v.len() as u64);
        for x in v {
            self.expr(x);
        }
    }

    fn quant(&mut self, q: &Quant) {
        match q {
            Quant::All => self.u8(0),
            Quant::Any => self.u8(1),
            Quant::None => self.u8(2),
            Quant::Count(x) => {
                self.u8(3);
                self.expr(x);
            }
            Quant::Percent(x) => {
                self.u8(4);
                self.expr(x);
            }
        }
    }

    fn strset(&mut self, s: &StrSet) {
        match s {
            StrSet::Them => self.u8(0),
            StrSet::Ids(ids) => {
                self.u8(1);
                self.strs(ids);
            }
        }
    }

    fn anchor(&mut self, a: &Anchor) {
        match a {
            Anchor::At(x) => {
                self.u8(0);
                self.expr(x);
            }
            Anchor::In(a, b) => {
                self.u8(1);
                self.expr(a);
                self.expr(b);
            }
        }
    }

    fn expr(&mut self, x: &Expr) {
        match x {
            Expr::Bool(b) => {
                self.u8(0);
                self.bool(*b);
            }
            Expr::Int(i) => {
                self.u8(1);
                self.int(*i);
            }
            Expr::Float(f) => {
                self.u8(2);
                self.out.extend_from_slice(&f.to_bits().to_le_bytes());
            }
            Expr::Str(s) => {
                self.u8(3);
                self.bytes(s);
            }
            Expr::Regex(n) => {
                self.u8(4);
                self.node(n);
            }
            Expr::Filesize => self.u8(5),
            Expr::Entrypoint => self.u8(6),
            Expr::Ident(s) => {
                self.u8(7);
                self.str(s);
            }
            Expr::Field(x, f) => {
                self.u8(8);
                self.expr(x);
                self.str(f);
            }
            Expr::Index(a, b) => {
                self.u8(9);
                self.expr(a);
                self.expr(b);
            }
            Expr::Call(f, args) => {
                self.u8(10);
                self.expr(f);
                self.exprs(args);
            }
            Expr::StrMatch { id, anchor } => {
                self.u8(11);
                self.str(id);
                self.opt(anchor, |e, a| e.anchor(a));
            }
            Expr::StrCount { id, range } => {
                self.u8(12);
                self.str(id);
                self.opt(range, |e, (a, b)| {
                    e.expr(a);
                    e.expr(b);
                });
            }
            Expr::StrOffset { id, index } => {
                self.u8(13);
                self.str(id);
                self.opt(index, |e, i| e.expr(i));
            }
            Expr::StrLength { id, index } => {
                self.u8(14);
                self.str(id);
                self.opt(index, |e, i| e.expr(i));
            }
            Expr::Unary(op, x) => {
                self.u8(15);
                self.u8(match op {
                    UnOp::Not => 0,
                    UnOp::Neg => 1,
                    UnOp::BitNot => 2,
                    UnOp::Defined => 3,
                });
                self.expr(x);
            }
            Expr::Binary(op, a, b) => {
                self.u8(16);
                self.u8(binop_tag(*op));
                self.expr(a);
                self.expr(b);
            }
            Expr::Of { quant, items, anchor } => {
                self.u8(17);
                self.quant(quant);
                match items {
                    OfItems::Strings(s) => {
                        self.u8(0);
                        self.strset(s);
                    }
                    OfItems::Rules(r) => {
                        self.u8(1);
                        self.strs(r);
                    }
                    OfItems::Exprs(x) => {
                        self.u8(2);
                        self.exprs(x);
                    }
                }
                self.opt(anchor, |e, a| e.anchor(a));
            }
            Expr::ForOf { quant, strings, body } => {
                self.u8(18);
                self.quant(quant);
                self.strset(strings);
                self.expr(body);
            }
            Expr::ForIn { quant, vars, iter, body } => {
                self.u8(19);
                self.quant(quant);
                self.strs(vars);
                match iter {
                    Iterable::Range(a, b) => {
                        self.u8(0);
                        self.expr(a);
                        self.expr(b);
                    }
                    Iterable::List(v) => {
                        self.u8(1);
                        self.exprs(v);
                    }
                    Iterable::Expr(x) => {
                        self.u8(2);
                        self.expr(x);
                    }
                }
                self.expr(body);
            }
            Expr::With { binds, body } => {
                self.u8(20);
                self.uint(binds.len() as u64);
                for (k, v) in binds {
                    self.str(k);
                    self.expr(v);
                }
                self.expr(body);
            }
        }
    }
}

const BINOPS: [BinOp; 26] = [
    BinOp::Or,
    BinOp::And,
    BinOp::Eq,
    BinOp::Ne,
    BinOp::Lt,
    BinOp::Le,
    BinOp::Gt,
    BinOp::Ge,
    BinOp::Contains,
    BinOp::IContains,
    BinOp::StartsWith,
    BinOp::IStartsWith,
    BinOp::EndsWith,
    BinOp::IEndsWith,
    BinOp::IEquals,
    BinOp::Matches,
    BinOp::BitOr,
    BinOp::BitXor,
    BinOp::BitAnd,
    BinOp::Shl,
    BinOp::Shr,
    BinOp::Add,
    BinOp::Sub,
    BinOp::Mul,
    BinOp::Div,
    BinOp::Mod,
];

fn binop_tag(op: BinOp) -> u8 {
    // Exhaustive, so a new operator needs a place in BINOPS to compile.
    match op {
        BinOp::Or
        | BinOp::And
        | BinOp::Eq
        | BinOp::Ne
        | BinOp::Lt
        | BinOp::Le
        | BinOp::Gt
        | BinOp::Ge
        | BinOp::Contains
        | BinOp::IContains
        | BinOp::StartsWith
        | BinOp::IStartsWith
        | BinOp::EndsWith
        | BinOp::IEndsWith
        | BinOp::IEquals
        | BinOp::Matches
        | BinOp::BitOr
        | BinOp::BitXor
        | BinOp::BitAnd
        | BinOp::Shl
        | BinOp::Shr
        | BinOp::Add
        | BinOp::Sub
        | BinOp::Mul
        | BinOp::Div
        | BinOp::Mod => BINOPS.iter().position(|o| *o == op).expect("every operator is listed") as u8,
    }
}

/// How deep a condition or pattern may nest when read back: past this, the
/// bundle is taken as corrupt rather than read with unbounded recursion.
const MAX_DEPTH: usize = 512;

pub(crate) struct Dec<'a> {
    data: &'a [u8],
    at: usize,
    depth: usize,
}

impl<'a> Dec<'a> {
    pub fn new(data: &'a [u8]) -> Read<Self> {
        let mut d = Dec { data, at: 0, depth: 0 };
        if d.take(4)? != MAGIC {
            return bad("not a rules bundle");
        }
        let v = u32::from_le_bytes(d.take(4)?.try_into().expect("four bytes"));
        if v != FORMAT {
            return bad(&format!("bundle format {v}, not {FORMAT}"));
        }
        Ok(d)
    }

    pub fn done(&self) -> bool {
        self.at == self.data.len()
    }

    fn take(&mut self, n: usize) -> Read<&'a [u8]> {
        let end = self.at.checked_add(n).filter(|e| *e <= self.data.len());
        let Some(end) = end else { return bad("short read") };
        let s = &self.data[self.at..end];
        self.at = end;
        Ok(s)
    }

    pub fn u8(&mut self) -> Read<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn uint(&mut self) -> Read<u64> {
        let mut n: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            n |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(n);
            }
        }
        bad("varint too long")
    }

    fn usize(&mut self) -> Read<usize> {
        usize::try_from(self.uint()?).or_else(|_| bad("number too large"))
    }

    fn u32(&mut self) -> Read<u32> {
        u32::try_from(self.uint()?).or_else(|_| bad("number too large"))
    }

    /// A count of things each at least one byte long: never more than the
    /// bytes left, so a corrupt count can't reserve gigabytes.
    fn count(&mut self) -> Read<usize> {
        let n = self.usize()?;
        if n > self.data.len() - self.at {
            return bad("count past the end");
        }
        Ok(n)
    }

    fn int(&mut self) -> Read<i64> {
        let u = self.uint()?;
        Ok((u >> 1) as i64 ^ -((u & 1) as i64))
    }

    fn bool(&mut self) -> Read<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => bad("bad bool"),
        }
    }

    fn bytes(&mut self) -> Read<Vec<u8>> {
        let n = self.count()?;
        Ok(self.take(n)?.to_vec())
    }

    pub fn str(&mut self) -> Read<String> {
        String::from_utf8(self.bytes()?).or_else(|_| bad("bad utf-8"))
    }

    fn strs(&mut self) -> Read<Vec<String>> {
        let n = self.count()?;
        (0..n).map(|_| self.str()).collect()
    }

    fn opt<T>(&mut self, mut f: impl FnMut(&mut Self) -> Read<T>) -> Read<Option<T>> {
        match self.u8()? {
            0 => Ok(None),
            1 => f(self).map(Some),
            _ => bad("bad option"),
        }
    }

    fn deeper<T>(&mut self, f: impl FnOnce(&mut Self) -> Read<T>) -> Read<T> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return bad("nested too deep");
        }
        let r = f(self);
        self.depth -= 1;
        r
    }

    pub fn rule(&mut self) -> Read<RuleRecord> {
        let namespace = self.str()?;
        let imports = self.strs()?;
        let name = self.str()?;
        let os = match self.u8()? {
            0 => Os::Windows,
            1 => Os::Linux,
            2 => Os::MacOS,
            3 => Os::Any,
            _ => return bad("bad os"),
        };
        let category = self.str()?;
        let score = self.int()?;
        let tags = self.strs()?;
        let n = self.count()?;
        let mut meta = Vec::with_capacity(n);
        for _ in 0..n {
            let k = self.str()?;
            meta.push((k, self.meta()?));
        }
        let private = self.bool()?;
        let global = self.bool()?;
        let line = self.usize()?;
        let condition = self.expr()?;
        let n = self.count()?;
        let strings = (0..n).map(|_| self.string()).collect::<Read<Vec<_>>>()?;
        Ok(RuleRecord {
            namespace,
            imports,
            name,
            os,
            category,
            score,
            tags,
            meta,
            private,
            global,
            line,
            condition,
            strings,
        })
    }

    pub fn rejected(&mut self) -> Read<(String, String, crate::Error)> {
        let namespace = self.str()?;
        let rule = self.str()?;
        let kind = self.u8()?;
        let line = self.usize()?;
        let msg = self.str()?;
        let e = match kind {
            0 => crate::Error::Syntax { line, msg },
            1 => crate::Error::Semantic { line, msg },
            _ => return bad("bad error kind"),
        };
        Ok((namespace, rule, e))
    }

    fn meta(&mut self) -> Read<Meta> {
        Ok(match self.u8()? {
            0 => Meta::Str(self.bytes()?),
            1 => Meta::Int(self.int()?),
            2 => Meta::Bool(self.bool()?),
            _ => return bad("bad meta"),
        })
    }

    fn string(&mut self) -> Read<CompiledString> {
        let id = self.str()?;
        let private = self.bool()?;
        let n = self.count()?;
        let variants = (0..n).map(|_| self.variant()).collect::<Read<Vec<_>>>()?;
        let captures = self.opt(|d| Ok((d.node()?, d.u32()?)))?;
        Ok(CompiledString { id, private, variants, captures })
    }

    fn variant(&mut self) -> Read<Variant> {
        let kind = match self.u8()? {
            0 => VariantKind::Literal { bytes: self.bytes()?, nocase: self.bool()? },
            1 => {
                let prefix = self.opt(|d| d.node())?;
                let rest = self.node()?;
                let reach = self.usize()?;
                let first = self.opt(|d| d.set())?;
                VariantKind::Pattern { prefix, rest, reach, first }
            }
            _ => return bad("bad variant"),
        };
        let n = self.count()?;
        let mut atoms = Vec::with_capacity(n);
        for _ in 0..n {
            let a = self.bytes()?;
            atoms.push((a, self.usize()?));
        }
        let fullword = match self.u8()? {
            0 => Fullword::No,
            1 => Fullword::Ascii(self.u8()?),
            2 => Fullword::Wide(self.u8()?),
            _ => return bad("bad fullword"),
        };
        Ok(Variant { kind, atoms, fullword })
    }

    fn set(&mut self) -> Read<ByteSet> {
        match self.u8()? {
            SET_FULL => Ok(ByteSet::FULL),
            SET_WORDS => {
                let mut w = [0u64; 4];
                for x in &mut w {
                    *x = u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes"));
                }
                Ok(ByteSet::from_words(w))
            }
            n if u32::from(n) <= SET_LISTED => {
                let mut set = ByteSet::default();
                for b in self.take(n as usize)? {
                    set.insert(*b);
                }
                Ok(set)
            }
            _ => bad("bad byte set"),
        }
    }

    fn node(&mut self) -> Read<Node> {
        self.deeper(|d| {
            Ok(match d.u8()? {
                0 => Node::Set(d.set()?),
                1 => Node::Seq(d.nodes()?),
                2 => Node::Alt(d.nodes()?),
                3 => {
                    let node = Box::new(d.node()?);
                    let min = d.u32()?;
                    let max = d.opt(|d| d.u32())?;
                    Node::Repeat { node, min, max, greedy: d.bool()? }
                }
                4 => Node::Assert(match d.u8()? {
                    0 => Assert::Start,
                    1 => Assert::End,
                    2 => Assert::WordBoundary,
                    3 => Assert::NotWordBoundary,
                    4 => Assert::LineStart,
                    5 => Assert::LineEnd,
                    _ => return bad("bad assertion"),
                }),
                5 => {
                    let k = d.u32()?;
                    Node::Group(k, Box::new(d.node()?))
                }
                6 => Node::Lit(d.bytes()?.into_boxed_slice()),
                _ => return bad("bad pattern node"),
            })
        })
    }

    fn nodes(&mut self) -> Read<Vec<Node>> {
        let n = self.count()?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.node()?);
        }
        Ok(v)
    }

    fn exprs(&mut self) -> Read<Vec<Expr>> {
        let n = self.count()?;
        (0..n).map(|_| self.expr()).collect()
    }

    fn boxed(&mut self) -> Read<Box<Expr>> {
        self.expr().map(Box::new)
    }

    fn quant(&mut self) -> Read<Quant> {
        Ok(match self.u8()? {
            0 => Quant::All,
            1 => Quant::Any,
            2 => Quant::None,
            3 => Quant::Count(self.boxed()?),
            4 => Quant::Percent(self.boxed()?),
            _ => return bad("bad quantifier"),
        })
    }

    fn strset(&mut self) -> Read<StrSet> {
        Ok(match self.u8()? {
            0 => StrSet::Them,
            1 => StrSet::Ids(self.strs()?),
            _ => return bad("bad string set"),
        })
    }

    fn anchor(&mut self) -> Read<Anchor> {
        Ok(match self.u8()? {
            0 => Anchor::At(self.boxed()?),
            1 => {
                let a = self.boxed()?;
                Anchor::In(a, self.boxed()?)
            }
            _ => return bad("bad anchor"),
        })
    }

    fn expr(&mut self) -> Read<Expr> {
        self.deeper(|d| {
            Ok(match d.u8()? {
                0 => Expr::Bool(d.bool()?),
                1 => Expr::Int(d.int()?),
                2 => Expr::Float(f64::from_bits(u64::from_le_bytes(d.take(8)?.try_into().expect("eight bytes")))),
                3 => Expr::Str(d.bytes()?),
                4 => Expr::Regex(d.node()?),
                5 => Expr::Filesize,
                6 => Expr::Entrypoint,
                7 => Expr::Ident(d.str()?),
                8 => {
                    let x = d.boxed()?;
                    Expr::Field(x, d.str()?)
                }
                9 => {
                    let a = d.boxed()?;
                    Expr::Index(a, d.boxed()?)
                }
                10 => {
                    let f = d.boxed()?;
                    Expr::Call(f, d.exprs()?)
                }
                11 => {
                    let id = d.str()?;
                    Expr::StrMatch { id, anchor: d.opt(|d| d.anchor())? }
                }
                12 => {
                    let id = d.str()?;
                    let range = d.opt(|d| {
                        let a = d.boxed()?;
                        Ok((a, d.boxed()?))
                    })?;
                    Expr::StrCount { id, range }
                }
                13 => {
                    let id = d.str()?;
                    Expr::StrOffset { id, index: d.opt(|d| d.boxed())? }
                }
                14 => {
                    let id = d.str()?;
                    Expr::StrLength { id, index: d.opt(|d| d.boxed())? }
                }
                15 => {
                    let op = match d.u8()? {
                        0 => UnOp::Not,
                        1 => UnOp::Neg,
                        2 => UnOp::BitNot,
                        3 => UnOp::Defined,
                        _ => return bad("bad unary operator"),
                    };
                    Expr::Unary(op, d.boxed()?)
                }
                16 => {
                    let Some(op) = BINOPS.get(d.u8()? as usize).copied() else { return bad("bad operator") };
                    let a = d.boxed()?;
                    Expr::Binary(op, a, d.boxed()?)
                }
                17 => {
                    let quant = d.quant()?;
                    let items = match d.u8()? {
                        0 => OfItems::Strings(d.strset()?),
                        1 => OfItems::Rules(d.strs()?),
                        2 => OfItems::Exprs(d.exprs()?),
                        _ => return bad("bad of items"),
                    };
                    Expr::Of { quant, items, anchor: d.opt(|d| d.anchor())? }
                }
                18 => {
                    let quant = d.quant()?;
                    let strings = d.strset()?;
                    Expr::ForOf { quant, strings, body: d.boxed()? }
                }
                19 => {
                    let quant = d.quant()?;
                    let vars = d.strs()?;
                    let iter = match d.u8()? {
                        0 => {
                            let a = d.boxed()?;
                            Iterable::Range(a, d.boxed()?)
                        }
                        1 => Iterable::List(d.exprs()?),
                        2 => Iterable::Expr(d.boxed()?),
                        _ => return bad("bad iterable"),
                    };
                    Expr::ForIn { quant, vars, iter, body: d.boxed()? }
                }
                20 => {
                    let n = d.count()?;
                    let mut binds = Vec::with_capacity(n);
                    for _ in 0..n {
                        let k = d.str()?;
                        binds.push((k, d.expr()?));
                    }
                    Expr::With { binds, body: d.boxed()? }
                }
                _ => return bad("bad expression"),
            })
        })
    }
}

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod tests;
