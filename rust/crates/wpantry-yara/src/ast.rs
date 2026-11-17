//! The parsed form of a rules file, before it compiles.

use crate::pattern::Node;

#[derive(Debug, Default)]
pub struct SourceFile {
    pub imports: Vec<String>,
    pub rules: Vec<Rule>,
}

#[derive(Debug)]
pub struct Rule {
    pub name: String,
    pub private: bool,
    pub global: bool,
    pub tags: Vec<String>,
    pub meta: Vec<(String, Meta)>,
    pub strings: Vec<StringDef>,
    pub condition: Expr,
    pub line: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Meta {
    Str(Vec<u8>),
    Int(i64),
    Bool(bool),
}

#[derive(Debug)]
pub struct StringDef {
    /// The name without `$`; anonymous strings get a name no rule can write.
    pub id: String,
    pub kind: StringKind,
    pub mods: Modifiers,
    pub line: usize,
    /// A regex string's text between the slashes and its `i` and `s` flags.
    pub source: Option<RegexSource>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RegexSource {
    pub src: Vec<u8>,
    pub nocase: bool,
    pub dotall: bool,
}

#[derive(Debug)]
pub enum StringKind {
    Text(Vec<u8>),
    Hex(Node),
    Regex(Node),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Modifiers {
    pub nocase: bool,
    pub ascii: bool,
    pub wide: bool,
    pub fullword: bool,
    pub private: bool,
    /// The key range of `xor`, `xor(n)` or `xor(lo-hi)`.
    pub xor: Option<(u8, u8)>,
    /// `base64` with its alphabet (the standard one when not given).
    pub base64: Option<Vec<u8>>,
    pub base64wide: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UnOp {
    Not,
    Neg,
    BitNot,
    Defined,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BinOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    IContains,
    StartsWith,
    IStartsWith,
    EndsWith,
    IEndsWith,
    IEquals,
    Matches,
    BitOr,
    BitXor,
    BitAnd,
    Shl,
    Shr,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Debug)]
pub enum Quant {
    All,
    Any,
    None,
    /// `n of`
    Count(Box<Expr>),
    /// `n% of`
    Percent(Box<Expr>),
}

/// The strings an `of` or `for … of` ranges over.
#[derive(Debug)]
pub enum StrSet {
    Them,
    /// Names, each possibly ending in `*`.
    Ids(Vec<String>),
}

#[derive(Debug)]
pub enum OfItems {
    Strings(StrSet),
    /// Rule names, each possibly ending in `*`.
    Rules(Vec<String>),
    /// yara-x's boolean tuples: `2 of (a, b > 1, $c)`.
    Exprs(Vec<Expr>),
}

#[derive(Debug)]
pub enum Anchor {
    At(Box<Expr>),
    In(Box<Expr>, Box<Expr>),
}

#[derive(Debug)]
pub enum Iterable {
    Range(Box<Expr>, Box<Expr>),
    List(Vec<Expr>),
    Expr(Box<Expr>),
}

#[derive(Debug)]
pub enum Expr {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Vec<u8>),
    Regex(Node),
    Filesize,
    Entrypoint,
    Ident(String),
    Field(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    Call(Box<Expr>, Vec<Expr>),
    /// `$a`, `$a at x`, `$a in (lo..hi)`; an empty id is the loop's current string.
    StrMatch {
        id: String,
        anchor: Option<Anchor>,
    },
    /// `#a` or `#a in (lo..hi)`.
    StrCount {
        id: String,
        range: Option<(Box<Expr>, Box<Expr>)>,
    },
    /// `@a` or `@a[i]` (1-based).
    StrOffset {
        id: String,
        index: Option<Box<Expr>>,
    },
    /// `!a` or `!a[i]`.
    StrLength {
        id: String,
        index: Option<Box<Expr>>,
    },
    Unary(UnOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    Of {
        quant: Quant,
        items: OfItems,
        anchor: Option<Anchor>,
    },
    ForOf {
        quant: Quant,
        strings: StrSet,
        body: Box<Expr>,
    },
    ForIn {
        quant: Quant,
        vars: Vec<String>,
        iter: Iterable,
        body: Box<Expr>,
    },
    With {
        binds: Vec<(String, Expr)>,
        body: Box<Expr>,
    },
}
