//! Rules files to [`ast`](crate::ast): imports, rules, meta, strings and conditions.
//!
//! Conditions follow YARA's precedence, loosest first: `or`, `and`, `not` and
//! `defined`, equality and the string operators (`contains`, `matches`, …),
//! ordering, `|`, `^`, `&`, shifts, `+ -`, `* \ %`, unary `- ~`, then
//! indexing, fields and calls.

use crate::Error;
use crate::ast::*;
use crate::lexer::{Lexer, Tok};
use crate::pattern::{self, Syntax};

/// Words that can't name a rule, string or variable.
const KEYWORDS: &[&str] = &[
    "all",
    "and",
    "any",
    "ascii",
    "at",
    "base64",
    "base64wide",
    "condition",
    "contains",
    "defined",
    "endswith",
    "entrypoint",
    "false",
    "filesize",
    "for",
    "fullword",
    "global",
    "icontains",
    "iendswith",
    "iequals",
    "import",
    "in",
    "include",
    "istartswith",
    "matches",
    "meta",
    "nocase",
    "none",
    "not",
    "of",
    "or",
    "private",
    "rule",
    "startswith",
    "strings",
    "them",
    "true",
    "wide",
    "with",
    "xor",
];

/// The alphabet `base64` uses when a rule names none.
pub const BASE64_STANDARD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Parse a whole file, failing at the first error.
#[cfg(test)]
pub fn parse(src: &str, syntax: Syntax) -> Result<SourceFile, Error> {
    let (file, mut errors) = parse_recovering(src, syntax);
    match errors.is_empty() {
        true => Ok(file),
        false => Err(errors.swap_remove(0).1),
    }
}

/// Parse a whole file, skipping a rule that doesn't parse and carrying on at
/// the next one; each skipped rule is returned with its name (when it got that
/// far) and the error.
pub fn parse_recovering(src: &str, syntax: Syntax) -> (SourceFile, Vec<(String, Error)>) {
    let mut p = Parser { lx: Lexer::new(src), syntax, anon: 0, rule_name: String::new() };
    let mut file = SourceFile::default();
    let mut errors = Vec::new();
    loop {
        p.rule_name.clear();
        let step = match p.lx.peek() {
            Ok(Tok::Eof) => return (file, errors),
            Ok(Tok::Ident(w)) if w == "import" => p.import().map(|m| file.imports.push(m)),
            Ok(Tok::Ident(w)) if w == "include" => Err(p.lx.err("include is not supported")),
            Ok(_) => p.rule().map(|r| file.rules.push(r)),
            Err(e) => Err(e),
        };
        if let Err(e) = step {
            errors.push((p.rule_name.clone(), e));
            p.recover();
        }
    }
}

struct Parser<'a> {
    lx: Lexer<'a>,
    syntax: Syntax,
    anon: usize,
    /// The rule being parsed, for error reports.
    rule_name: String,
}

impl Parser<'_> {
    fn import(&mut self) -> Result<String, Error> {
        self.lx.next()?;
        match self.lx.next()? {
            Tok::Text(name) => Ok(String::from_utf8_lossy(&name).into_owned()),
            _ => Err(self.lx.err("import needs a module name in quotes")),
        }
    }

    /// Skip to just after a `}` that is followed by the start of a rule or
    /// import, or to the end.
    fn recover(&mut self) {
        let starts = |t: &Tok| {
            matches!(t, Tok::Eof)
                || matches!(t, Tok::Ident(w) if ["rule", "private", "global", "import"].contains(&w.as_str()))
        };
        // The error may have been the closing `}` itself.
        if self.lx.peek().is_ok_and(starts) {
            return;
        }
        loop {
            match self.lx.next() {
                Ok(Tok::Eof) => return,
                Ok(Tok::Punct("}")) => {
                    if self.lx.peek().is_ok_and(starts) {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => self.lx.skip_byte(),
            }
        }
    }

    fn expect(&mut self, punct: &str) -> Result<(), Error> {
        match self.lx.next()? {
            Tok::Punct(p) if p == punct => Ok(()),
            other => Err(self.lx.err(format!("expected `{punct}`, found {}", describe(&other)))),
        }
    }

    fn eat(&mut self, punct: &str) -> Result<bool, Error> {
        if matches!(self.lx.peek()?, Tok::Punct(p) if *p == punct) {
            self.lx.next()?;
            return Ok(true);
        }
        Ok(false)
    }

    fn peek_word(&mut self, word: &str) -> Result<bool, Error> {
        Ok(matches!(self.lx.peek()?, Tok::Ident(w) if w == word))
    }

    fn eat_word(&mut self, word: &str) -> Result<bool, Error> {
        if self.peek_word(word)? {
            self.lx.next()?;
            return Ok(true);
        }
        Ok(false)
    }

    fn expect_word(&mut self, word: &str) -> Result<(), Error> {
        if !self.eat_word(word)? {
            let found = describe(self.lx.peek()?);
            return Err(self.lx.err(format!("expected `{word}`, found {found}")));
        }
        Ok(())
    }

    /// A name that isn't a keyword.
    fn name(&mut self) -> Result<String, Error> {
        match self.lx.next()? {
            Tok::Ident(w) if !KEYWORDS.contains(&w.as_str()) => Ok(w),
            other => Err(self.lx.err(format!("expected a name, found {}", describe(&other)))),
        }
    }

    fn rule(&mut self) -> Result<Rule, Error> {
        let line = self.lx.line();
        let (mut private, mut global) = (false, false);
        loop {
            let flag = if self.eat_word("private")? {
                &mut private
            } else if self.eat_word("global")? {
                &mut global
            } else {
                break;
            };
            if *flag && self.syntax == Syntax::Strict {
                return Err(self.lx.err("a rule modifier is repeated"));
            }
            *flag = true;
        }
        self.expect_word("rule")?;
        let name = self.name()?;
        self.rule_name = name.clone();
        let mut tags = Vec::new();
        if self.eat(":")? {
            while let Tok::Ident(_) = self.lx.peek()? {
                tags.push(self.name()?);
            }
        }
        self.expect("{")?;
        let mut meta = Vec::new();
        if self.eat_word("meta")? {
            self.expect(":")?;
            while matches!(self.lx.peek()?, Tok::Ident(w) if w != "strings" && w != "condition") {
                let Tok::Ident(key) = self.lx.next()? else { unreachable!() };
                self.expect("=")?;
                meta.push((key, self.meta_value()?));
            }
        }
        let mut strings = Vec::new();
        if self.eat_word("strings")? {
            self.expect(":")?;
            while let Tok::StrId(_) = self.lx.peek()? {
                let def = self.string_def()?;
                if !def.id.starts_with('\0') && strings.iter().any(|s: &StringDef| s.id == def.id) {
                    return Err(Error::Syntax { line: def.line, msg: format!("duplicate string ${}", def.id) });
                }
                strings.push(def);
            }
        }
        self.expect_word("condition")?;
        self.expect(":")?;
        let condition = self.expr()?;
        self.expect("}")?;
        Ok(Rule { name, private, global, tags, meta, strings, condition, line })
    }

    fn meta_value(&mut self) -> Result<Meta, Error> {
        Ok(match self.lx.next()? {
            Tok::Text(t) => Meta::Str(t),
            Tok::Int(i) => Meta::Int(i),
            Tok::Punct("-") => match self.lx.next()? {
                Tok::Int(i) => Meta::Int(-i),
                _ => return Err(self.lx.err("bad meta value")),
            },
            Tok::Ident(w) if w == "true" => Meta::Bool(true),
            Tok::Ident(w) if w == "false" => Meta::Bool(false),
            // Some published rules carry float meta; keep it as text.
            Tok::Float(f) => Meta::Str(f.to_string().into_bytes()),
            other => return Err(self.lx.err(format!("bad meta value {}", describe(&other)))),
        })
    }

    fn string_def(&mut self) -> Result<StringDef, Error> {
        let line = self.lx.line();
        let Tok::StrId(id) = self.lx.next()? else { unreachable!() };
        if id.ends_with('*') {
            return Err(self.lx.err("a string name can't end in `*`"));
        }
        let id = if id.is_empty() {
            self.anon += 1;
            format!("\0{}", self.anon)
        } else {
            id
        };
        self.expect("=")?;
        let (kind, allowed): (_, &[&str]) = match self.lx.next()? {
            Tok::Text(t) => {
                if t.is_empty() {
                    return Err(self.lx.err("empty string"));
                }
                (
                    StringKind::Text(t),
                    &["nocase", "ascii", "wide", "fullword", "private", "xor", "base64", "base64wide"],
                )
            }
            Tok::Regex { src, nocase, dotall } => {
                let node = pattern::parse_regex(&src, nocase, dotall, self.syntax, line)?;
                (StringKind::Regex(node), &["nocase", "ascii", "wide", "fullword", "private"])
            }
            Tok::Punct("{") => {
                let (body, line) = self.lx.hex_body()?;
                (StringKind::Hex(pattern::parse_hex(&body, line)?), &["private"])
            }
            other => return Err(self.lx.err(format!("bad string value {}", describe(&other)))),
        };
        let mods = self.modifiers(allowed)?;
        Ok(StringDef { id, kind, mods, line })
    }

    fn modifiers(&mut self, allowed: &[&str]) -> Result<Modifiers, Error> {
        let mut m = Modifiers::default();
        while let Tok::Ident(w) = self.lx.peek()? {
            let w = w.clone();
            if !["nocase", "ascii", "wide", "fullword", "private", "xor", "base64", "base64wide"].contains(&w.as_str())
            {
                break;
            }
            if !allowed.contains(&w.as_str()) {
                return Err(self.lx.err(format!("`{w}` doesn't apply to this kind of string")));
            }
            self.lx.next()?;
            match w.as_str() {
                "nocase" => m.nocase = true,
                "ascii" => m.ascii = true,
                "wide" => m.wide = true,
                "fullword" => m.fullword = true,
                "private" => m.private = true,
                "xor" => m.xor = Some(self.xor_range()?),
                "base64" => m.base64 = Some(self.alphabet()?),
                _ => m.base64wide = Some(self.alphabet()?),
            }
        }
        if m.xor.is_some() && m.nocase {
            return Err(self.lx.err("xor and nocase can't be combined"));
        }
        if (m.base64.is_some() || m.base64wide.is_some()) && (m.nocase || m.xor.is_some() || m.fullword) {
            return Err(self.lx.err("base64 can't be combined with nocase, xor or fullword"));
        }
        Ok(m)
    }

    fn xor_range(&mut self) -> Result<(u8, u8), Error> {
        if !self.eat("(")? {
            return Ok((0, 255));
        }
        let byte = |p: &mut Self| match p.lx.next()? {
            Tok::Int(i) if (0..=255).contains(&i) => Ok(i as u8),
            _ => Err(p.lx.err("xor key out of range")),
        };
        let lo = byte(self)?;
        let hi = if self.eat("-")? { byte(self)? } else { lo };
        self.expect(")")?;
        if hi < lo {
            return Err(self.lx.err("bad xor range"));
        }
        Ok((lo, hi))
    }

    fn alphabet(&mut self) -> Result<Vec<u8>, Error> {
        if !self.eat("(")? {
            return Ok(BASE64_STANDARD.to_vec());
        }
        let Tok::Text(a) = self.lx.next()? else { return Err(self.lx.err("base64 alphabet must be a string")) };
        self.expect(")")?;
        if a.len() != 64 {
            return Err(self.lx.err("a base64 alphabet has 64 characters"));
        }
        Ok(a)
    }

    // ------------------------------------------------------------ conditions

    pub fn expr(&mut self) -> Result<Expr, Error> {
        let mut lhs = self.and_expr()?;
        while self.eat_word("or")? {
            lhs = Expr::Binary(BinOp::Or, Box::new(lhs), Box::new(self.and_expr()?));
        }
        Ok(lhs)
    }

    fn and_expr(&mut self) -> Result<Expr, Error> {
        let mut lhs = self.not_expr()?;
        while self.eat_word("and")? {
            lhs = Expr::Binary(BinOp::And, Box::new(lhs), Box::new(self.not_expr()?));
        }
        Ok(lhs)
    }

    fn not_expr(&mut self) -> Result<Expr, Error> {
        if self.eat_word("not")? {
            return Ok(Expr::Unary(UnOp::Not, Box::new(self.not_expr()?)));
        }
        if self.eat_word("defined")? {
            return Ok(Expr::Unary(UnOp::Defined, Box::new(self.not_expr()?)));
        }
        self.eq_expr()
    }

    fn eq_expr(&mut self) -> Result<Expr, Error> {
        let mut lhs = self.rel_expr()?;
        loop {
            let op = match self.lx.peek()? {
                Tok::Punct("==") => BinOp::Eq,
                Tok::Punct("!=") => BinOp::Ne,
                Tok::Ident(w) => match w.as_str() {
                    "contains" => BinOp::Contains,
                    "icontains" => BinOp::IContains,
                    "startswith" => BinOp::StartsWith,
                    "istartswith" => BinOp::IStartsWith,
                    "endswith" => BinOp::EndsWith,
                    "iendswith" => BinOp::IEndsWith,
                    "iequals" => BinOp::IEquals,
                    "matches" => BinOp::Matches,
                    _ => return Ok(lhs),
                },
                _ => return Ok(lhs),
            };
            self.lx.next()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(self.rel_expr()?));
        }
    }

    fn rel_expr(&mut self) -> Result<Expr, Error> {
        self.binary(&[("<", BinOp::Lt), ("<=", BinOp::Le), (">", BinOp::Gt), (">=", BinOp::Ge)], Self::bor)
    }

    fn bor(&mut self) -> Result<Expr, Error> {
        self.binary(&[("|", BinOp::BitOr)], Self::bxor)
    }

    fn bxor(&mut self) -> Result<Expr, Error> {
        self.binary(&[("^", BinOp::BitXor)], Self::band)
    }

    fn band(&mut self) -> Result<Expr, Error> {
        self.binary(&[("&", BinOp::BitAnd)], Self::shift)
    }

    fn shift(&mut self) -> Result<Expr, Error> {
        self.binary(&[("<<", BinOp::Shl), (">>", BinOp::Shr)], Self::add)
    }

    fn add(&mut self) -> Result<Expr, Error> {
        self.binary(&[("+", BinOp::Add), ("-", BinOp::Sub)], Self::mul)
    }

    /// A left-associative level of binary operators.
    fn binary(&mut self, ops: &[(&str, BinOp)], next: fn(&mut Self) -> Result<Expr, Error>) -> Result<Expr, Error> {
        let mut lhs = next(self)?;
        loop {
            let op = match self.lx.peek()? {
                Tok::Punct(p) => match ops.iter().find(|(s, _)| s == p) {
                    Some((_, op)) => *op,
                    None => return Ok(lhs),
                },
                _ => return Ok(lhs),
            };
            self.lx.next()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(next(self)?));
        }
    }

    /// `* \ %`, where `n% of …` is a percentage quantifier, not a remainder.
    fn mul(&mut self) -> Result<Expr, Error> {
        let mut lhs = self.unary()?;
        loop {
            let op = match self.lx.peek()? {
                Tok::Punct("*") => BinOp::Mul,
                Tok::Punct("\\") => BinOp::Div,
                Tok::Punct("%") => BinOp::Mod,
                _ => return Ok(lhs),
            };
            self.lx.next()?;
            if op == BinOp::Mod && self.peek_word("of")? {
                lhs = self.of_rest(Quant::Percent(Box::new(lhs)))?;
                continue;
            }
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(self.unary()?));
        }
    }

    fn unary(&mut self) -> Result<Expr, Error> {
        if self.eat("-")? {
            return Ok(Expr::Unary(UnOp::Neg, Box::new(self.unary()?)));
        }
        if self.eat("~")? {
            return Ok(Expr::Unary(UnOp::BitNot, Box::new(self.unary()?)));
        }
        let e = self.postfix()?;
        if self.peek_word("of")? {
            return self.of_rest(Quant::Count(Box::new(e)));
        }
        Ok(e)
    }

    fn postfix(&mut self) -> Result<Expr, Error> {
        let mut e = self.primary()?;
        loop {
            if self.eat("[")? {
                let i = self.expr()?;
                self.expect("]")?;
                e = Expr::Index(Box::new(e), Box::new(i));
            } else if self.eat(".")? {
                let Tok::Ident(f) = self.lx.next()? else { return Err(self.lx.err("expected a field name after `.`")) };
                e = Expr::Field(Box::new(e), f);
            } else if matches!(e, Expr::Ident(_) | Expr::Field(..)) && self.eat("(")? {
                let mut args = Vec::new();
                if !self.eat(")")? {
                    loop {
                        args.push(self.expr()?);
                        if self.eat(")")? {
                            break;
                        }
                        self.expect(",")?;
                    }
                }
                e = Expr::Call(Box::new(e), args);
            } else {
                return Ok(e);
            }
        }
    }

    fn range(&mut self) -> Result<(Box<Expr>, Box<Expr>), Error> {
        self.expect("(")?;
        let lo = self.expr()?;
        self.expect("..")?;
        let hi = self.expr()?;
        self.expect(")")?;
        Ok((Box::new(lo), Box::new(hi)))
    }

    /// The operand of `at`: arithmetic, but no comparison or boolean.
    fn anchor(&mut self) -> Result<Option<Anchor>, Error> {
        if self.eat_word("at")? {
            return Ok(Some(Anchor::At(Box::new(self.bor()?))));
        }
        if self.eat_word("in")? {
            let (lo, hi) = self.range()?;
            return Ok(Some(Anchor::In(lo, hi)));
        }
        Ok(None)
    }

    fn primary(&mut self) -> Result<Expr, Error> {
        let tok = self.lx.next()?;
        Ok(match tok {
            Tok::Int(i) => Expr::Int(i),
            Tok::Float(f) => Expr::Float(f),
            Tok::Text(t) => Expr::Str(t),
            Tok::Regex { src, nocase, dotall } => {
                let line = self.lx.line();
                Expr::Regex(pattern::parse_regex(&src, nocase, dotall, self.syntax, line)?)
            }
            Tok::Punct("(") => {
                let e = self.expr()?;
                self.expect(")")?;
                e
            }
            Tok::StrId(id) => {
                if id.ends_with('*') {
                    return Err(self.lx.err("a wildcard string set can only follow `of`"));
                }
                Expr::StrMatch { anchor: self.anchor()?, id }
            }
            Tok::StrCount(id) => {
                let range = if self.eat_word("in")? { Some(self.range()?) } else { None };
                Expr::StrCount { id, range }
            }
            Tok::StrOffset(id) => Expr::StrOffset { index: self.str_index()?, id },
            Tok::StrLength(id) => Expr::StrLength { index: self.str_index()?, id },
            Tok::Ident(w) => match w.as_str() {
                "true" => Expr::Bool(true),
                "false" => Expr::Bool(false),
                "filesize" => Expr::Filesize,
                "entrypoint" => Expr::Entrypoint,
                "all" => self.of_rest(Quant::All)?,
                "any" => self.of_rest(Quant::Any)?,
                "none" => self.of_rest(Quant::None)?,
                "for" => self.for_expr()?,
                "with" => self.with_expr()?,
                _ if KEYWORDS.contains(&w.as_str()) => return Err(self.lx.err(format!("unexpected `{w}`"))),
                _ => Expr::Ident(w),
            },
            other => return Err(self.lx.err(format!("unexpected {}", describe(&other)))),
        })
    }

    fn str_index(&mut self) -> Result<Option<Box<Expr>>, Error> {
        if self.eat("[")? {
            let i = self.expr()?;
            self.expect("]")?;
            return Ok(Some(Box::new(i)));
        }
        Ok(None)
    }

    /// After a quantifier: `of them`, `of ($a*, $b)`, `of (rule_*)`,
    /// `of (expr, …)`, with an optional `at` or `in` for strings.
    fn of_rest(&mut self, quant: Quant) -> Result<Expr, Error> {
        self.expect_word("of")?;
        let items = if self.eat_word("them")? {
            OfItems::Strings(StrSet::Them)
        } else {
            self.expect("(")?;
            if let Tok::StrId(_) = self.lx.peek()? {
                OfItems::Strings(StrSet::Ids(self.str_ids()?))
            } else {
                let mut exprs = Vec::new();
                loop {
                    exprs.push(self.expr()?);
                    if self.eat(")")? {
                        break;
                    }
                    self.expect(",")?;
                }
                if exprs.iter().all(|e| matches!(e, Expr::Ident(_))) {
                    OfItems::Rules(
                        exprs.into_iter().map(|e| if let Expr::Ident(n) = e { n } else { unreachable!() }).collect(),
                    )
                } else {
                    OfItems::Exprs(exprs)
                }
            }
        };
        let anchor = match items {
            OfItems::Strings(_) => self.anchor()?,
            _ => None,
        };
        Ok(Expr::Of { quant, items, anchor })
    }

    /// `$a, $b*, …)` after the `(`.
    fn str_ids(&mut self) -> Result<Vec<String>, Error> {
        let mut ids = Vec::new();
        loop {
            match self.lx.next()? {
                Tok::StrId(id) => ids.push(id),
                other => return Err(self.lx.err(format!("expected a string, found {}", describe(&other)))),
            }
            if self.eat(")")? {
                return Ok(ids);
            }
            self.expect(",")?;
        }
    }

    fn quantifier(&mut self) -> Result<Quant, Error> {
        if self.eat_word("all")? {
            return Ok(Quant::All);
        }
        if self.eat_word("any")? {
            return Ok(Quant::Any);
        }
        if self.eat_word("none")? {
            return Ok(Quant::None);
        }
        let e = Box::new(self.postfix()?);
        Ok(if self.eat("%")? { Quant::Percent(e) } else { Quant::Count(e) })
    }

    /// `for <quant> of <strings> : (…)` or `for <quant> <vars> in <iterable> : (…)`.
    fn for_expr(&mut self) -> Result<Expr, Error> {
        let quant = self.quantifier()?;
        if self.eat_word("of")? {
            let strings = if self.eat_word("them")? {
                StrSet::Them
            } else {
                self.expect("(")?;
                StrSet::Ids(self.str_ids()?)
            };
            let body = self.body()?;
            return Ok(Expr::ForOf { quant, strings, body });
        }
        let mut vars = vec![self.name()?];
        while self.eat(",")? {
            vars.push(self.name()?);
        }
        self.expect_word("in")?;
        let iter = if self.eat("(")? {
            let first = self.expr()?;
            if self.eat("..")? {
                let hi = self.expr()?;
                self.expect(")")?;
                Iterable::Range(Box::new(first), Box::new(hi))
            } else {
                let mut items = vec![first];
                while self.eat(",")? {
                    items.push(self.expr()?);
                }
                self.expect(")")?;
                Iterable::List(items)
            }
        } else {
            Iterable::Expr(Box::new(self.postfix()?))
        };
        let body = self.body()?;
        Ok(Expr::ForIn { quant, vars, iter, body })
    }

    /// `: ( condition )`
    fn body(&mut self) -> Result<Box<Expr>, Error> {
        self.expect(":")?;
        self.expect("(")?;
        let body = self.expr()?;
        self.expect(")")?;
        Ok(Box::new(body))
    }

    /// yara-x's `with a = expr, b = expr : ( condition )`.
    fn with_expr(&mut self) -> Result<Expr, Error> {
        let mut binds = Vec::new();
        loop {
            let name = self.name()?;
            self.expect("=")?;
            binds.push((name, self.expr()?));
            if !self.eat(",")? {
                break;
            }
        }
        let body = self.body()?;
        Ok(Expr::With { binds, body })
    }
}

fn describe(tok: &Tok) -> String {
    match tok {
        Tok::Ident(w) => format!("`{w}`"),
        Tok::Punct(p) => format!("`{p}`"),
        Tok::Eof => "the end of the file".into(),
        Tok::Int(i) => format!("`{i}`"),
        Tok::Float(f) => format!("`{f}`"),
        Tok::Text(_) => "a string".into(),
        Tok::Regex { .. } => "a regular expression".into(),
        Tok::StrId(s) => format!("`${s}`"),
        Tok::StrCount(s) => format!("`#{s}`"),
        Tok::StrOffset(s) => format!("`@{s}`"),
        Tok::StrLength(s) => format!("`!{s}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(src: &str) -> Rule {
        let mut f = parse(src, Syntax::Strict).unwrap();
        assert_eq!(f.rules.len(), 1);
        f.rules.pop().unwrap()
    }

    fn cond(c: &str) -> Expr {
        one(&format!("rule r {{ strings: $a = \"x\" $b = \"y\" condition: {c} }}")).condition
    }

    #[test]
    fn rule_header_meta_and_tags() {
        let f = parse(
            r#"import "pe" import "math"
            private global rule r : t1 t2 { meta: a = "x" b = -3 c = true d = false e = 1.5 condition: true }"#,
            Syntax::Strict,
        )
        .unwrap();
        assert_eq!(f.imports, ["pe", "math"]);
        let r = &f.rules[0];
        assert!(r.private && r.global);
        assert_eq!(r.tags, ["t1", "t2"]);
        assert_eq!(r.meta[0], ("a".into(), Meta::Str(b"x".to_vec())));
        assert_eq!(r.meta[1].1, Meta::Int(-3));
        assert_eq!(r.meta[2].1, Meta::Bool(true));
        assert_eq!(r.meta[3].1, Meta::Bool(false));
        assert_eq!(r.meta[4].1, Meta::Str(b"1.5".to_vec()));
    }

    #[test]
    fn strings_and_modifiers() {
        let r = one(r#"rule r { strings:
                $a = "abc" nocase wide ascii fullword private
                $b = "abc" xor(1-3)
                $c = "abc" base64 base64wide("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                $d = { 4D 5A } private
                $e = /a+b/i wide
                $ = "anon"
                $ = "anon2"
              condition: any of them }"#);
        assert_eq!(r.strings.len(), 7);
        let m = &r.strings[0].mods;
        assert!(m.nocase && m.wide && m.ascii && m.fullword && m.private);
        assert_eq!(r.strings[1].mods.xor, Some((1, 3)));
        assert_eq!(r.strings[2].mods.base64.as_deref(), Some(BASE64_STANDARD));
        assert!(r.strings[2].mods.base64wide.is_some());
        assert!(matches!(r.strings[3].kind, StringKind::Hex(_)));
        assert!(matches!(r.strings[4].kind, StringKind::Regex(_)));
        assert!(r.strings[5].id.starts_with('\0') && r.strings[5].id != r.strings[6].id);
        assert_eq!(one(r#"rule r { strings: $a = "x" xor condition: $a }"#).strings[0].mods.xor, Some((0, 255)));
        assert_eq!(one(r#"rule r { strings: $a = "x" xor(7) condition: $a }"#).strings[0].mods.xor, Some((7, 7)));
    }

    #[test]
    fn string_errors() {
        for bad in [
            r#"rule r { strings: $a = "x" $a = "y" condition: $a }"#,
            r#"rule r { strings: $a = { 4D } nocase condition: $a }"#,
            r#"rule r { strings: $a = /x/ xor condition: $a }"#,
            r#"rule r { strings: $a = "x" xor nocase condition: $a }"#,
            r#"rule r { strings: $a = "x" base64 nocase condition: $a }"#,
            r#"rule r { strings: $a = "x" xor(3-1) condition: $a }"#,
            r#"rule r { strings: $a = "x" xor(300) condition: $a }"#,
            r#"rule r { strings: $a = "x" base64("short") condition: $a }"#,
            r#"rule r { strings: $a = "" condition: $a }"#,
            r#"rule r { strings: $a* = "x" condition: $a }"#,
            r#"rule r { strings: $a = 3 condition: $a }"#,
            r#"private private rule r { condition: true }"#,
            r#"rule and { condition: true }"#,
            r#"include "x.yar""#,
            r#"import pe"#,
            r#"rule r { meta: a = b condition: true }"#,
            r#"rule r { condition: true"#,
        ] {
            assert!(parse(bad, Syntax::Strict).is_err(), "{bad}");
        }
        // Relaxed mode allows a repeated modifier, as classic YARA does.
        assert!(parse("private private rule r { condition: true }", Syntax::Relaxed).is_ok());
    }

    #[test]
    fn precedence() {
        // not binds looser than ==, and looser than or? no: or < and < not < ==.
        let Expr::Binary(BinOp::Or, a, b) = cond("true or false and $a") else { panic!() };
        assert!(matches!(*a, Expr::Bool(true)));
        assert!(matches!(*b, Expr::Binary(BinOp::And, ..)));
        let Expr::Unary(UnOp::Not, inner) = cond("not 1 == 2") else { panic!() };
        assert!(matches!(*inner, Expr::Binary(BinOp::Eq, ..)));
        let Expr::Binary(BinOp::Eq, l, _) = cond("1 + 2 * 3 == 7") else { panic!() };
        let Expr::Binary(BinOp::Add, _, r) = *l else { panic!() };
        assert!(matches!(*r, Expr::Binary(BinOp::Mul, ..)));
        assert!(matches!(cond("-1 < ~2"), Expr::Binary(BinOp::Lt, ..)));
        assert!(matches!(cond("1 | 2 ^ 3 & 4 << 5 > 0"), Expr::Binary(BinOp::Gt, ..)));
        assert!(matches!(cond("defined 1"), Expr::Unary(UnOp::Defined, _)));
    }

    #[test]
    fn string_references() {
        assert!(matches!(cond("$a at 10 + 2"), Expr::StrMatch { anchor: Some(Anchor::At(_)), .. }));
        assert!(matches!(cond("$a in (0..100)"), Expr::StrMatch { anchor: Some(Anchor::In(..)), .. }));
        assert!(matches!(cond("#a in (0..filesize) > 2"), Expr::Binary(BinOp::Gt, ..)));
        assert!(matches!(cond("@a[2] == 5"), Expr::Binary(BinOp::Eq, ..)));
        assert!(matches!(cond("!a == 5"), Expr::Binary(BinOp::Eq, ..)));
        assert!(matches!(cond("@a"), Expr::StrOffset { index: None, .. }));
        assert!(parse("rule r { condition: $a* }", Syntax::Strict).is_err());
    }

    #[test]
    fn quantifiers() {
        assert!(matches!(
            cond("all of them"),
            Expr::Of { quant: Quant::All, items: OfItems::Strings(StrSet::Them), .. }
        ));
        assert!(matches!(
            cond("any of ($a*, $b)"),
            Expr::Of { quant: Quant::Any, items: OfItems::Strings(StrSet::Ids(_)), .. }
        ));
        assert!(matches!(cond("2 of them"), Expr::Of { quant: Quant::Count(_), .. }));
        assert!(matches!(cond("50% of them"), Expr::Of { quant: Quant::Percent(_), .. }));
        assert!(matches!(cond("none of them in (0..10)"), Expr::Of { anchor: Some(Anchor::In(..)), .. }));
        assert!(matches!(cond("any of them at 0"), Expr::Of { anchor: Some(Anchor::At(_)), .. }));
        let Expr::Of { items: OfItems::Rules(rules), .. } = cond("any of (r1, r2*)") else { panic!() };
        assert_eq!(rules, ["r1", "r2*"]);
        assert!(matches!(cond("1 of (true, $a, 1 > 2)"), Expr::Of { items: OfItems::Exprs(_), .. }));
        assert!(matches!(cond("10 % 3 == 1"), Expr::Binary(BinOp::Eq, ..)));
    }

    #[test]
    fn loops_and_with() {
        assert!(matches!(cond("for any of ($a*) : ($ at 0)"), Expr::ForOf { .. }));
        assert!(matches!(cond("for all of them : (# > 1)"), Expr::ForOf { .. }));
        assert!(matches!(cond("for 2 i in (1..#a) : (@a[i] > 0)"), Expr::ForIn { iter: Iterable::Range(..), .. }));
        assert!(matches!(
            cond("for 50% i in (1, 2, 3) : (i > 0)"),
            Expr::ForIn { quant: Quant::Percent(_), iter: Iterable::List(_), .. }
        ));
        let Expr::ForIn { vars, iter: Iterable::Expr(_), .. } = cond("for any k, v in pe.version_info : (k == \"x\")")
        else {
            panic!()
        };
        assert_eq!(vars, ["k", "v"]);
        assert!(matches!(cond("with a = 1, b = 2 : (a < b)"), Expr::With { .. }));
        assert!(matches!(cond("pe.imports(\"k\", \"f\")"), Expr::Call(..)));
        assert!(matches!(cond("pe.sections[0].name == \".text\""), Expr::Binary(BinOp::Eq, ..)));
        assert!(matches!(cond("pe.number_of_sections matches /x/"), Expr::Binary(BinOp::Matches, ..)));
    }

    #[test]
    fn recovery_skips_a_bad_rule() {
        let src = r#"rule good1 { condition: true }
            rule bad { strings: $a = "x" condition: $a and }
            rule good2 { strings: $h = { 4D } condition: $h }
            rule ` { }
            rule good3 { condition: false }"#;
        let (file, errors) = parse_recovering(src, Syntax::Strict);
        assert_eq!(file.rules.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["good1", "good2", "good3"]);
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].0, "bad");
        assert!(parse(src, Syntax::Strict).is_err());
    }

    #[test]
    fn condition_errors() {
        for bad in
            ["(", "1 +", "for any i in x", "for any of $a : (true)", "with a 1 : (a)", "of them", "$a at", "pe.", "x[1"]
        {
            let src = format!("rule r {{ strings: $a = \"x\" condition: {bad} }}");
            assert!(parse(&src, Syntax::Strict).is_err(), "{bad}");
        }
    }
}
