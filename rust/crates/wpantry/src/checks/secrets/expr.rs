//! The subset of [Expr](https://expr-lang.org/) betterleaks' filter programs
//! use, so a rule whose filter is a program (`filter_expr` meta) runs that
//! program, as written, rather than a port of it: `let` bindings, `? :`,
//! `|| && !`, comparisons, `+ -`, `contains`, string and list slicing and
//! indexing, and the functions in [`call`]. Regexes are Go's RE2
//! ([`Syntax::Re2`]). A program that fails to run keeps its finding, as
//! betterleaks does.

use super::{entropy, readable};
use std::cell::RefCell;
use std::collections::HashMap;
use wpantry_yara::matcher::{self, Matcher};
use wpantry_yara::pattern::{self, Node, Syntax};

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Nil,
    Bool(bool),
    Num(f64),
    Str(Vec<u8>),
    List(Vec<Value>),
    /// `finding` or `attributes`, read by key.
    Map(&'static str),
}

/// What a program reads: `finding[...]` and `attributes[...]`.
pub struct Env<'a> {
    pub finding: Vec<(&'static str, Value)>,
    pub attributes: Vec<(&'static str, Value)>,
    /// Set by `filter.setConfidence(level)`.
    pub confidence: RefCell<Option<String>>,
    pub _text: std::marker::PhantomData<&'a ()>,
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Num(f64),
    Str(Vec<u8>),
    Name(String),
    Op(&'static str),
}

#[derive(Clone, Debug)]
enum Expr {
    Lit(Value),
    Var(String),
    List(Vec<Expr>),
    Call(String, Vec<Expr>),
    Index(Box<Expr>, Box<Expr>),
    Slice(Box<Expr>, Option<Box<Expr>>, Option<Box<Expr>>),
    Unary(&'static str, Box<Expr>),
    Binary(&'static str, Box<Expr>, Box<Expr>),
    Cond(Box<Expr>, Box<Expr>, Box<Expr>),
    Let(String, Box<Expr>, Box<Expr>),
}

/// A compiled filter program.
#[derive(Clone, Debug)]
pub struct Program(Expr);

const OPS: [&str; 22] = [
    "||", "&&", "==", "!=", "<=", ">=", "??", "?.", "!", "<", ">", "+", "-", "*", "/", "?", ":", ",", "(", ")", "[",
    "]",
];
const MORE_OPS: [&str; 4] = [";", "=", "{", "}"];

fn tokenize(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'`' {
            let end = b[i + 1..].iter().position(|&x| x == b'`').ok_or("unclosed `")? + i + 1;
            out.push(Tok::Str(b[i + 1..end].to_vec()));
            i = end + 1;
        } else if c == b'"' {
            let mut s = Vec::new();
            i += 1;
            loop {
                let ch = *b.get(i).ok_or("unclosed \"")?;
                i += 1;
                match ch {
                    b'"' => break,
                    b'\\' => {
                        let e = *b.get(i).ok_or("bad escape")?;
                        i += 1;
                        s.push(match e {
                            b'n' => b'\n',
                            b't' => b'\t',
                            b'r' => b'\r',
                            other => other,
                        });
                    }
                    other => s.push(other),
                }
            }
            out.push(Tok::Str(s));
        } else if c.is_ascii_digit() {
            let start = i;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            out.push(Tok::Num(src[start..i].parse().map_err(|_| "bad number")?));
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'.') {
                i += 1;
            }
            out.push(Tok::Name(src[start..i].to_string()));
        } else if let Some(op) = OPS.iter().chain(MORE_OPS.iter()).find(|op| b[i..].starts_with(op.as_bytes())) {
            out.push(Tok::Op(op));
            i += op.len();
        } else {
            return Err(format!("unexpected {:?}", c as char));
        }
    }
    Ok(out)
}

struct Parser {
    t: Vec<Tok>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }
    fn is_op(&self, op: &str) -> bool {
        matches!(self.peek(), Some(Tok::Op(o)) if *o == op)
    }
    fn is_name(&self, n: &str) -> bool {
        matches!(self.peek(), Some(Tok::Name(x)) if x == n)
    }
    fn expect(&mut self, op: &str) -> Result<(), String> {
        if self.is_op(op) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected {op}, got {:?}", self.peek()))
        }
    }

    fn program(&mut self) -> Result<Expr, String> {
        if self.is_name("let") {
            self.i += 1;
            let Some(Tok::Name(name)) = self.peek().cloned() else { return Err("let needs a name".into()) };
            self.i += 1;
            self.expect("=")?;
            let value = self.expr()?;
            self.expect(";")?;
            let rest = self.program()?;
            return Ok(Expr::Let(name, Box::new(value), Box::new(rest)));
        }
        self.expr()
    }

    fn expr(&mut self) -> Result<Expr, String> {
        // `let` may open any expression, a parenthesized one included.
        if self.is_name("let") {
            return self.program();
        }
        let c = self.or()?;
        if self.is_op("?") {
            self.i += 1;
            let a = self.expr()?;
            self.expect(":")?;
            let b = self.expr()?;
            return Ok(Expr::Cond(Box::new(c), Box::new(a), Box::new(b)));
        }
        Ok(c)
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut e = self.and()?;
        while self.is_op("||") || self.is_name("or") {
            self.i += 1;
            e = Expr::Binary("||", Box::new(e), Box::new(self.and()?));
        }
        Ok(e)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut e = self.not()?;
        while self.is_op("&&") || self.is_name("and") {
            self.i += 1;
            e = Expr::Binary("&&", Box::new(e), Box::new(self.not()?));
        }
        Ok(e)
    }

    fn not(&mut self) -> Result<Expr, String> {
        if self.is_op("!") || self.is_name("not") {
            self.i += 1;
            return Ok(Expr::Unary("!", Box::new(self.not()?)));
        }
        self.cmp()
    }

    fn cmp(&mut self) -> Result<Expr, String> {
        let e = self.add()?;
        for op in ["==", "!=", "<=", ">=", "<", ">"] {
            if self.is_op(op) {
                self.i += 1;
                return Ok(Expr::Binary(op, Box::new(e), Box::new(self.add()?)));
            }
        }
        for op in ["contains", "startsWith", "endsWith", "in"] {
            if self.is_name(op) {
                self.i += 1;
                let name: &'static str = match op {
                    "contains" => "contains",
                    "startsWith" => "startsWith",
                    "endsWith" => "endsWith",
                    _ => "in",
                };
                return Ok(Expr::Binary(name, Box::new(e), Box::new(self.add()?)));
            }
        }
        Ok(e)
    }

    fn add(&mut self) -> Result<Expr, String> {
        let mut e = self.unary()?;
        loop {
            let op = if self.is_op("+") {
                "+"
            } else if self.is_op("-") {
                "-"
            } else {
                return Ok(e);
            };
            self.i += 1;
            e = Expr::Binary(op, Box::new(e), Box::new(self.unary()?));
        }
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.is_op("-") {
            self.i += 1;
            return Ok(Expr::Unary("-", Box::new(self.unary()?)));
        }
        self.postfix()
    }

    fn postfix(&mut self) -> Result<Expr, String> {
        let mut e = self.primary()?;
        while self.is_op("[") {
            self.i += 1;
            let lo = if self.is_op(":") { None } else { Some(Box::new(self.expr()?)) };
            if self.is_op(":") {
                self.i += 1;
                let hi = if self.is_op("]") { None } else { Some(Box::new(self.expr()?)) };
                self.expect("]")?;
                e = Expr::Slice(Box::new(e), lo, hi);
            } else {
                self.expect("]")?;
                e = Expr::Index(Box::new(e), lo.ok_or("empty index")?);
            }
        }
        Ok(e)
    }

    fn primary(&mut self) -> Result<Expr, String> {
        let tok = self.peek().cloned().ok_or("unexpected end")?;
        self.i += 1;
        match tok {
            Tok::Num(n) => Ok(Expr::Lit(Value::Num(n))),
            Tok::Str(s) => Ok(Expr::Lit(Value::Str(s))),
            Tok::Op("(") => {
                let e = self.expr()?;
                self.expect(")")?;
                Ok(e)
            }
            Tok::Op("[") => {
                let mut items = Vec::new();
                while !self.is_op("]") {
                    items.push(self.expr()?);
                    if self.is_op(",") {
                        self.i += 1;
                    }
                }
                self.i += 1;
                Ok(Expr::List(items))
            }
            Tok::Name(n) if n == "true" => Ok(Expr::Lit(Value::Bool(true))),
            Tok::Name(n) if n == "false" => Ok(Expr::Lit(Value::Bool(false))),
            Tok::Name(n) if n == "nil" => Ok(Expr::Lit(Value::Nil)),
            Tok::Name(n) => {
                if self.is_op("(") {
                    self.i += 1;
                    let mut args = Vec::new();
                    while !self.is_op(")") {
                        args.push(self.expr()?);
                        if self.is_op(",") {
                            self.i += 1;
                        }
                    }
                    self.i += 1;
                    return Ok(Expr::Call(n, args));
                }
                Ok(Expr::Var(n))
            }
            other => Err(format!("unexpected {other:?}")),
        }
    }
}

impl Program {
    pub fn compile(src: &str) -> Result<Program, String> {
        let mut p = Parser { t: tokenize(src)?, i: 0 };
        let e = p.program()?;
        if p.i != p.t.len() {
            return Err(format!("trailing {:?}", p.peek()));
        }
        Ok(Program(e))
    }

    /// Whether the program says to skip the finding; None if it failed.
    pub fn skips(&self, env: &Env) -> Option<bool> {
        let mut vars = Vec::new();
        match eval(&self.0, env, &mut vars) {
            Ok(Value::Bool(b)) => Some(b),
            _ => None,
        }
    }
}

thread_local! {
    static REGEXES: RefCell<HashMap<Vec<u8>, Option<Node>>> = RefCell::new(HashMap::new());
}

/// `pattern` compiled as Go's RE2, cached per thread.
pub fn re2(pattern: &[u8]) -> Option<Node> {
    REGEXES.with(|c| {
        c.borrow_mut()
            .entry(pattern.to_vec())
            .or_insert_with(|| pattern::parse_regex(pattern, false, false, Syntax::Re2, 0).ok())
            .clone()
    })
}

fn truthy(v: &Value) -> bool {
    matches!(v, Value::Bool(true))
}

fn num(v: &Value) -> Result<f64, String> {
    match v {
        Value::Num(n) => Ok(*n),
        other => Err(format!("not a number: {other:?}")),
    }
}

fn bytes(v: &Value) -> Result<&[u8], String> {
    match v {
        Value::Str(s) => Ok(s),
        other => Err(format!("not a string: {other:?}")),
    }
}

fn list(v: &Value) -> Result<Vec<Vec<u8>>, String> {
    match v {
        Value::List(items) => items.iter().map(|i| bytes(i).map(<[u8]>::to_vec)).collect(),
        other => Err(format!("not a list: {other:?}")),
    }
}

fn clamp(i: f64, len: usize) -> usize {
    if i < 0.0 { 0 } else { (i as usize).min(len) }
}

fn eval(e: &Expr, env: &Env, vars: &mut Vec<(String, Value)>) -> Result<Value, String> {
    Ok(match e {
        Expr::Lit(v) => v.clone(),
        Expr::Var(name) => match name.as_str() {
            "finding" => Value::Map("finding"),
            "attributes" => Value::Map("attributes"),
            _ => vars.iter().rev().find(|(n, _)| n == name).map(|(_, v)| v.clone()).ok_or(format!("no {name}"))?,
        },
        Expr::List(items) => Value::List(items.iter().map(|i| eval(i, env, vars)).collect::<Result<_, _>>()?),
        Expr::Let(name, value, rest) => {
            let v = eval(value, env, vars)?;
            vars.push((name.clone(), v));
            let out = eval(rest, env, vars);
            vars.pop();
            out?
        }
        Expr::Cond(c, a, b) => {
            if truthy(&eval(c, env, vars)?) {
                eval(a, env, vars)?
            } else {
                eval(b, env, vars)?
            }
        }
        Expr::Unary("!", a) => Value::Bool(!truthy(&eval(a, env, vars)?)),
        Expr::Unary(_, a) => Value::Num(-num(&eval(a, env, vars)?)?),
        Expr::Binary("||", a, b) => Value::Bool(truthy(&eval(a, env, vars)?) || truthy(&eval(b, env, vars)?)),
        Expr::Binary("&&", a, b) => Value::Bool(truthy(&eval(a, env, vars)?) && truthy(&eval(b, env, vars)?)),
        Expr::Binary(op, a, b) => {
            let (a, b) = (eval(a, env, vars)?, eval(b, env, vars)?);
            binary(op, &a, &b)?
        }
        Expr::Index(target, key) => {
            let t = eval(target, env, vars)?;
            let k = eval(key, env, vars)?;
            match (&t, &k) {
                (Value::Map(m), Value::Str(key)) => {
                    let fields = if *m == "finding" { &env.finding } else { &env.attributes };
                    fields
                        .iter()
                        .find(|(n, _)| n.as_bytes() == key.as_slice())
                        .map(|(_, v)| v.clone())
                        .unwrap_or(Value::Str(Vec::new()))
                }
                (Value::List(items), Value::Num(i)) => {
                    let i = if *i < 0.0 { items.len() as f64 + i } else { *i };
                    items.get(i as usize).cloned().ok_or("index out of range")?
                }
                (Value::Str(s), Value::Num(i)) => Value::Str(vec![*s.get(*i as usize).ok_or("index out of range")?]),
                _ => return Err("bad index".into()),
            }
        }
        Expr::Slice(target, lo, hi) => {
            let t = eval(target, env, vars)?;
            let len = match &t {
                Value::Str(s) => s.len(),
                Value::List(l) => l.len(),
                _ => return Err("bad slice".into()),
            };
            let lo = match lo {
                Some(x) => clamp(num(&eval(x, env, vars)?)?, len),
                None => 0,
            };
            let hi = match hi {
                Some(x) => clamp(num(&eval(x, env, vars)?)?, len),
                None => len,
            };
            let hi = hi.max(lo);
            match t {
                Value::Str(s) => Value::Str(s[lo..hi].to_vec()),
                Value::List(l) => Value::List(l[lo..hi].to_vec()),
                _ => unreachable!(),
            }
        }
        Expr::Call(name, args) => {
            let args: Vec<Value> = args.iter().map(|a| eval(a, env, vars)).collect::<Result<_, _>>()?;
            call(name, &args, env)?
        }
    })
}

fn binary(op: &str, a: &Value, b: &Value) -> Result<Value, String> {
    Ok(match op {
        "==" => Value::Bool(a == b),
        "!=" => Value::Bool(a != b),
        "<" => Value::Bool(num(a)? < num(b)?),
        "<=" => Value::Bool(num(a)? <= num(b)?),
        ">" => Value::Bool(num(a)? > num(b)?),
        ">=" => Value::Bool(num(a)? >= num(b)?),
        "-" => Value::Num(num(a)? - num(b)?),
        "+" => match (a, b) {
            (Value::Str(x), Value::Str(y)) => Value::Str([x.as_slice(), y].concat()),
            _ => Value::Num(num(a)? + num(b)?),
        },
        "contains" => Value::Bool(super::contains(bytes(a)?, bytes(b)?)),
        "startsWith" => Value::Bool(bytes(a)?.starts_with(bytes(b)?)),
        "endsWith" => Value::Bool(bytes(a)?.ends_with(bytes(b)?)),
        "in" => match b {
            Value::List(items) => Value::Bool(items.contains(a)),
            _ => return Err("in needs a list".into()),
        },
        _ => return Err(format!("operator {op}")),
    })
}

fn call(name: &str, args: &[Value], env: &Env) -> Result<Value, String> {
    let arg = |i: usize| args.get(i).ok_or(format!("{name} needs {} arguments", i + 1));
    Ok(match name {
        "entropy" | "filter.entropy" => Value::Num(entropy(bytes(arg(0)?)?)),
        // Pantry reads text as having an unbounded token ratio, a key as none.
        "filter.tokenRatio" => Value::Num(if readable::readable(bytes(arg(0)?)?) { f64::INFINITY } else { 0.0 }),
        "filter.failsTokenEfficiency" => Value::Bool(readable::readable(bytes(arg(0)?)?)),
        "matchesAny" | "filter.matchesAny" => {
            let text = bytes(arg(0)?)?;
            let mut any = false;
            for p in list(arg(1)?)? {
                let re = re2(&p).ok_or(format!("bad regex {}", String::from_utf8_lossy(&p)))?;
                if matcher::search(&re, text) {
                    any = true;
                    break;
                }
            }
            Value::Bool(any)
        }
        "containsAny" | "filter.containsAny" => {
            let text = bytes(arg(0)?)?.to_ascii_lowercase();
            Value::Bool(list(arg(1)?)?.iter().any(|w| super::contains(&text, &w.to_ascii_lowercase())))
        }
        "filter.findMatch" => {
            let text = bytes(arg(0)?)?;
            let p = bytes(arg(1)?)?;
            let re = re2(p).ok_or("bad regex")?;
            let found =
                (0..=text.len()).find_map(|s| Matcher::new(text, s, true, text.len()).first(&re, s).map(|e| (s, e)));
            Value::Str(found.map(|(s, e)| text[s..e].to_vec()).unwrap_or_default())
        }
        "filter.setConfidence" => {
            let level = String::from_utf8_lossy(bytes(arg(0)?)?).into_owned();
            *env.confidence.borrow_mut() = Some(level.clone());
            Value::Str(level.into_bytes())
        }
        "len" => Value::Num(match arg(0)? {
            Value::Str(s) => s.len(),
            Value::List(l) => l.len(),
            _ => return Err("len of what".into()),
        } as f64),
        "max" => Value::Num(args.iter().map(num).collect::<Result<Vec<_>, _>>()?.into_iter().fold(f64::MIN, f64::max)),
        "min" => Value::Num(args.iter().map(num).collect::<Result<Vec<_>, _>>()?.into_iter().fold(f64::MAX, f64::min)),
        "lower" => Value::Str(bytes(arg(0)?)?.to_ascii_lowercase()),
        "upper" => Value::Str(bytes(arg(0)?)?.to_ascii_uppercase()),
        "trim" => Value::Str(bytes(arg(0)?)?.trim_ascii().to_vec()),
        "split" => {
            let (s, sep) = (bytes(arg(0)?)?, bytes(arg(1)?)?);
            if sep.is_empty() {
                return Err("split on nothing".into());
            }
            let mut parts = Vec::new();
            let mut rest = s;
            while let Some(at) = rest.windows(sep.len()).position(|w| w == sep) {
                parts.push(Value::Str(rest[..at].to_vec()));
                rest = &rest[at + sep.len()..];
            }
            parts.push(Value::Str(rest.to_vec()));
            Value::List(parts)
        }
        "join" => {
            let sep = bytes(arg(1)?)?;
            Value::Str(list(arg(0)?)?.join(sep))
        }
        _ => return Err(format!("no function {name}")),
    })
}

#[cfg(test)]
#[path = "expr_tests.rs"]
mod tests;
