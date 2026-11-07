//! Rules to a scannable [`Rules`]: strings to atoms, conditions to closures.
//!
//! Each condition is compiled once into a tree of boxed closures, each node
//! a `Fn(&Ctx) -> Value` that holds its children; evaluating a rule is calling
//! the root. Identifiers, string names, module fields and loop variables are
//! all resolved here, so a name is never looked up while scanning. A rule that
//! doesn't compile is set aside with its reason ([`Rejected`]) and the rest of
//! the file still loads.

use crate::Error;
use crate::ast::*;
use crate::atoms::{AtomTable, Target};
use crate::classify::{self, Os};
use crate::matcher;
use crate::modules::{self, Module};
use crate::parser;
use crate::pattern::{Node, Syntax};
use crate::scan::{Ctx, FileType};
use crate::strings::{self, CompiledString};
use crate::value::{FieldKind, FnCtx, StructType, Type, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub use crate::ast::Meta;

/// A compiled condition (or part of one).
pub type Ev = Box<dyn Fn(&Ctx) -> Value + Send + Sync>;

/// External variables every rule may read; set per scan in
/// [`crate::ScanOptions`]. They are the ones Loki and THOR define, which
/// signature-base's rules use.
pub const EXTERNALS: &[&str] = &["filename", "filepath", "extension", "filetype", "owner"];

/// A rule that didn't compile, and why.
#[derive(Clone, Debug, PartialEq)]
pub struct Rejected {
    pub namespace: String,
    /// Empty when the source didn't parse far enough to name the rule.
    pub rule: String,
    pub error: Error,
}

pub struct CompiledRule {
    pub name: String,
    /// The system its targets run on and the threat it names ([`crate::classify`]).
    pub os: Os,
    pub category: &'static str,
    /// The rule's `score` meta (Forge's), 75 when it has none.
    pub score: i64,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, Meta)>,
    pub private: bool,
    pub global: bool,
    /// Global ids of the rule's strings.
    pub strings: std::ops::Range<u32>,
    pub(crate) cond: Ev,
    /// The kind of file the condition requires, when it requires one.
    pub(crate) needs: Option<FileType>,
    /// The condition is false unless one of the rule's strings matched.
    pub(crate) requires_match: bool,
}

/// Compiled rules, ready to scan with. Shareable across threads.
pub struct Rules {
    pub(crate) rules: Vec<CompiledRule>,
    pub(crate) strings: Vec<CompiledString>,
    /// The rule each string belongs to.
    pub(crate) string_rule: Vec<u32>,
    pub(crate) atoms: AtomTable,
    /// Variants with no atom, tried at every position: `(string, variant)`.
    pub(crate) brute: Vec<(u32, u32)>,
    pub(crate) modules: Vec<Arc<dyn Module>>,
    pub(crate) nslots: usize,
    pub(crate) skipped: usize,
    pub rejected: Vec<Rejected>,
}

/// Sizes of a compiled rule set, for reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    pub rules: usize,
    /// Rules left out by the compiler's filter.
    pub skipped: usize,
    pub strings: usize,
    pub atoms: usize,
    /// String variants with no atom, tried at every position.
    pub unanchored: usize,
}

impl Rules {
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// `(rule, string)` for each string with a variant that has no atom:
    /// the slow ones, worth rewriting.
    pub fn unanchored(&self) -> Vec<(&str, &str)> {
        self.brute
            .iter()
            .map(|(s, _)| {
                (
                    self.rules[self.string_rule[*s as usize] as usize].name.as_str(),
                    self.strings[*s as usize].id.as_str(),
                )
            })
            .collect()
    }

    pub fn stats(&self) -> Stats {
        Stats {
            rules: self.rules.len(),
            skipped: self.skipped,
            strings: self.strings.len(),
            atoms: self.atoms.len(),
            unanchored: self.brute.len(),
        }
    }
}

pub struct Compiler {
    modules: Vec<Arc<dyn Module>>,
    rules: Vec<CompiledRule>,
    strings: Vec<CompiledString>,
    string_rule: Vec<u32>,
    /// `(namespace, rule name)` to rule index.
    names: HashMap<(String, String), usize>,
    rejected: Vec<Rejected>,
    nslots: usize,
    /// Which rules to keep, by system and category; the rest are skipped.
    filter: Option<Filter>,
    skipped: usize,
    /// How far a regex match may run, in bytes ([`strings::REGEX_REACH`] unless set).
    regex_reach: usize,
}

type Filter = Box<dyn Fn(Os, &str) -> bool>;

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Compiler {
    pub fn new() -> Self {
        Compiler {
            modules: modules::builtin(),
            rules: Vec::new(),
            strings: Vec::new(),
            string_rule: Vec::new(),
            names: HashMap::new(),
            rejected: Vec::new(),
            nslots: 0,
            filter: None,
            skipped: 0,
            regex_reach: strings::REGEX_REACH,
        }
    }

    /// How far a regex match may run from where it starts, for the rules added
    /// after this. YARA's 4,096 bytes ([`strings::REGEX_REACH`]) by default; a
    /// secret such as a private key block runs longer.
    pub fn set_regex_reach(&mut self, bytes: usize) {
        self.regex_reach = bytes;
    }

    /// Keep only the rules `keep(os, category)` accepts (this machine's
    /// system and `any`, say); the others are skipped, not rejected. A kept
    /// rule that names a skipped one is rejected as naming an unknown rule.
    pub fn set_filter(&mut self, keep: impl Fn(Os, &str) -> bool + 'static) {
        self.filter = Some(Box::new(keep));
    }

    /// Make a module importable (replacing a built-in of the same name).
    pub fn add_module(&mut self, module: Arc<dyn Module>) {
        self.modules.retain(|m| m.name() != module.name());
        self.modules.push(module);
    }

    /// Compile a rules file into `namespace`; returns how many rules it added.
    /// Rules that fail are recorded in [`Rules::rejected`], and parsing picks
    /// up again at the next rule.
    pub fn add_source(&mut self, namespace: &str, src: &str, syntax: Syntax) -> usize {
        let (file, errors) = parser::parse_recovering(src, syntax);
        for (rule, error) in errors {
            self.rejected.push(Rejected { namespace: namespace.into(), rule, error });
        }
        let mut imports = Vec::new();
        for name in &file.imports {
            if let Some(i) = self.modules.iter().position(|m| m.name() == name) {
                imports.push(i);
            }
        }
        let mut added = 0;
        for rule in file.rules {
            let name = rule.name.clone();
            let used: Vec<String> = file.imports.iter().filter(|m| uses(&rule.condition, m)).cloned().collect();
            let class = classify::classify(&rule.name, &rule.tags, &rule.meta, &used, file_need(&rule.condition));
            if self.filter.as_ref().is_some_and(|keep| !keep(class.0, class.1)) {
                self.skipped += 1;
                continue;
            }
            match self.rule(namespace, &imports, rule, class) {
                Ok(()) => added += 1,
                Err(error) => self.rejected.push(Rejected { namespace: namespace.into(), rule: name, error }),
            }
        }
        added
    }

    fn rule(
        &mut self,
        namespace: &str,
        imports: &[usize],
        rule: Rule,
        (os, category, score): (Os, &'static str, i64),
    ) -> Result<(), Error> {
        let key = (namespace.to_string(), rule.name.clone());
        if self.names.contains_key(&key) {
            return Err(Error::Semantic { line: rule.line, msg: format!("duplicate rule {}", rule.name) });
        }
        let base = self.strings.len() as u32;
        let ids: Vec<(String, u32)> =
            rule.strings.iter().enumerate().map(|(i, s)| (s.id.clone(), base + i as u32)).collect();
        let mut cx = Cx {
            comp: self,
            namespace,
            imports,
            strings: &ids,
            scopes: Vec::new(),
            current: None,
            slots: 0,
            line: rule.line,
        };
        let (cond, _) = cx.value(&rule.condition)?;
        let slots = cx.slots;
        let index = self.rules.len() as u32;
        for def in &rule.strings {
            self.strings.push(strings::compile(def, self.regex_reach));
            self.string_rule.push(index);
        }
        self.nslots = self.nslots.max(slots);
        self.names.insert(key, self.rules.len());
        self.rules.push(CompiledRule {
            name: rule.name,
            os,
            category,
            score,
            namespace: namespace.into(),
            tags: rule.tags,
            meta: rule.meta,
            private: rule.private,
            global: rule.global,
            strings: base..self.strings.len() as u32,
            cond,
            needs: file_need(&rule.condition),
            requires_match: requires_match(&rule.condition),
        });
        Ok(())
    }

    /// Build the atom table and finish.
    pub fn build(self) -> Rules {
        let mut atoms = AtomTable::default();
        let mut brute = Vec::new();
        for (si, s) in self.strings.iter().enumerate() {
            for (vi, v) in s.variants.iter().enumerate() {
                if v.atoms.is_empty() {
                    brute.push((si as u32, vi as u32));
                }
                for (atom, offset) in &v.atoms {
                    atoms.add(atom, Target { string: si as u32, variant: vi as u32, offset: *offset as u32 });
                }
            }
        }
        Rules {
            rules: self.rules,
            strings: self.strings,
            string_rule: self.string_rule,
            atoms,
            brute,
            modules: self.modules,
            nslots: self.nslots,
            skipped: self.skipped,
            rejected: self.rejected,
        }
    }
}

/// What an expression compiles to: a value type, or a regex literal (only
/// valid where `matches` or a module function takes one).
#[derive(Clone, Debug)]
enum Ty {
    V(Type),
    Regex(Arc<Node>),
}

/// A string reference: a fixed string, or the loop's current one (in a slot).
#[derive(Clone, Copy)]
enum SRef {
    Fixed(u32),
    Current(usize),
}

impl SRef {
    fn id(self, c: &Ctx) -> u32 {
        match self {
            SRef::Fixed(id) => id,
            SRef::Current(slot) => c.var(slot).as_int().unwrap_or(0) as u32,
        }
    }
}

type Pred = Box<dyn Fn(&Ctx) -> bool + Send + Sync>;

enum Quantity {
    All,
    Any,
    None,
    Count(Ev),
    Percent(Ev),
}

impl Quantity {
    /// Whether `n` items satisfy it, given each item's truth on demand;
    /// stops as soon as the answer is known.
    fn eval(&self, c: &Ctx, n: usize, mut item: impl FnMut(usize) -> bool) -> bool {
        let need = match self {
            Quantity::All => n,
            Quantity::Any => 1,
            Quantity::None => return (0..n).all(|i| !item(i)),
            Quantity::Count(e) => match e(c).as_int() {
                Some(k) => k.max(0) as usize,
                None => return false,
            },
            Quantity::Percent(e) => match e(c).as_int() {
                Some(p) => (p.max(0) as usize * n).div_ceil(100),
                None => return false,
            },
        };
        let mut count = 0;
        for i in 0..n {
            if count >= need {
                return true;
            }
            if count + (n - i) < need {
                return false;
            }
            if item(i) {
                count += 1;
            }
        }
        count >= need
    }
}

struct Cx<'a> {
    comp: &'a Compiler,
    namespace: &'a str,
    imports: &'a [usize],
    strings: &'a [(String, u32)],
    /// Loop and `with` variables in scope, innermost last.
    scopes: Vec<(String, usize, Type)>,
    /// The slot holding the current string inside `for … of`.
    current: Option<usize>,
    slots: usize,
    line: usize,
}

fn konst(v: Value) -> Ev {
    Box::new(move |_| v.clone())
}

fn bool_ev(f: impl Fn(&Ctx) -> bool + Send + Sync + 'static) -> Ev {
    Box::new(move |c| Value::Bool(f(c)))
}

impl Cx<'_> {
    fn err<T>(&self, msg: impl Into<String>) -> Result<T, Error> {
        Err(Error::Semantic { line: self.line, msg: msg.into() })
    }

    fn slot(&mut self) -> usize {
        self.slots += 1;
        self.slots - 1
    }

    fn value(&mut self, e: &Expr) -> Result<(Ev, Type), Error> {
        match self.expr(e)? {
            (ev, Ty::V(t)) => Ok((ev, t)),
            (_, Ty::Regex(_)) => self.err("a regular expression can only follow `matches`"),
        }
    }

    fn int(&mut self, e: &Expr) -> Result<Ev, Error> {
        match self.value(e)? {
            (ev, Type::Int | Type::Bool) => Ok(ev),
            (_, t) => self.err(format!("expected an integer, found a {}", t.name())),
        }
    }

    fn cond(&mut self, e: &Expr) -> Result<Pred, Error> {
        let (ev, _) = self.value(e)?;
        Ok(Box::new(move |c| ev(c).truthy()))
    }

    fn expr(&mut self, e: &Expr) -> Result<(Ev, Ty), Error> {
        let v = |ev, t| Ok((ev, Ty::V(t)));
        match e {
            Expr::Bool(b) => v(konst(Value::Bool(*b)), Type::Bool),
            Expr::Int(i) => v(konst(Value::Int(*i)), Type::Int),
            Expr::Float(f) => v(konst(Value::Float(*f)), Type::Float),
            Expr::Str(s) => v(konst(Value::str(s)), Type::Str),
            Expr::Regex(node) => {
                let node = Arc::new(node.clone());
                Ok((konst(Value::Regex(node.clone())), Ty::Regex(node)))
            }
            Expr::Filesize => v(Box::new(|c| Value::Int(c.data.len() as i64)), Type::Int),
            Expr::Entrypoint => v(Box::new(|c| modules::entry_point(c.data)), Type::Int),
            Expr::Ident(name) => self.ident(name),
            Expr::Field(base, name) => self.field(base, name),
            Expr::Index(base, index) => self.index(base, index),
            Expr::Call(callee, args) => self.call(callee, args),
            Expr::StrMatch { id, anchor } => {
                let s = self.string_ref(id)?;
                let p = self.anchored(s, anchor.as_ref())?;
                v(bool_ev(p), Type::Bool)
            }
            Expr::StrCount { id, range } => {
                let s = self.string_ref(id)?;
                let ev: Ev = match range {
                    None => Box::new(move |c| Value::Int(c.matches(s.id(c)).len() as i64)),
                    Some((lo, hi)) => {
                        let (lo, hi) = (self.int(lo)?, self.int(hi)?);
                        Box::new(move |c| match (lo(c).as_int(), hi(c).as_int()) {
                            (Some(lo), Some(hi)) => {
                                let m = c.matches(s.id(c));
                                Value::Int(m.iter().filter(|(o, _)| (lo..=hi).contains(&(*o as i64))).count() as i64)
                            }
                            _ => Value::Undef,
                        })
                    }
                };
                v(ev, Type::Int)
            }
            Expr::StrOffset { id, index } => self.nth_match(id, index.as_deref(), |m| m.0),
            Expr::StrLength { id, index } => self.nth_match(id, index.as_deref(), |m| m.1),
            Expr::Unary(op, inner) => self.unary(*op, inner),
            Expr::Binary(op, l, r) => self.binary(*op, l, r),
            Expr::Of { quant, items, anchor } => self.of(quant, items, anchor.as_ref()),
            Expr::ForOf { quant, strings, body } => self.for_of(quant, strings, body),
            Expr::ForIn { quant, vars, iter, body } => self.for_in(quant, vars, iter, body),
            Expr::With { binds, body } => self.with(binds, body),
        }
    }

    fn ident(&mut self, name: &str) -> Result<(Ev, Ty), Error> {
        if let Some((_, slot, ty)) = self.scopes.iter().rev().find(|(n, ..)| n == name) {
            let slot = *slot;
            return Ok((Box::new(move |c| c.var(slot)), Ty::V(ty.clone())));
        }
        if let Some(&m) = self.imports.iter().find(|m| self.comp.modules[**m].name() == name) {
            let schema = self.comp.modules[m].schema();
            return Ok((Box::new(move |c| c.module(m)), Ty::V(Type::Struct(schema))));
        }
        if let Some(&r) = self.comp.names.get(&(self.namespace.to_string(), name.to_string())) {
            return Ok((bool_ev(move |c| c.rule(r)), Ty::V(Type::Bool)));
        }
        if let Some(i) = EXTERNALS.iter().position(|e| *e == name) {
            return Ok((Box::new(move |c| c.external(i)), Ty::V(Type::Str)));
        }
        let hint = if self.comp.modules.iter().any(|m| m.name() == name) { " (missing import?)" } else { "" };
        self.err(format!("unknown identifier `{name}`{hint}"))
    }

    fn structure(&mut self, base: &Expr) -> Result<(Ev, Arc<StructType>), Error> {
        match self.value(base)? {
            (ev, Type::Struct(st)) => Ok((ev, st)),
            (_, t) => self.err(format!("a {} has no fields", t.name())),
        }
    }

    fn field(&mut self, base: &Expr, name: &str) -> Result<(Ev, Ty), Error> {
        let (base, st) = self.structure(base)?;
        match st.lookup(name) {
            Some(FieldKind::Value { ty, slot }) => {
                let slot = *slot;
                Ok((Box::new(move |c| base(c).field(slot)), Ty::V(ty.clone())))
            }
            Some(FieldKind::Const(v)) => {
                let ty = match v {
                    Value::Str(_) => Type::Str,
                    Value::Float(_) => Type::Float,
                    _ => Type::Int,
                };
                Ok((konst(v.clone()), Ty::V(ty)))
            }
            Some(FieldKind::Func(_)) => self.err(format!("`{name}` is a function; call it")),
            None => self.err(format!("unknown field `{name}`")),
        }
    }

    fn index(&mut self, base: &Expr, index: &Expr) -> Result<(Ev, Ty), Error> {
        let (base, t) = self.value(base)?;
        match t {
            Type::Array(elem) => {
                let i = self.int(index)?;
                let ev: Ev = Box::new(move |c| match (base(c), i(c).as_int()) {
                    (Value::Array(a), Some(i)) => {
                        usize::try_from(i).ok().and_then(|i| a.get(i).cloned()).unwrap_or_default()
                    }
                    _ => Value::Undef,
                });
                Ok((ev, Ty::V(*elem)))
            }
            Type::Dict(elem) => {
                let (key, kt) = self.value(index)?;
                if !matches!(kt, Type::Str) {
                    return self.err("a dictionary key is a string");
                }
                let ev: Ev = Box::new(move |c| match (base(c), key(c)) {
                    (Value::Dict(d), Value::Str(k)) => {
                        d.iter().find(|(dk, _)| **dk == *k).map(|(_, v)| v.clone()).unwrap_or_default()
                    }
                    _ => Value::Undef,
                });
                Ok((ev, Ty::V(*elem)))
            }
            t => self.err(format!("a {} can't be indexed", t.name())),
        }
    }

    fn call(&mut self, callee: &Expr, args: &[Expr]) -> Result<(Ev, Ty), Error> {
        if let Expr::Ident(name) = callee
            && let Some(read) = int_reader(name)
        {
            if args.len() != 1 {
                return self.err(format!("{name} takes one offset"));
            }
            let off = self.int(&args[0])?;
            return Ok((
                Box::new(move |c| off(c).as_int().and_then(|o| read(c.data, o)).map_or(Value::Undef, Value::Int)),
                Ty::V(Type::Int),
            ));
        }
        let Expr::Field(base, name) = callee else { return self.err("only functions can be called") };
        // yara-x's `.len()` on a string, array or dictionary.
        if name == "len" && args.is_empty() {
            let (b, t) = self.value(base)?;
            if !matches!(t, Type::Struct(_)) {
                let ev: Ev = Box::new(move |c| match b(c) {
                    Value::Str(s) => Value::Int(s.len() as i64),
                    Value::Array(a) => Value::Int(a.len() as i64),
                    Value::Dict(d) => Value::Int(d.len() as i64),
                    _ => Value::Undef,
                });
                return Ok((ev, Ty::V(Type::Int)));
            }
        }
        let (this, st) = self.structure(base)?;
        let Some(FieldKind::Func(overloads)) = st.lookup(name) else {
            return self.err(format!("unknown function `{name}`"));
        };
        let mut compiled = Vec::new();
        let mut kinds = String::new();
        for a in args {
            let (ev, ty) = self.expr(a)?;
            kinds.push(match ty {
                Ty::Regex(_) => 'r',
                Ty::V(Type::Int | Type::Bool) => 'i',
                Ty::V(Type::Float) => 'f',
                Ty::V(Type::Str) => 's',
                Ty::V(t) => return self.err(format!("a {} can't be a function argument", t.name())),
            });
            compiled.push(ev);
        }
        // An integer may stand in for a float argument.
        let fits = |want: &str| {
            want.len() == kinds.len() && want.chars().zip(kinds.chars()).all(|(w, k)| w == k || (w == 'f' && k == 'i'))
        };
        let Some(func) = overloads.iter().find(|f| f.args == kinds).or_else(|| overloads.iter().find(|f| fits(f.args)))
        else {
            return self.err(format!("no `{name}` takes ({kinds})"));
        };
        let (f, ret) = (func.f, func.ret.clone());
        // A module's own functions (`hash.md5(0, filesize)`, `pe.imphash()`)
        // answer the same for the same arguments all scan long, and rules
        // repeat them: remember their answers. Methods (`signatures[i].valid_on`)
        // depend on `this`, so they always run.
        let memo =
            matches!(base.as_ref(), Expr::Ident(n) if self.imports.iter().any(|m| self.comp.modules[*m].name() == n));
        let ev: Ev = Box::new(move |c| {
            let this = this(c);
            if this.is_undef() {
                return Value::Undef;
            }
            let mut vals = Vec::with_capacity(compiled.len());
            for a in &compiled {
                let v = a(c);
                if v.is_undef() {
                    return Value::Undef;
                }
                vals.push(v);
            }
            if memo {
                c.memoized(f as usize, &vals, || f(&FnCtx { data: c.data, this: &this }, &vals))
            } else {
                f(&FnCtx { data: c.data, this: &this }, &vals)
            }
        });
        Ok((ev, Ty::V(ret)))
    }

    /// `$a` (or `$` in a loop) to the string it names.
    fn string_ref(&self, id: &str) -> Result<SRef, Error> {
        if id.is_empty() {
            return match self.current {
                Some(slot) => Ok(SRef::Current(slot)),
                None => self.err("`$` outside a `for … of` loop"),
            };
        }
        match self.strings.iter().find(|(n, _)| n == id) {
            Some((_, g)) => Ok(SRef::Fixed(*g)),
            None => self.err(format!("undefined string ${id}")),
        }
    }

    /// The strings a set names: `them`, `$a`, `$a*`.
    fn string_set(&self, set: &StrSet) -> Result<Vec<SRef>, Error> {
        let all = || self.strings.iter().map(|(_, g)| SRef::Fixed(*g));
        let refs: Vec<SRef> = match set {
            StrSet::Them => all().collect(),
            StrSet::Ids(ids) => {
                let mut out = Vec::new();
                for id in ids {
                    match id.strip_suffix('*') {
                        Some(prefix) => {
                            let found: Vec<_> = self
                                .strings
                                .iter()
                                .filter(|(n, _)| n.starts_with(prefix) || (prefix.is_empty() && n.starts_with('\0')))
                                .map(|(_, g)| SRef::Fixed(*g))
                                .collect();
                            if found.is_empty() {
                                return self.err(format!("no string matches ${id}"));
                            }
                            out.extend(found);
                        }
                        None => out.push(self.string_ref(id)?),
                    }
                }
                out
            }
        };
        if refs.is_empty() {
            return self.err("the rule has no strings");
        }
        Ok(refs)
    }

    /// Whether string `s` matched, optionally at an offset or in a range.
    fn anchored(&mut self, s: SRef, anchor: Option<&Anchor>) -> Result<Pred, Error> {
        Ok(match anchor {
            None => Box::new(move |c| !c.matches(s.id(c)).is_empty()),
            Some(Anchor::At(at)) => {
                let at = self.int(at)?;
                Box::new(move |c| {
                    let Some(at) = at(c).as_int() else { return false };
                    let m = c.matches(s.id(c));
                    usize::try_from(at).is_ok_and(|at| m.binary_search_by_key(&at, |(o, _)| *o).is_ok())
                })
            }
            Some(Anchor::In(lo, hi)) => {
                let (lo, hi) = (self.int(lo)?, self.int(hi)?);
                Box::new(move |c| match (lo(c).as_int(), hi(c).as_int()) {
                    (Some(lo), Some(hi)) => c.matches(s.id(c)).iter().any(|(o, _)| (lo..=hi).contains(&(*o as i64))),
                    _ => false,
                })
            }
        })
    }

    /// `@a[i]` or `!a[i]` (1-based; `@a` is `@a[1]`).
    fn nth_match(
        &mut self,
        id: &str,
        index: Option<&Expr>,
        pick: fn(&(usize, usize)) -> usize,
    ) -> Result<(Ev, Ty), Error> {
        let s = self.string_ref(id)?;
        let index = match index {
            Some(i) => self.int(i)?,
            None => konst(Value::Int(1)),
        };
        let ev: Ev = Box::new(move |c| {
            let Some(i) = index(c).as_int() else { return Value::Undef };
            let m = c.matches(s.id(c));
            usize::try_from(i - 1).ok().and_then(|i| m.get(i)).map_or(Value::Undef, |m| Value::Int(pick(m) as i64))
        });
        Ok((ev, Ty::V(Type::Int)))
    }

    fn unary(&mut self, op: UnOp, inner: &Expr) -> Result<(Ev, Ty), Error> {
        let (e, t) = self.value(inner)?;
        Ok(match op {
            UnOp::Not => (
                Box::new(move |c| match e(c) {
                    Value::Undef => Value::Undef,
                    v => Value::Bool(!v.truthy()),
                }),
                Ty::V(Type::Bool),
            ),
            UnOp::Defined => (bool_ev(move |c| !e(c).is_undef()), Ty::V(Type::Bool)),
            UnOp::Neg => {
                if !t.is_numeric() {
                    return self.err(format!("can't negate a {}", t.name()));
                }
                (
                    Box::new(move |c| match e(c) {
                        Value::Float(f) => Value::Float(-f),
                        v => v.as_int().map_or(Value::Undef, |i| Value::Int(i.wrapping_neg())),
                    }),
                    Ty::V(if matches!(t, Type::Float) { Type::Float } else { Type::Int }),
                )
            }
            UnOp::BitNot => {
                if !matches!(t, Type::Int | Type::Bool) {
                    return self.err(format!("`~` needs an integer, found a {}", t.name()));
                }
                (Box::new(move |c| e(c).as_int().map_or(Value::Undef, |i| Value::Int(!i))), Ty::V(Type::Int))
            }
        })
    }

    fn binary(&mut self, op: BinOp, l: &Expr, r: &Expr) -> Result<(Ev, Ty), Error> {
        use BinOp::*;
        if op == Matches {
            let (lhs, lt) = self.value(l)?;
            let (_, Ty::Regex(node)) = self.expr(r)? else { return self.err("`matches` needs a regular expression") };
            if !matches!(lt, Type::Str) {
                return self.err("`matches` needs a string on its left");
            }
            return Ok((
                Box::new(move |c| match lhs(c) {
                    Value::Str(s) => Value::Bool(matcher::search(&node, &s)),
                    _ => Value::Undef,
                }),
                Ty::V(Type::Bool),
            ));
        }
        if op == And || op == Or {
            let (lhs, rhs) = (self.cond(l)?, self.cond(r)?);
            let ev = if op == And { bool_ev(move |c| lhs(c) && rhs(c)) } else { bool_ev(move |c| lhs(c) || rhs(c)) };
            return Ok((ev, Ty::V(Type::Bool)));
        }
        let (lhs, lt) = self.value(l)?;
        let (rhs, rt) = self.value(r)?;
        let both_str = matches!((&lt, &rt), (Type::Str, Type::Str));
        let both_num = lt.is_numeric() && rt.is_numeric();
        match op {
            Eq | Ne | Lt | Le | Gt | Ge => {
                if !both_str && !both_num {
                    return self.err(format!("can't compare a {} with a {}", lt.name(), rt.name()));
                }
                let ev: Ev = Box::new(move |c| {
                    let ord = compare(&lhs(c), &rhs(c));
                    ord.map_or(Value::Undef, |o| {
                        Value::Bool(match op {
                            Eq => o.is_eq(),
                            Ne => o.is_ne(),
                            Lt => o.is_lt(),
                            Le => o.is_le(),
                            Gt => o.is_gt(),
                            _ => o.is_ge(),
                        })
                    })
                });
                Ok((ev, Ty::V(Type::Bool)))
            }
            Contains | IContains | StartsWith | IStartsWith | EndsWith | IEndsWith | IEquals => {
                if !both_str {
                    return self.err(format!("`{op:?}` needs two strings"));
                }
                let ev: Ev = Box::new(move |c| match (lhs(c), rhs(c)) {
                    (Value::Str(a), Value::Str(b)) => Value::Bool(string_op(op, &a, &b)),
                    _ => Value::Undef,
                });
                Ok((ev, Ty::V(Type::Bool)))
            }
            _ => {
                if !both_num {
                    return self.err(format!("arithmetic needs numbers, found a {} and a {}", lt.name(), rt.name()));
                }
                let float = matches!(lt, Type::Float) || matches!(rt, Type::Float);
                if float && matches!(op, BitOr | BitXor | BitAnd | Shl | Shr | Mod) {
                    return self.err("bitwise operators and `%` need integers");
                }
                let ev: Ev = Box::new(move |c| arith(op, &lhs(c), &rhs(c)));
                Ok((ev, Ty::V(if float { Type::Float } else { Type::Int })))
            }
        }
    }

    fn quantity(&mut self, q: &Quant) -> Result<Quantity, Error> {
        Ok(match q {
            Quant::All => Quantity::All,
            Quant::Any => Quantity::Any,
            Quant::None => Quantity::None,
            Quant::Count(e) => Quantity::Count(self.int(e)?),
            Quant::Percent(e) => Quantity::Percent(self.int(e)?),
        })
    }

    fn of(&mut self, quant: &Quant, items: &OfItems, anchor: Option<&Anchor>) -> Result<(Ev, Ty), Error> {
        let q = self.quantity(quant)?;
        let preds: Vec<Pred> = match items {
            OfItems::Strings(set) => {
                let refs = self.string_set(set)?;
                let mut preds = Vec::new();
                for s in refs {
                    preds.push(self.anchored(s, anchor)?);
                }
                preds
            }
            OfItems::Rules(names) => {
                let mut preds: Vec<Pred> = Vec::new();
                for name in names {
                    let found: Vec<usize> = match name.strip_suffix('*') {
                        Some(prefix) => {
                            let mut v: Vec<usize> = self
                                .comp
                                .names
                                .iter()
                                .filter(|((ns, n), _)| ns == self.namespace && n.starts_with(prefix))
                                .map(|(_, i)| *i)
                                .collect();
                            v.sort();
                            v
                        }
                        None => self
                            .comp
                            .names
                            .get(&(self.namespace.to_string(), name.clone()))
                            .into_iter()
                            .copied()
                            .collect(),
                    };
                    if found.is_empty() {
                        // Not a rule: a boolean item (yara-x's tuples), such as a loop variable.
                        let (ev, _) = self.ident(name)?;
                        preds.push(Box::new(move |c| ev(c).truthy()));
                    }
                    for r in found {
                        preds.push(Box::new(move |c| c.rule(r)));
                    }
                }
                preds
            }
            OfItems::Exprs(exprs) => {
                let mut preds = Vec::new();
                for e in exprs {
                    preds.push(self.cond(e)?);
                }
                preds
            }
        };
        Ok((bool_ev(move |c| q.eval(c, preds.len(), |i| preds[i](c))), Ty::V(Type::Bool)))
    }

    fn for_of(&mut self, quant: &Quant, strings: &StrSet, body: &Expr) -> Result<(Ev, Ty), Error> {
        let q = self.quantity(quant)?;
        let refs = self.string_set(strings)?;
        let slot = self.slot();
        let outer = self.current.replace(slot);
        let body = self.cond(body);
        self.current = outer;
        let body = body?;
        let ev = bool_ev(move |c| {
            q.eval(c, refs.len(), |i| {
                c.set_var(slot, Value::Int(i64::from(refs[i].id(c))));
                body(c)
            })
        });
        Ok((ev, Ty::V(Type::Bool)))
    }

    fn for_in(&mut self, quant: &Quant, vars: &[String], iter: &Iterable, body: &Expr) -> Result<(Ev, Ty), Error> {
        let q = self.quantity(quant)?;
        // The iterable as a function producing the list of per-iteration
        // variable values, and the variables' types.
        type Items = Box<dyn Fn(&Ctx) -> Option<Vec<Vec<Value>>> + Send + Sync>;
        let (items, types): (Items, Vec<Type>) = match iter {
            Iterable::Range(lo, hi) => {
                let (lo, hi) = (self.int(lo)?, self.int(hi)?);
                let items: Items = Box::new(move |c| {
                    let (lo, hi) = (lo(c).as_int()?, hi(c).as_int()?);
                    // An empty range is undefined, as in YARA: the loop is false.
                    if lo > hi || hi.saturating_sub(lo) > c.loop_budget() {
                        return None;
                    }
                    Some((lo..=hi).map(|i| vec![Value::Int(i)]).collect())
                });
                (items, vec![Type::Int])
            }
            Iterable::List(list)
                if list.len() > 1 || !matches!(self.peek_type(&list[0])?, Type::Array(_) | Type::Dict(_)) =>
            {
                let mut evs = Vec::new();
                let mut ty = None;
                for e in list {
                    let (ev, t) = self.value(e)?;
                    ty.get_or_insert(t);
                    evs.push(ev);
                }
                let items: Items = Box::new(move |c| Some(evs.iter().map(|e| vec![e(c)]).collect()));
                (items, vec![ty.expect("non-empty list")])
            }
            Iterable::List(list) => self.collection(&list[0], vars.len())?,
            Iterable::Expr(e) => self.collection(e, vars.len())?,
        };
        if types.len() != vars.len() {
            return self.err(format!("this loop binds {} variable(s), not {}", types.len(), vars.len()));
        }
        let slots: Vec<usize> = vars.iter().map(|_| self.slot()).collect();
        let depth = self.scopes.len();
        for ((name, slot), ty) in vars.iter().zip(&slots).zip(types) {
            self.scopes.push((name.clone(), *slot, ty));
        }
        let body = self.cond(body);
        self.scopes.truncate(depth);
        let body = body?;
        let ev = bool_ev(move |c| {
            let Some(list) = items(c) else { return false };
            q.eval(c, list.len(), |i| {
                if !c.tick() {
                    return false;
                }
                for (slot, v) in slots.iter().zip(&list[i]) {
                    c.set_var(*slot, v.clone());
                }
                body(c)
            })
        });
        Ok((ev, Ty::V(Type::Bool)))
    }

    /// The type an expression would have, without keeping its code.
    fn peek_type(&mut self, e: &Expr) -> Result<Type, Error> {
        let slots = self.slots;
        let t = self.value(e).map(|(_, t)| t);
        self.slots = slots;
        t
    }

    /// Iterating a module array (one variable) or dictionary (key and value).
    #[allow(clippy::type_complexity)]
    fn collection(
        &mut self,
        e: &Expr,
        nvars: usize,
    ) -> Result<(Box<dyn Fn(&Ctx) -> Option<Vec<Vec<Value>>> + Send + Sync>, Vec<Type>), Error> {
        let (ev, t) = self.value(e)?;
        match t {
            Type::Array(elem) => Ok((
                Box::new(move |c| match ev(c) {
                    Value::Array(a) => Some(a.iter().map(|v| vec![v.clone()]).collect()),
                    _ => None,
                }),
                vec![*elem],
            )),
            Type::Dict(elem) => {
                let both = nvars == 2;
                Ok((
                    Box::new(move |c| match ev(c) {
                        Value::Dict(d) => Some(
                            d.iter()
                                .map(|(k, v)| {
                                    if both {
                                        vec![Value::Str(k.clone()), v.clone()]
                                    } else {
                                        vec![Value::Str(k.clone())]
                                    }
                                })
                                .collect(),
                        ),
                        _ => None,
                    }),
                    if both { vec![Type::Str, *elem] } else { vec![Type::Str] },
                ))
            }
            t => self.err(format!("can't loop over a {}", t.name())),
        }
    }

    fn with(&mut self, binds: &[(String, Expr)], body: &Expr) -> Result<(Ev, Ty), Error> {
        let depth = self.scopes.len();
        let mut evs = Vec::new();
        for (name, e) in binds {
            let (ev, t) = match self.value(e) {
                Ok(x) => x,
                Err(err) => {
                    self.scopes.truncate(depth);
                    return Err(err);
                }
            };
            let slot = self.slot();
            self.scopes.push((name.clone(), slot, t));
            evs.push((slot, ev));
        }
        let body = self.value(body);
        self.scopes.truncate(depth);
        let (body, t) = body?;
        let ev: Ev = Box::new(move |c| {
            for (slot, ev) in &evs {
                let v = ev(c);
                c.set_var(*slot, v);
            }
            body(c)
        });
        Ok((ev, Ty::V(t)))
    }
}

/// Reads an integer at an offset of the data.
type IntReader = fn(&[u8], i64) -> Option<i64>;

/// `int8`…`uint32be`: read an integer from the data.
fn int_reader(name: &str) -> Option<IntReader> {
    use crate::modules::{u16be, u16le, u32be, u32le};
    fn at(o: i64) -> Option<usize> {
        usize::try_from(o).ok()
    }
    Some(match name {
        "uint8" | "uint8be" => |d, o| d.get(at(o)?).map(|b| i64::from(*b)),
        "int8" | "int8be" => |d, o| d.get(at(o)?).map(|b| i64::from(*b as i8)),
        "uint16" => |d, o| u16le(d, at(o)?).map(i64::from),
        "int16" => |d, o| u16le(d, at(o)?).map(|v| i64::from(v as i16)),
        "uint16be" => |d, o| u16be(d, at(o)?).map(i64::from),
        "int16be" => |d, o| u16be(d, at(o)?).map(|v| i64::from(v as i16)),
        "uint32" => |d, o| u32le(d, at(o)?).map(i64::from),
        "int32" => |d, o| u32le(d, at(o)?).map(|v| i64::from(v as i32)),
        "uint32be" => |d, o| u32be(d, at(o)?).map(i64::from),
        "int32be" => |d, o| u32be(d, at(o)?).map(|v| i64::from(v as i32)),
        _ => return None,
    })
}

fn compare(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    match (a, b) {
        (Value::Str(x), Value::Str(y)) => Some(x.cmp(y)),
        (Value::Float(_), _) | (_, Value::Float(_)) => a.as_float()?.partial_cmp(&b.as_float()?),
        _ => Some(a.as_int()?.cmp(&b.as_int()?)),
    }
}

fn string_op(op: BinOp, a: &[u8], b: &[u8]) -> bool {
    let lower = |s: &[u8]| s.to_ascii_lowercase();
    match op {
        BinOp::Contains => b.is_empty() || a.windows(b.len()).any(|w| w == b),
        BinOp::IContains => {
            let (a, b) = (lower(a), lower(b));
            b.is_empty() || a.windows(b.len()).any(|w| w == b.as_slice())
        }
        BinOp::StartsWith => a.starts_with(b),
        BinOp::IStartsWith => lower(a).starts_with(&lower(b)),
        BinOp::EndsWith => a.ends_with(b),
        BinOp::IEndsWith => lower(a).ends_with(&lower(b)),
        _ => a.eq_ignore_ascii_case(b),
    }
}

fn arith(op: BinOp, a: &Value, b: &Value) -> Value {
    use BinOp::*;
    if matches!(a, Value::Float(_)) || matches!(b, Value::Float(_)) {
        let (Some(x), Some(y)) = (a.as_float(), b.as_float()) else { return Value::Undef };
        return Value::Float(match op {
            Add => x + y,
            Sub => x - y,
            Mul => x * y,
            _ => x / y,
        });
    }
    let (Some(x), Some(y)) = (a.as_int(), b.as_int()) else { return Value::Undef };
    Value::Int(match op {
        Add => x.wrapping_add(y),
        Sub => x.wrapping_sub(y),
        Mul => x.wrapping_mul(y),
        Div if y == 0 => return Value::Undef,
        Div => x.wrapping_div(y),
        Mod if y == 0 => return Value::Undef,
        Mod => x.wrapping_rem(y),
        BitOr => x | y,
        BitXor => x ^ y,
        BitAnd => x & y,
        Shl | Shr if y < 0 => return Value::Undef,
        Shl => {
            if y >= 64 {
                0
            } else {
                x << y
            }
        }
        _ => {
            if y >= 64 {
                0
            } else {
                x >> y
            }
        }
    })
}

/// The kind of file a condition requires, from the terms it `and`s together:
/// a check of the magic at offset 0, or `pe.is_pe`.
fn file_need(e: &Expr) -> Option<FileType> {
    match e {
        Expr::Binary(BinOp::And, l, r) => file_need(l).or_else(|| file_need(r)),
        Expr::Binary(BinOp::Eq, l, r) => magic_check(l, r).or_else(|| magic_check(r, l)),
        Expr::Field(base, f) if f == "is_pe" && matches!(base.as_ref(), Expr::Ident(m) if m == "pe") => {
            Some(FileType::Mz)
        }
        _ => None,
    }
}

fn magic_check(read: &Expr, value: &Expr) -> Option<FileType> {
    let Expr::Call(f, args) = read else { return None };
    let (Expr::Ident(name), [Expr::Int(0)], Expr::Int(v)) = (f.as_ref(), args.as_slice(), value) else { return None };
    match (name.as_str(), *v) {
        ("uint16", 0x5A4D) | ("uint16be", 0x4D5A) => Some(FileType::Mz),
        ("uint32", 0x464C_457F) | ("uint32be", 0x7F45_4C46) => Some(FileType::Elf),
        ("uint32", 0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE | 0xBEBA_FECA | 0xCAFE_BABE)
        | ("uint32be", 0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE | 0xCAFE_BABE | 0xBEBA_FECA) => {
            Some(FileType::MachO)
        }
        _ => None,
    }
}

/// Whether a condition names `module` (a file imports modules for all its
/// rules; this is what one rule uses).
fn uses(e: &Expr, module: &str) -> bool {
    let any = |items: &[Expr]| items.iter().any(|i| uses(i, module));
    let anchor = |a: &Option<Anchor>| match a {
        Some(Anchor::At(x)) => uses(x, module),
        Some(Anchor::In(lo, hi)) => uses(lo, module) || uses(hi, module),
        None => false,
    };
    let quant = |q: &Quant| matches!(q, Quant::Count(x) | Quant::Percent(x) if uses(x, module));
    match e {
        Expr::Ident(n) => n == module,
        Expr::Field(b, _) => uses(b, module),
        Expr::Index(a, b) => uses(a, module) || uses(b, module),
        Expr::Call(f, args) => uses(f, module) || any(args),
        Expr::Unary(_, x) => uses(x, module),
        Expr::Binary(_, a, b) => uses(a, module) || uses(b, module),
        Expr::StrMatch { anchor: a, .. } => anchor(a),
        Expr::StrCount { range: Some((lo, hi)), .. } => uses(lo, module) || uses(hi, module),
        Expr::StrOffset { index: Some(i), .. } | Expr::StrLength { index: Some(i), .. } => uses(i, module),
        Expr::Of { quant: q, items, anchor: a } => {
            quant(q) || anchor(a) || matches!(items, OfItems::Exprs(x) if any(x))
        }
        Expr::ForOf { quant: q, body, .. } => quant(q) || uses(body, module),
        Expr::ForIn { quant: q, iter, body, .. } => {
            quant(q)
                || uses(body, module)
                || match iter {
                    Iterable::Range(lo, hi) => uses(lo, module) || uses(hi, module),
                    Iterable::List(items) => any(items),
                    Iterable::Expr(x) => uses(x, module),
                }
        }
        Expr::With { binds, body } => binds.iter().any(|(_, x)| uses(x, module)) || uses(body, module),
        _ => false,
    }
}

/// Whether the condition is false whenever none of the rule's strings matched.
fn requires_match(e: &Expr) -> bool {
    match e {
        Expr::StrMatch { id, .. } => !id.is_empty(),
        Expr::Binary(BinOp::And, l, r) => requires_match(l) || requires_match(r),
        Expr::Binary(BinOp::Or, l, r) => requires_match(l) && requires_match(r),
        Expr::Binary(op, l, r) => match (l.as_ref(), r.as_ref()) {
            (Expr::StrCount { .. }, Expr::Int(n)) => match op {
                BinOp::Gt => *n >= 0,
                BinOp::Ge | BinOp::Eq => *n >= 1,
                _ => false,
            },
            _ => false,
        },
        Expr::Of { quant, items: OfItems::Strings(_), .. } => match quant {
            Quant::Any | Quant::All => true,
            Quant::Count(n) | Quant::Percent(n) => matches!(n.as_ref(), Expr::Int(n) if *n >= 1),
            Quant::None => false,
        },
        _ => false,
    }
}

#[cfg(test)]
#[path = "compile_tests.rs"]
mod tests;
