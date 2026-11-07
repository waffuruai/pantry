//! Scanning bytes with compiled [`Rules`].
//!
//! One pass of the atom table finds candidate positions; each candidate is
//! verified against its string variant, skipping strings whose rule needs a
//! different kind of file. Then the rules are evaluated in order (a rule may
//! name an earlier one), skipping any whose condition needs a string match
//! that didn't happen. Module data is parsed at most once per scan, and only
//! if a condition reaches it.

use crate::compile::{EXTERNALS, Rules};
use crate::value::Value;
use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashMap;

/// The most matches kept per string; more add nothing a condition can use.
pub const MAX_MATCHES: usize = 100_000;

/// Loop iterations and range sizes one scan may spend in conditions.
pub const LOOP_BUDGET: i64 = 50_000_000;

/// What a file is, from its first bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    /// Starts with `MZ` (DOS, PE).
    Mz,
    Elf,
    MachO,
    Other,
}

impl FileType {
    pub fn detect(data: &[u8]) -> FileType {
        match data {
            [b'M', b'Z', ..] => FileType::Mz,
            [0x7F, b'E', b'L', b'F', ..] => FileType::Elf,
            [0xFE, 0xED, 0xFA, 0xCE | 0xCF, ..]
            | [0xCE | 0xCF, 0xFA, 0xED, 0xFE, ..]
            | [0xCA, 0xFE, 0xBA, 0xBE, ..]
            | [0xBE, 0xBA, 0xFE, 0xCA, ..] => FileType::MachO,
            _ => FileType::Other,
        }
    }
}

/// Per-scan inputs: the external variables (`filename`, …).
#[derive(Clone, Debug, Default)]
pub struct ScanOptions {
    pub filename: Option<String>,
    pub filepath: Option<String>,
    pub extension: Option<String>,
    pub filetype: Option<String>,
    pub owner: Option<String>,
}

/// A rule that matched.
#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    pub namespace: String,
    pub rule: String,
    /// Index into [`Rules::rules`], for its tags and meta.
    pub index: usize,
    /// The rule's strings that matched: `(name, first offset)`.
    pub strings: Vec<(String, usize)>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ScanResult {
    pub matches: Vec<Hit>,
    /// A condition ran out of its loop budget; its rule counted as false.
    pub truncated: bool,
}

/// What a condition sees while it runs.
pub struct Ctx<'a> {
    pub data: &'a [u8],
    rules: &'a Rules,
    matches: &'a [Vec<(usize, usize)>],
    results: Vec<Cell<bool>>,
    modules: Vec<OnceCell<Value>>,
    vars: RefCell<Vec<Value>>,
    externals: Vec<Value>,
    budget: Cell<i64>,
    /// Module function answers this scan: (function, encoded arguments).
    memo: RefCell<HashMap<(usize, Vec<u8>), Value>>,
}

impl Ctx<'_> {
    /// The sorted `(offset, length)` matches of a string.
    pub fn matches(&self, string: u32) -> &[(usize, usize)] {
        self.matches.get(string as usize).map_or(&[], Vec::as_slice)
    }

    pub fn rule(&self, index: usize) -> bool {
        self.results.get(index).is_some_and(Cell::get)
    }

    pub fn module(&self, index: usize) -> Value {
        self.modules[index].get_or_init(|| self.rules.modules[index].parse(self.data)).clone()
    }

    pub fn external(&self, index: usize) -> Value {
        self.externals[index].clone()
    }

    pub fn var(&self, slot: usize) -> Value {
        self.vars.borrow()[slot].clone()
    }

    pub fn set_var(&self, slot: usize, v: Value) {
        self.vars.borrow_mut()[slot] = v;
    }

    /// Spend one loop iteration; false once the scan's budget is gone.
    pub fn tick(&self) -> bool {
        let left = self.budget.get();
        self.budget.set(left - 1);
        left > 0
    }

    /// The answer of `function` for `args`, computed once per scan.
    pub fn memoized(&self, function: usize, args: &[Value], compute: impl FnOnce() -> Value) -> Value {
        let mut key = Vec::new();
        for a in args {
            match a {
                Value::Int(i) => key.extend(i.to_le_bytes()),
                Value::Float(f) => key.extend(f.to_bits().to_le_bytes()),
                Value::Str(s) => {
                    key.extend((s.len() as u64).to_le_bytes());
                    key.extend_from_slice(s);
                }
                // Regexes are compiled once, so their address names them.
                Value::Regex(r) => key.extend((std::sync::Arc::as_ptr(r) as usize).to_le_bytes()),
                _ => return compute(),
            }
            key.push(0xFF);
        }
        if let Some(v) = self.memo.borrow().get(&(function, key.clone())) {
            return v.clone();
        }
        let v = compute();
        self.memo.borrow_mut().insert((function, key), v.clone());
        v
    }

    /// How many iterations a range may still have.
    pub fn loop_budget(&self) -> i64 {
        self.budget.get().max(0)
    }
}

/// Every verified match of every string, for callers that need more than
/// each string's first ([`Rules::scan_spans`]).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Spans {
    /// By global string id: `(start, len)`, sorted, at most one per start.
    pub by_string: Vec<Vec<(usize, usize)>>,
}

impl Rules {
    pub fn scan(&self, data: &[u8], opts: &ScanOptions) -> ScanResult {
        self.scan_spans(data, opts).0
    }

    /// The rule a global string id belongs to (an index into [`Rules::rules`]).
    pub fn string_rule(&self, string: usize) -> usize {
        self.string_rule[string] as usize
    }

    /// As [`Rules::scan`], with every match of every string kept.
    pub fn scan_spans(&self, data: &[u8], opts: &ScanOptions) -> (ScanResult, Spans) {
        let ft = FileType::detect(data);
        let wanted = |string: u32| {
            let rule = &self.rules[self.string_rule[string as usize] as usize];
            rule.needs.is_none_or(|n| n == ft)
        };
        let mut matches: Vec<Vec<(usize, usize)>> = vec![Vec::new(); self.strings.len()];
        self.atoms.scan(data, |pos, t| {
            let list = &mut matches[t.string as usize];
            if list.len() < MAX_MATCHES && wanted(t.string) {
                self.strings[t.string as usize].variants[t.variant as usize].verify(data, pos, t.offset as usize, list);
            }
        });
        for &(s, v) in &self.brute {
            if wanted(s) {
                self.strings[s as usize].variants[v as usize].scan_all(data, &mut matches[s as usize]);
            }
        }
        for list in &mut matches {
            if list.len() > 1 {
                list.sort_unstable();
                list.dedup_by_key(|m| m.0);
                list.truncate(MAX_MATCHES);
            }
        }
        let externals = [&opts.filename, &opts.filepath, &opts.extension, &opts.filetype, &opts.owner]
            .iter()
            .map(|v| Value::str(v.as_deref().unwrap_or("")))
            .collect::<Vec<_>>();
        debug_assert_eq!(externals.len(), EXTERNALS.len());
        let ctx = Ctx {
            data,
            rules: self,
            matches: &matches,
            results: (0..self.rules.len()).map(|_| Cell::new(false)).collect(),
            modules: (0..self.modules.len()).map(|_| OnceCell::new()).collect(),
            vars: RefCell::new(vec![Value::Undef; self.nslots]),
            externals,
            budget: Cell::new(LOOP_BUDGET),
            memo: RefCell::new(HashMap::new()),
        };
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.needs.is_some_and(|n| n != ft) {
                continue;
            }
            if rule.requires_match && !rule.strings.clone().any(|s| !matches[s as usize].is_empty()) {
                continue;
            }
            ctx.results[i].set((rule.cond)(&ctx).truthy());
        }
        // A false global rule makes every rule in its namespace false.
        let failed: Vec<&str> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(i, r)| r.global && !ctx.results[*i].get())
            .map(|(_, r)| r.namespace.as_str())
            .collect();
        let mut out = ScanResult { matches: Vec::new(), truncated: ctx.budget.get() < 0 };
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.private || !ctx.results[i].get() || failed.contains(&rule.namespace.as_str()) {
                continue;
            }
            let strings = rule
                .strings
                .clone()
                .filter_map(|s| {
                    let first = matches[s as usize].first()?;
                    let name = &self.strings[s as usize];
                    (!name.private).then(|| (name.id.clone(), first.0))
                })
                .collect();
            out.matches.push(Hit { namespace: rule.namespace.clone(), rule: rule.name.clone(), index: i, strings });
        }
        drop(ctx);
        (out, Spans { by_string: matches })
    }
}

#[cfg(test)]
#[path = "scan_tests.rs"]
mod tests;
