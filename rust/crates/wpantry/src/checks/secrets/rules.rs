//! The secret rules: YARA files (pantry-rules' `rules/any/secret/`, compiled
//! in from `assets/secrets/rules.yar`) whose `$secret` regex finds a candidate
//! and whose meta says what betterleaks' filters said. The meta keys are
//! pantry-rules' `tools/betterleaks.py`'s; this module reads them into
//! [`SecretRule`]s and compiles the regexes once.

use crate::error::{Error, Result};
use wpantry_yara::compile::{CompiledRule, Meta};
use wpantry_yara::pattern::{self, Node, Syntax};
use wpantry_yara::{Compiler, Rules};

/// The rules Pantry ships.
pub const BUNDLED: &str = include_str!("../../../assets/secrets/rules.yar");

/// How far a secret's regex may run from where it starts: a fragment is at
/// most 125 KB, and a private key block is a few KB (YARA's 4,096 is short).
pub const REACH: usize = 1 << 17;

/// betterleaks' default specificity, for rules that don't set one.
pub const DEFAULT_SPECIFICITY: i64 = 100;

/// What a filter reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The secret (its capture group).
    Secret,
    /// The whole regex match.
    Match,
    /// The lines the match is on, with their line ends.
    Line,
    /// The file's path.
    Path,
}

impl Target {
    fn parse(s: &str) -> Option<Target> {
        Some(match s {
            "secret" => Target::Secret,
            "match" => Target::Match,
            "line" => Target::Line,
            "path" => Target::Path,
            _ => return None,
        })
    }
}

/// When a finding is skipped: any one of these that holds skips it.
#[derive(Clone, Debug, Default)]
pub struct Skips {
    pub entropy_le: Option<f64>,
    pub entropy_lt: Option<f64>,
    pub token_ratio_ge: Option<f64>,
    pub token_efficiency: bool,
    /// The target matches the regex.
    pub regex: Vec<(Target, Node)>,
    /// The target, lowercased, contains the word (lowercased).
    pub words: Vec<(Target, Vec<u8>)>,
    /// The target doesn't match the regex.
    pub require: Vec<(Target, Node)>,
}

impl Skips {
    pub fn is_empty(&self) -> bool {
        self.entropy_le.is_none()
            && self.entropy_lt.is_none()
            && self.token_ratio_ge.is_none()
            && !self.token_efficiency
            && self.regex.is_empty()
            && self.words.is_empty()
            && self.require.is_empty()
    }
}

/// How close a component must be to the secret it completes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub lines_before: Option<usize>,
    pub lines_after: Option<usize>,
    pub cols_before: Option<usize>,
    pub cols_after: Option<usize>,
}

impl Window {
    /// betterleaks' `within` (`5L`, `100C`, `-2L,+4C`): `NL` is N lines in
    /// all (the match's own and N-1 more), a bare number counts characters,
    /// `-` and `+` limit a side. Empty or `0`: anywhere in the fragment.
    pub fn parse(s: &str) -> Option<Window> {
        let mut w = Window::default();
        let s = s.trim();
        if s.is_empty() || s == "0" {
            return Some(w);
        }
        for part in s.split(',') {
            let part = part.trim();
            let (before, after, rest) = match part.as_bytes().first()? {
                b'-' => (true, false, &part[1..]),
                b'+' => (false, true, &part[1..]),
                _ => (true, true, part),
            };
            let (num, lines) = match rest.strip_suffix(['L', 'l']) {
                Some(n) => (n, true),
                None => (rest.strip_suffix(['C', 'c']).unwrap_or(rest), false),
            };
            let n: usize = num.parse().ok()?;
            let n = if lines { n.saturating_sub(1) } else { n };
            let (b, a) =
                if lines { (&mut w.lines_before, &mut w.lines_after) } else { (&mut w.cols_before, &mut w.cols_after) };
            if before {
                *b = Some(n);
            }
            if after {
                *a = Some(n);
            }
        }
        Some(w)
    }

    pub fn is_fragment(&self) -> bool {
        *self == Window::default()
    }
}

#[derive(Clone, Debug)]
pub struct Component {
    pub id: String,
    pub within: Window,
    pub optional: bool,
}

/// betterleaks' confidence in a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug)]
pub struct SecretRule {
    /// betterleaks' id (`aws-access-token`): findings and fingerprints use it.
    pub id: String,
    /// The YARA rule's name.
    pub name: String,
    pub description: String,
    pub confidence: Option<Confidence>,
    /// Lowercased; empty: the rule always runs.
    pub keywords: Vec<Vec<u8>>,
    /// The capture group holding the secret; 0: the first that matched.
    pub secret_group: u32,
    pub specificity: i64,
    pub skips: Skips,
    /// A filter too involved for meta: betterleaks' program, as written.
    pub program: Option<super::expr::Program>,
    pub components: Vec<Component>,
    /// Never reported on its own: only as a component of another rule.
    pub private: bool,
    /// Its `$secret`: the string's global id and its tree with capture groups.
    pub regex: Option<(usize, Node, u32)>,
    /// The YARA rule's index in [`RuleSet::yara`].
    pub index: usize,
}

/// A filter that applies to every rule, or to the `applies_to` ones.
#[derive(Clone, Debug)]
pub struct GlobalSkips {
    /// The YARA rule it came from.
    pub name: String,
    pub applies_to: Vec<String>,
    pub skips: Skips,
}

/// The compiled secret rules.
pub struct RuleSet {
    pub rules: Vec<SecretRule>,
    /// Every rule but the unanchored ones, compiled together.
    pub yara: Rules,
    /// Rules with no atom to anchor on (they'd be tried at every byte),
    /// compiled alone and run only where their keywords are: `(rule, set)`.
    pub loose: Vec<(usize, Rules)>,
    /// One YARA rule per secret rule with keywords (named by its index).
    pub keywords: Rules,
    /// Paths never read (betterleaks' prefilter).
    pub prefilter: Skips,
    /// betterleaks' global filter and Pantry's own.
    pub filters: Vec<GlobalSkips>,
}

fn meta_str<'a>(rule: &'a CompiledRule, key: &str) -> impl Iterator<Item = String> + 'a {
    let key = key.to_string();
    rule.meta.iter().filter(move |(k, _)| *k == key).map(|(_, v)| match v {
        Meta::Str(s) => String::from_utf8_lossy(s).into_owned(),
        Meta::Int(i) => i.to_string(),
        Meta::Bool(b) => b.to_string(),
    })
}

fn first(rule: &CompiledRule, key: &str) -> Option<String> {
    meta_str(rule, key).next()
}

fn number(rule: &CompiledRule, key: &str) -> Result<Option<f64>> {
    first(rule, key)
        .map(|v| v.parse().map_err(|_| Error::Invalid(format!("secret rule {}: {key} isn't a number", rule.name))))
        .transpose()
}

/// A meta regex: Go's RE2, as betterleaks writes them.
pub fn meta_regex(src: &str) -> Result<Node> {
    pattern::parse_regex(src.as_bytes(), false, false, Syntax::Re2, 0)
        .map_err(|e| Error::Invalid(format!("secret rule regex {src:?}: {e}")))
}

fn skips(rule: &CompiledRule) -> Result<Skips> {
    let mut s = Skips {
        entropy_le: number(rule, "skip_entropy_le")?,
        entropy_lt: number(rule, "skip_entropy_lt")?,
        token_ratio_ge: number(rule, "skip_token_ratio_ge")?,
        token_efficiency: first(rule, "skip_token_efficiency").as_deref() == Some("true"),
        ..Default::default()
    };
    for (key, value) in &rule.meta {
        let Meta::Str(v) = value else { continue };
        let v = String::from_utf8_lossy(v);
        let target = |prefix: &str| key.strip_prefix(prefix).and_then(Target::parse);
        if let Some(t) = target("skip_regex_") {
            s.regex.push((t, meta_regex(&v)?));
        } else if let Some(t) = target("skip_word_") {
            s.words.push((t, v.to_lowercase().into_bytes()));
        } else if let Some(t) = target("require_") {
            s.require.push((t, meta_regex(&v)?));
        }
    }
    Ok(s)
}

fn components(rule: &CompiledRule) -> Result<Vec<Component>> {
    let mut out = Vec::new();
    for n in 1.. {
        let Some(id) = first(rule, &format!("component{n}")) else { break };
        let within = first(rule, &format!("component{n}_within")).unwrap_or_default();
        let within = Window::parse(&within)
            .ok_or_else(|| Error::Invalid(format!("secret rule {}: component{n}_within {within:?}", rule.name)))?;
        let optional = first(rule, &format!("component{n}_optional")).as_deref() == Some("true");
        out.push(Component { id, within, optional });
    }
    Ok(out)
}

fn confidence(rule: &CompiledRule) -> Option<Confidence> {
    match first(rule, "confidence")?.as_str() {
        "high" => Some(Confidence::High),
        "medium" => Some(Confidence::Medium),
        "low" => Some(Confidence::Low),
        _ => None,
    }
}

fn compiler() -> Compiler {
    let mut c = Compiler::new();
    c.set_regex_reach(REACH);
    c.keep_captures(true);
    c
}

/// A YARA string literal for `text`.
fn quoted(text: &[u8]) -> String {
    let mut out = String::from("\"");
    for &b in text {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out.push('"');
    out
}

impl RuleSet {
    /// The bundled rules, with `extra` (the user's own secret rules, YARA)
    /// after them.
    pub fn load(extra: &[(&str, &str)]) -> Result<RuleSet> {
        let mut sources = vec![("bundled", BUNDLED)];
        sources.extend_from_slice(extra);
        RuleSet::from_sources(&sources)
    }

    /// Compile `(namespace, YARA source)` pairs into a rule set; a rule that
    /// doesn't compile is an error, naming it.
    pub fn from_sources(sources: &[(&str, &str)]) -> Result<RuleSet> {
        let mut c = compiler();
        for (ns, src) in sources {
            c.add_source(ns, src, Syntax::Strict);
        }
        let probe = c.build();
        if let Some(r) = probe.rejected.first() {
            return Err(Error::Invalid(format!("secret rule {} ({}): {}", r.rule, r.namespace, r.error)));
        }
        let unanchored: Vec<&str> = probe.unanchored().into_iter().map(|(r, _)| r).collect();
        // The unanchored rules again, each alone, and everything else together.
        let mut whole = compiler();
        let mut loose_src = Vec::new();
        for (ns, src) in sources {
            let mut kept = String::new();
            for chunk in split_rules(src) {
                match rule_name(chunk) {
                    Some(name) if unanchored.contains(&name) => loose_src.push((ns.to_string(), chunk.to_string())),
                    _ => kept.push_str(chunk),
                }
            }
            whole.add_source(ns, &kept, Syntax::Strict);
        }
        let yara = whole.build();
        let mut rules = Vec::new();
        let mut prefilter = Skips::default();
        let mut filters = Vec::new();
        for (index, r) in yara.rules().iter().enumerate() {
            if first(r, "category").as_deref() != Some("secret") {
                continue;
            }
            let Some(id) = first(r, "id") else {
                // A filter: betterleaks' prefilter or filter, or one of ours.
                if r.name == "Any_Secret_Prefilter" {
                    prefilter = skips(r)?;
                } else {
                    filters.push(GlobalSkips {
                        name: r.name.clone(),
                        applies_to: meta_str(r, "applies_to").collect(),
                        skips: skips(r)?,
                    });
                }
                continue;
            };
            rules.push(secret_rule(&yara, r, index, id)?);
        }
        let mut loose = Vec::new();
        for (ns, src) in loose_src {
            let mut c = compiler();
            c.add_source(&ns, &src, Syntax::Strict);
            let set = c.build();
            let r = &set.rules()[0];
            let id = first(r, "id").ok_or_else(|| Error::Invalid(format!("secret rule {} has no id", r.name)))?;
            let rule = secret_rule(&set, r, usize::MAX, id)?;
            loose.push((rules.len(), set));
            rules.push(rule);
        }
        let keywords = keyword_rules(&rules)?;
        Ok(RuleSet { rules, yara, loose, keywords, prefilter, filters })
    }

    pub fn by_id(&self, id: &str) -> Option<usize> {
        self.rules.iter().position(|r| r.id == id)
    }
}

/// Why a file of the user's own secret rules can't be used, if it can't:
/// it doesn't read, or a rule in it doesn't compile beside the bundled ones.
pub fn policy_error(path: &std::path::Path) -> Option<String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return Some(e.to_string()),
    };
    RuleSet::load(&[("user", &text)]).err().map(|e| e.to_string())
}

fn secret_rule(set: &Rules, r: &CompiledRule, index: usize, id: String) -> Result<SecretRule> {
    let regex = r.strings.clone().find(|s| set.string_name(*s as usize) == "secret").map(|s| {
        let (tree, groups) = set.capture_tree(s as usize).expect("kept captures");
        (s as usize, tree.clone(), groups)
    });
    let secret_group = first(r, "secret_group").map(|g| g.parse().unwrap_or(0)).unwrap_or(0);
    let specificity = first(r, "specificity").and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_SPECIFICITY);
    Ok(SecretRule {
        description: first(r, "description").unwrap_or_default(),
        name: r.name.clone(),
        confidence: confidence(r),
        keywords: meta_str(r, "keyword").map(|k| k.to_lowercase().into_bytes()).collect(),
        secret_group,
        specificity,
        skips: skips(r)?,
        program: first(r, "filter_expr")
            .map(|src| super::expr::Program::compile(&src))
            .transpose()
            .map_err(|e| Error::Invalid(format!("secret rule {}: filter_expr: {e}", r.name)))?,
        components: components(r)?,
        private: r.private,
        regex,
        index,
        id,
    })
}

/// Each rule with keywords as a YARA rule of them (nocase), named by its
/// index, for the keyword gate.
fn keyword_rules(rules: &[SecretRule]) -> Result<Rules> {
    let mut src = String::new();
    for (i, r) in rules.iter().enumerate().filter(|(_, r)| !r.keywords.is_empty()) {
        src.push_str(&format!("rule k{i} {{ strings: "));
        for (n, k) in r.keywords.iter().enumerate() {
            src.push_str(&format!("$k{n} = {} nocase ", quoted(k)));
        }
        src.push_str("condition: any of them }\n");
    }
    let mut c = Compiler::new();
    c.add_source("keywords", &src, Syntax::Relaxed);
    let set = c.build();
    if let Some(r) = set.rejected.first() {
        return Err(Error::Invalid(format!("secret keywords of {}: {}", r.rule, r.error)));
    }
    Ok(set)
}

/// The rule a keyword rule stands for.
pub fn keyword_owner(name: &str) -> Option<usize> {
    name.strip_prefix('k')?.parse().ok()
}

/// A YARA source cut before each top-level `rule` (or `private rule`): the
/// generated files have one rule each and put `rule` at the start of a line.
fn split_rules(src: &str) -> Vec<&str> {
    let mut cuts = vec![0];
    let mut at = 0;
    for line in src.split_inclusive('\n') {
        let t = line.trim_start();
        if (t.starts_with("rule ") || t.starts_with("private rule ")) && at > 0 {
            cuts.push(at);
        }
        at += line.len();
    }
    cuts.push(src.len());
    cuts.windows(2).map(|w| &src[w[0]..w[1]]).collect()
}

fn rule_name(chunk: &str) -> Option<&str> {
    chunk.lines().find_map(|l| {
        let t = l.trim_start();
        let t = t.strip_prefix("private ").unwrap_or(t);
        t.strip_prefix("rule ").map(|rest| rest.split(|c: char| !c.is_alphanumeric() && c != '_').next().unwrap_or(""))
    })
}

#[cfg(test)]
#[path = "rules_tests.rs"]
mod tests;
