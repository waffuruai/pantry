//! Pantry's secret scanner: betterleaks' rules (pantry-rules' YARA
//! translation, [`rules`]) run by `wpantry-yara`, with betterleaks' matching
//! rules, so a file reports what betterleaks v1.10.0 reports for it:
//!
//! - **Fragments:** a file is read in fragments of about 100 KB, each cut at
//!   a blank line when one comes within 25 KB ([`fragments`]). A rule runs on
//!   a fragment only when one of its keywords is in it, in any case.
//! - **Matches:** a rule's matches in a fragment are leftmost-first and don't
//!   overlap, as RE2's. The secret is the rule's `secret_group`, or the first
//!   group that matched, in the match with its `\n`s trimmed.
//! - **Skips:** a line with `gitleaks:allow` or `betterleaks:allow` is never
//!   reported. A finding is dropped when its rule's skips hold, or the global
//!   ones, or Pantry's own (`Any.Secret.PantryFilter.yar`).
//! - **Ties:** a finding gives way to one of higher specificity on the same
//!   line whose secret contains it (a generic rule to a provider's).
//! - **Components:** a multipart rule reports only when its parts are near.
//! - **Encodings:** percent, `\u`/`U+`, hex and base64 text is decoded, up
//!   to five levels, and scanned again ([`decode`]).
//!
//! What Pantry does differently: a file that sniffs as binary is skipped (see
//! [`fragments::binary`]), and secrets never leave memory: findings carry the
//! rule, the place and a fingerprint.

pub mod decode;
pub mod expr;
pub mod fragments;
pub mod readable;
pub mod rules;

use rules::{Component, RuleSet, SecretRule, Skips, Target, Window};
use std::collections::HashSet;
use wpantry_yara::ScanOptions;
use wpantry_yara::matcher::{self, Matcher};

/// Marks a line whose secrets are never reported.
pub const ALLOW: [&[u8]; 2] = [b"gitleaks:allow", b"betterleaks:allow"];

/// One secret found: where, by which rule, and never the secret itself
/// (only its length and entropy, for review).
#[derive(Clone, Debug, PartialEq)]
pub struct Found {
    pub rule: String,
    pub description: String,
    pub start_line: usize,
    pub end_line: usize,
    /// 1-based byte columns: the match's first byte, and its last.
    pub start_col: usize,
    pub end_col: usize,
    /// `decoded:base64` and the like, then `decode-depth:N`, for a secret
    /// found in decoded text.
    pub tags: Vec<String>,
    pub confidence: Option<rules::Confidence>,
    /// betterleaks' `path:rule:line` (gitleaks' too, so `.gitleaksignore`
    /// entries keep working); a commit's adds `sha:` in front.
    pub fingerprint: String,
}

/// A finding while it's still in memory, with its text.
#[derive(Clone, Debug)]
struct Hit {
    rule: usize,
    secret: Vec<u8>,
    /// The match's offsets in the text the pass scanned.
    start: usize,
    end: usize,
    /// Where it is in the fragment as read (decoded hits are mapped back).
    orig: (usize, usize),
    /// The line it starts on, counted from the fragment's first (0).
    line_no: usize,
    tags: Vec<String>,
    /// Set by the rule's filter program, in place of the rule's own.
    confidence: Option<rules::Confidence>,
    /// A multipart finding's parts, near it: they outrank as it does.
    parts: Vec<Hit>,
}

/// The text one pass scans: the fragment, or a decoding of it.
struct Pass<'a> {
    text: &'a [u8],
    decoder: &'a decode::Decoder,
    depth: usize,
}

/// The secret scanner: rules compiled once, shareable across threads.
pub struct Scanner {
    pub rules: RuleSet,
    /// Rule indices, highest specificity first (stable).
    order: Vec<usize>,
    /// Decoding passes after the first (betterleaks' `--max-decode-depth`).
    pub max_decode_depth: usize,
}

impl Scanner {
    pub fn new(rules: RuleSet) -> Scanner {
        let mut order: Vec<usize> = (0..rules.rules.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(rules.rules[i].specificity));
        Scanner { rules, order, max_decode_depth: decode::MAX_DEPTH }
    }

    /// Whether betterleaks' prefilter skips `path` without reading it.
    pub fn skips_path(&self, path: &str) -> bool {
        any_regex(&self.rules.prefilter, Target::Path, path.as_bytes())
    }

    /// The secrets in a file's bytes, `path` its path (for the path rules and
    /// filters, and the fingerprint); `commit` prefixes the fingerprint.
    pub fn scan(&self, data: &[u8], path: &str, commit: Option<&str>) -> Vec<Found> {
        if self.skips_path(path) || fragments::binary(data) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (first, frag) in fragments::split(data).into_iter().enumerate().map(|(i, f)| (i == 0, f)) {
            for hit in self.fragment(&data[frag.range.clone()], path, first) {
                out.push(self.found(&hit, &data[frag.range.clone()], frag.start_line, path, commit));
            }
        }
        out
    }

    fn found(&self, hit: &Hit, frag: &[u8], start_line: usize, path: &str, commit: Option<&str>) -> Found {
        let rule = &self.rules.rules[hit.rule];
        let loc = location(frag, hit.orig.0, hit.orig.1, start_line);
        let fingerprint = match commit {
            Some(sha) => format!("{sha}:{path}:{}:{}", rule.id, loc.start_line),
            None => format!("{path}:{}:{}", rule.id, loc.start_line),
        };
        Found {
            rule: rule.id.clone(),
            description: rule.description.clone(),
            start_line: loc.start_line,
            end_line: loc.end_line,
            start_col: loc.start_col,
            end_col: loc.end_col,
            tags: hit.tags.clone(),
            confidence: hit.confidence.or(rule.confidence),
            fingerprint,
        }
    }

    /// The hits in one fragment, every pass.
    fn fragment(&self, frag: &[u8], path: &str, first: bool) -> Vec<Hit> {
        let mut hits: Vec<Hit> = Vec::new();
        let mut decoder = decode::Decoder::new(frag);
        let mut depth = 0;
        loop {
            let pass = Pass { text: decoder.text(), decoder: &decoder, depth };
            let found = self.pass(&pass, frag, path, first, &hits);
            hits.extend(found);
            depth += 1;
            if depth > self.max_decode_depth || !decoder.decode_next() {
                break;
            }
        }
        suppress(&self.rules.rules, &mut hits);
        hits
    }

    /// One pass over `pass.text`: each rule that may run, highest specificity first.
    fn pass(&self, pass: &Pass, frag: &[u8], path: &str, first: bool, earlier: &[Hit]) -> Vec<Hit> {
        let gate = self.keyword_gate(pass.text);
        let opts = ScanOptions { filepath: Some(path.to_string()), ..Default::default() };
        let (res, spans) = self.rules.yara.scan_spans(pass.text, &opts);
        let held: HashSet<usize> = res.matches.iter().map(|h| h.index).collect();
        let mut loose: Vec<(usize, Vec<(usize, usize)>)> = Vec::new();
        for (rule, set) in &self.rules.loose {
            if gate.contains(rule) {
                let (r, s) = set.scan_spans(pass.text, &opts);
                if !r.matches.is_empty() {
                    let string = self.rules.rules[*rule].regex.as_ref().map_or(0, |(s, _, _)| *s);
                    loose.push((*rule, s.by_string.get(string).cloned().unwrap_or_default()));
                }
            }
        }
        let mut out: Vec<Hit> = Vec::new();
        for &i in &self.order {
            let rule = &self.rules.rules[i];
            if rule.private {
                continue;
            }
            let candidates: &[(usize, usize)] = match loose.iter().find(|(r, _)| *r == i) {
                Some((_, c)) => c,
                None if rule.index != usize::MAX && held.contains(&rule.index) => match &rule.regex {
                    Some((s, _, _)) => &spans.by_string[*s],
                    None => &[],
                },
                None => continue,
            };
            if !rule.keywords.is_empty() && !gate.contains(&i) {
                continue;
            }
            let Some(_) = &rule.regex else {
                // A path rule: the file is the finding, once, undecoded.
                if pass.depth == 0 && first {
                    out.push(Hit {
                        rule: i,
                        secret: Vec::new(),
                        start: 0,
                        end: 0,
                        orig: (0, 0),
                        line_no: 0,
                        tags: Vec::new(),
                        confidence: None,
                        parts: Vec::new(),
                    });
                }
                continue;
            };
            let prior: Vec<&Hit> = earlier.iter().chain(out.iter()).collect();
            let mut found = self.rule_hits(i, candidates, pass, frag, path, &prior);
            if !rule.components.is_empty() {
                found.retain_mut(|h| match self.components_near(rule, h, pass, frag, path) {
                    Some(parts) => {
                        h.parts = parts;
                        true
                    }
                    None => false,
                });
            }
            out.extend(found);
        }
        out
    }

    /// The rules whose keywords are in `text`.
    fn keyword_gate(&self, text: &[u8]) -> HashSet<usize> {
        let res = self.rules.keywords.scan(text, &ScanOptions::default());
        res.matches.iter().filter_map(|h| rules::keyword_owner(&h.rule)).collect()
    }

    /// Rule `i`'s hits in the pass, given its candidate match starts.
    fn rule_hits(
        &self,
        i: usize,
        candidates: &[(usize, usize)],
        pass: &Pass,
        frag: &[u8],
        path: &str,
        prior: &[&Hit],
    ) -> Vec<Hit> {
        let rule = &self.rules.rules[i];
        let mut out = Vec::new();
        for (start, raw_end) in find_all(rule, pass.text, candidates) {
            // betterleaks trims the match's newlines and keeps its start.
            let whole = &pass.text[start..raw_end];
            let trimmed = trim_newlines(whole);
            let end = start + trimmed.len();
            let (orig, tags) = if pass.depth == 0 {
                ((start, end), Vec::new())
            } else {
                match pass.decoder.map(start, end) {
                    Some(m) => m,
                    None => continue, // not in text this pass decoded
                }
            };
            let line = line_of(frag, orig.0, orig.1);
            if ALLOW.iter().any(|a| contains(line, a)) {
                continue;
            }
            let Some(secret) = secret_of(rule, trimmed) else { continue };
            let line_no = frag[..orig.0.min(frag.len())].iter().filter(|&&b| b == b'\n').count();
            let mut hit = Hit { rule: i, secret, start, end, orig, line_no, tags, confidence: None, parts: Vec::new() };
            if suppressed_by(&self.rules.rules, &hit, prior.iter().copied().chain(out.iter())) {
                continue;
            }
            let line = if pass.depth == 0 { line } else { pass.decoder.line(start, end) };
            let ctx = Ctx { secret: &hit.secret, matched: trimmed, line, path: path.as_bytes() };
            let (skip, confidence) = self.skipped(rule, &ctx, pass.text, start, raw_end);
            if skip {
                continue;
            }
            hit.confidence = confidence;
            out.push(hit);
        }
        out
    }

    /// Whether a filter skips the candidate at `start..end` (untrimmed) of
    /// the pass's `text`, and the confidence its program set, if any.
    fn skipped(
        &self,
        rule: &SecretRule,
        ctx: &Ctx,
        text: &[u8],
        start: usize,
        end: usize,
    ) -> (bool, Option<rules::Confidence>) {
        for g in &self.rules.filters {
            if (g.applies_to.is_empty() || g.applies_to.contains(&rule.id)) && skips(&g.skips, ctx) {
                return (true, None);
            }
        }
        if skips(&rule.skips, ctx) {
            return (true, None);
        }
        let Some(program) = &rule.program else { return (false, None) };
        let line_start = text[..start].iter().rposition(|&b| b == b'\n' || b == b'\r').map_or(0, |i| i + 1);
        let line_end = text[end..].iter().position(|&b| b == b'\n' || b == b'\r').map_or(text.len(), |i| end + i);
        let s = |b: &[u8]| expr::Value::Str(b.to_vec());
        let n = |v: usize| expr::Value::Num(v as f64);
        let env = expr::Env {
            finding: vec![
                ("secret", s(ctx.secret)),
                ("match", s(ctx.matched)),
                ("line", s(ctx.line)),
                ("rule_id", s(rule.id.as_bytes())),
                ("description", s(rule.description.as_bytes())),
                ("entropy", s(format!("{}", entropy(ctx.secret)).as_bytes())),
                ("fragment_raw", s(text)),
                ("match_start_idx", n(start)),
                ("match_end_idx", n(end)),
                ("match_line_start_idx", n(line_start)),
                ("match_line_end_idx", n(line_end)),
            ],
            attributes: vec![("path", s(ctx.path))],
            confidence: Default::default(),
            _text: Default::default(),
        };
        // A program that fails keeps the finding, as betterleaks does.
        let skip = program.skips(&env).unwrap_or(false);
        let confidence = match env.confidence.borrow().as_deref() {
            Some("high") => Some(rules::Confidence::High),
            Some("medium") => Some(rules::Confidence::Medium),
            Some("low") => Some(rules::Confidence::Low),
            _ => None,
        };
        (skip, confidence)
    }

    /// The component hits near `hit`, when every required component of
    /// `rule` has one; None when one is missing.
    fn components_near(&self, rule: &SecretRule, hit: &Hit, pass: &Pass, frag: &[u8], path: &str) -> Option<Vec<Hit>> {
        let mut parts = Vec::new();
        for c in &rule.components {
            let near_hits: Vec<Hit> = match self.rules.by_id(&c.id) {
                Some(ci) => self
                    .component_hits(ci, pass, frag, path)
                    .into_iter()
                    .filter(|h| near(c, hit, h, pass.text))
                    .collect(),
                None => Vec::new(),
            };
            if near_hits.is_empty() && !c.optional {
                return None;
            }
            parts.extend(near_hits);
        }
        Some(parts)
    }

    /// A component rule's hits in the pass: its filters apply, its keywords
    /// gate it, and it's run even if private.
    fn component_hits(&self, ci: usize, pass: &Pass, frag: &[u8], path: &str) -> Vec<Hit> {
        let rule = &self.rules.rules[ci];
        if !rule.keywords.is_empty() && !self.keyword_gate(pass.text).contains(&ci) {
            return Vec::new();
        }
        let Some((s, _, _)) = &rule.regex else { return Vec::new() };
        let opts = ScanOptions { filepath: Some(path.to_string()), ..Default::default() };
        let spans = match self.rules.loose.iter().find(|(r, _)| *r == ci) {
            Some((_, set)) => set.scan_spans(pass.text, &opts).1.by_string.swap_remove(*s),
            None => self.rules.yara.scan_spans(pass.text, &opts).1.by_string.swap_remove(*s),
        };
        self.rule_hits(ci, &spans, pass, frag, path, &[])
    }
}

/// What a filter reads about one candidate.
#[derive(Clone, Copy)]
pub struct Ctx<'a> {
    pub secret: &'a [u8],
    pub matched: &'a [u8],
    pub line: &'a [u8],
    pub path: &'a [u8],
}

impl Ctx<'_> {
    fn get(&self, t: Target) -> &[u8] {
        match t {
            Target::Secret => self.secret,
            Target::Match => self.matched,
            Target::Line => self.line,
            Target::Path => self.path,
        }
    }
}

/// Whether any of `s`'s skips holds for `ctx`.
pub fn skips(s: &Skips, ctx: &Ctx) -> bool {
    if s.is_empty() {
        return false;
    }
    let e = entropy(ctx.secret);
    if s.entropy_le.is_some_and(|v| e <= v) || s.entropy_lt.is_some_and(|v| e < v) {
        return true;
    }
    // betterleaks' token checks: readable text ([`readable`]).
    if (s.token_ratio_ge.is_some() || s.token_efficiency) && readable::readable(ctx.secret) {
        return true;
    }
    if s.regex.iter().any(|(t, re)| matcher::search(re, ctx.get(*t))) {
        return true;
    }
    if s.words.iter().any(|(t, w)| contains(&ctx.get(*t).to_ascii_lowercase(), w)) {
        return true;
    }
    s.require.iter().any(|(t, re)| !matcher::search(re, ctx.get(*t)))
}

fn any_regex(s: &Skips, t: Target, text: &[u8]) -> bool {
    s.regex.iter().any(|(tt, re)| *tt == t && matcher::search(re, text))
}

/// Shannon entropy over bytes, as betterleaks' filters compute it.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| c as f64 / n).map(|p| -p * p.log2()).sum()
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

fn trim_newlines(s: &[u8]) -> &[u8] {
    let a = s.iter().position(|&b| b != b'\n').unwrap_or(s.len());
    let b = s.iter().rposition(|&b| b != b'\n').map_or(a, |i| i + 1);
    &s[a..b.max(a)]
}

/// RE2's FindAll: the leftmost-first matches, none overlapping, from the
/// candidate starts the engine verified (a superset of the starts of matches).
fn find_all(rule: &SecretRule, text: &[u8], candidates: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let Some((_, tree, groups)) = &rule.regex else { return Vec::new() };
    let mut out: Vec<(usize, usize)> = Vec::new();
    let mut pos = 0;
    let mut starts: Vec<usize> = candidates.iter().map(|c| c.0).collect();
    starts.sort_unstable();
    starts.dedup();
    for s in starts {
        if s < pos {
            continue;
        }
        let m = Matcher::new(text, s, true, rules::REACH).captures(tree, s, *groups);
        let Some(Some((a, b))) = m.map(|c| c[0]) else { continue };
        // An empty match right after the last one doesn't count.
        if a == b && out.last().is_some_and(|l| l.1 == a) {
            pos = a + 1;
            continue;
        }
        out.push((a, b));
        pos = if b > a { b } else { a + 1 };
    }
    out
}

/// The secret in a trimmed match: the regex run again on just the match.
fn secret_of(rule: &SecretRule, matched: &[u8]) -> Option<Vec<u8>> {
    let Some((_, tree, groups)) = &rule.regex else { return Some(Vec::new()) };
    let Some(caps) = matcher::search_captures(tree, matched, *groups) else { return Some(matched.to_vec()) };
    if *groups == 0 {
        return Some(matched.to_vec());
    }
    let group = |g: usize| caps.get(g).copied();
    if rule.secret_group > 0 {
        let g = group(rule.secret_group as usize)?;
        return Some(g.map(|(a, b)| matched[a..b].to_vec()).unwrap_or_default());
    }
    for g in 1..=*groups as usize {
        if let Some(Some((a, b))) = group(g)
            && b > a
        {
            return Some(matched[a..b].to_vec());
        }
    }
    Some(matched.to_vec())
}

/// Whether a hit of higher specificity, on the same line, with a secret
/// containing this one's, outranks it.
fn suppressed_by<'a>(rules: &[SecretRule], hit: &Hit, mut others: impl Iterator<Item = &'a Hit>) -> bool {
    let outranks = |o: &Hit| {
        o.rule != hit.rule
            && o.line_no == hit.line_no
            && rules[o.rule].specificity > rules[hit.rule].specificity
            && contains(&o.secret, &hit.secret)
    };
    // A multipart finding's parts outrank only findings of other rules than its own.
    others.any(|o| outranks(o) || (o.rule != hit.rule && o.parts.iter().any(outranks)))
}

/// The fragment's final pass: drop each hit a higher-specificity one
/// outranks (betterleaks runs this once more over the whole fragment).
fn suppress(rules: &[SecretRule], hits: &mut Vec<Hit>) {
    // A finding that is also a part of a multipart one is reported as that part.
    let part = |h: &Hit| {
        hits.iter().any(|o| o.parts.iter().any(|p| p.rule == h.rule && p.orig == h.orig && p.secret == h.secret))
    };
    let keep: Vec<bool> = (0..hits.len())
        .map(|i| {
            let others = hits.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, o)| o);
            !part(&hits[i]) && !suppressed_by(rules, &hits[i], others)
        })
        .collect();
    let mut keep = keep.into_iter();
    hits.retain(|_| keep.next().unwrap_or(true));
}

fn near(c: &Component, primary: &Hit, comp: &Hit, text: &[u8]) -> bool {
    let w: Window = c.within;
    if w.is_fragment() {
        return true;
    }
    let p = location(text, primary.start, primary.end, 1);
    let q = location(text, comp.start, comp.end, 1);
    let lines = w.lines_before.is_some() || w.lines_after.is_some();
    if !lines {
        let lo = primary.start.saturating_sub(w.cols_before.unwrap_or(0));
        let hi = primary.end + w.cols_after.unwrap_or(0);
        return comp.start >= lo && comp.start < hi;
    }
    let lo = p.start_line.saturating_sub(w.lines_before.unwrap_or(0));
    let hi = p.end_line + w.lines_after.unwrap_or(0);
    if q.start_line < lo || q.start_line > hi {
        return false;
    }
    if p.start_line == p.end_line && (w.cols_before.is_some() || w.cols_after.is_some()) {
        let col = q.start_col - 1;
        let lo = (p.start_col - 1).saturating_sub(w.cols_before.unwrap_or(0));
        let hi = p.end_col + w.cols_after.unwrap_or(0);
        return col >= lo && col < hi;
    }
    true
}

pub struct Location {
    pub start_line: usize,
    pub end_line: usize,
    pub start_col: usize,
    pub end_col: usize,
}

/// betterleaks' location of `start..end` in a fragment whose first line is
/// `first_line`: 1-based lines, 1-based byte columns from the line's start.
pub fn location(frag: &[u8], start: usize, end: usize, first_line: usize) -> Location {
    let line_start = |at: usize| frag[..at.min(frag.len())].iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    let lines_before = |at: usize| frag[..at.min(frag.len())].iter().filter(|&&b| b == b'\n').count();
    let last = end.saturating_sub(1).max(start);
    Location {
        start_line: first_line + lines_before(start),
        end_line: first_line + lines_before(last),
        start_col: start - line_start(start) + 1,
        end_col: end.max(start + 1) - line_start(last),
    }
}

/// The whole lines `start..end` is on, line ends included.
fn line_of(frag: &[u8], start: usize, end: usize) -> &[u8] {
    let a = frag[..start.min(frag.len())].iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    let last = end.saturating_sub(1).max(start).min(frag.len());
    let b = frag[last..].iter().position(|&b| b == b'\n').map_or(frag.len(), |i| last + i + 1);
    &frag[a..b]
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
