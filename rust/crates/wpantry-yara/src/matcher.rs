//! A backtracking matcher over [`Node`] trees, forwards or backwards.
//!
//! Strings are found from an atom outwards, as YARA does: the part of a
//! pattern from the atom on is matched forwards from the atom's position, and
//! the part before it is matched backwards (the reversed tree, read right to
//! left) to find where the match starts. Backtracking keeps lazy and greedy
//! repeats and hex jumps exact; a step budget bounds the worst case, and a
//! repeat of a single byte set (`.*`, `[a-z]+`, a jump) is a loop rather than
//! a recursion, so long runs never deepen the stack.

use crate::pattern::{Assert, ByteSet, Node};
use std::cell::{Cell, RefCell};

/// Steps one anchored attempt may take before it gives up (no match).
pub const STEPS_PER_ATTEMPT: u64 = 1 << 20;

pub struct Matcher<'d> {
    data: &'d [u8],
    /// The positions a match may reach: `lo..=hi`.
    lo: usize,
    hi: usize,
    forward: bool,
    budget: Cell<u64>,
    /// Where each capture group matched, while [`Matcher::captures`] runs.
    caps: RefCell<Vec<Option<(usize, usize)>>>,
}

/// Each group's `(start, end)`, index 0 the whole match; None where a group took no part.
pub type Captures = Vec<Option<(usize, usize)>>;

impl<'d> Matcher<'d> {
    /// A matcher anchored at `start`, reading forwards (or backwards) at most
    /// `limit` bytes.
    pub fn new(data: &'d [u8], start: usize, forward: bool, limit: usize) -> Self {
        let (lo, hi) = if forward {
            (start, start.saturating_add(limit).min(data.len()))
        } else {
            (start.saturating_sub(limit), start)
        };
        Matcher { data, lo, hi, forward, budget: Cell::new(STEPS_PER_ATTEMPT), caps: RefCell::new(Vec::new()) }
    }

    /// The end of the first match (in pattern priority order) of `node` from `start`.
    pub fn first(&self, node: &Node, start: usize) -> Option<usize> {
        let mut found = None;
        self.m(node, start, &mut |end| {
            found = Some(end);
            true
        });
        found
    }

    /// The first match of `node` (from [`crate::pattern::parse_regex_groups`],
    /// with `groups` groups) from `start`, reading forwards, with where each
    /// group matched: the last iteration's, for a group in a repeat.
    pub fn captures(&self, node: &Node, start: usize, groups: u32) -> Option<Captures> {
        *self.caps.borrow_mut() = vec![None; groups as usize + 1];
        let mut found = None;
        self.m(node, start, &mut |end| {
            let mut caps = self.caps.borrow().clone();
            caps[0] = Some((start, end));
            found = Some(caps);
            true
        });
        found
    }

    /// Every distinct end position a match of `node` from `start` can reach.
    pub fn all(&self, node: &Node, start: usize) -> Vec<usize> {
        let mut ends = Vec::new();
        self.m(node, start, &mut |end| {
            if !ends.contains(&end) {
                ends.push(end);
            }
            false
        });
        ends
    }

    fn tick(&self) -> bool {
        let left = self.budget.get();
        if left == 0 {
            return false;
        }
        self.budget.set(left - 1);
        true
    }

    /// The byte the next step consumes from `pos`, if one is in range.
    fn byte(&self, pos: usize) -> Option<u8> {
        if self.forward { (pos < self.hi).then(|| self.data[pos]) } else { (pos > self.lo).then(|| self.data[pos - 1]) }
    }

    fn step(&self, pos: usize, n: usize) -> usize {
        if self.forward { pos + n } else { pos - n }
    }

    /// Match `node` at `pos`, calling `k` with each end until it returns true.
    fn m(&self, node: &Node, pos: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
        if !self.tick() {
            return false;
        }
        match node {
            Node::Set(set) => match self.byte(pos) {
                Some(b) if set.contains(b) => k(self.step(pos, 1)),
                _ => false,
            },
            Node::Seq(items) => self.seq(items, pos, k),
            Node::Alt(branches) => branches.iter().any(|b| self.m(b, pos, k)),
            Node::Assert(a) => self.assert(*a, pos) && k(pos),
            Node::Repeat { node, min, max, greedy } => match node.as_ref() {
                Node::Set(set) => self.run(set, pos, *min, *max, *greedy, k),
                inner => self.rep(inner, 0, *min, *max, *greedy, pos, k),
            },
            Node::Group(n, inner) => {
                let i = *n as usize;
                self.m(inner, pos, &mut |end| {
                    let span = if self.forward { (pos, end) } else { (end, pos) };
                    let saved = self.caps.borrow_mut().get_mut(i).map(|c| c.replace(span));
                    if k(end) {
                        return true;
                    }
                    if let (Some(saved), Some(c)) = (saved, self.caps.borrow_mut().get_mut(i)) {
                        *c = saved;
                    }
                    false
                })
            }
        }
    }

    fn seq(&self, items: &[Node], pos: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
        // A run of single bytes has one way to match: walk it in a loop, and
        // only recurse at the first position that can branch.
        let mut p = pos;
        let mut i = 0;
        while let Some(Node::Set(set)) = items.get(i) {
            match self.byte(p) {
                Some(b) if set.contains(b) => {
                    p = self.step(p, 1);
                    i += 1;
                }
                _ => return false,
            }
        }
        match items[i..].split_first() {
            None => k(p),
            Some((first, rest)) => self.m(first, p, &mut |q| self.seq(rest, q, k)),
        }
    }

    /// A repeat of one byte set: measure the run, then try its lengths.
    fn run(
        &self,
        set: &ByteSet,
        pos: usize,
        min: u32,
        max: Option<u32>,
        greedy: bool,
        k: &mut dyn FnMut(usize) -> bool,
    ) -> bool {
        let max = max.map_or(usize::MAX, |m| m as usize);
        let mut len = 0;
        let mut p = pos;
        while len < max {
            match self.byte(p) {
                Some(b) if set.contains(b) => {
                    len += 1;
                    p = self.step(p, 1);
                }
                _ => break,
            }
        }
        let min = min as usize;
        if len < min {
            return false;
        }
        let mut try_len = |n: usize| self.tick() && k(self.step(pos, n));
        if greedy { (min..=len).rev().any(&mut try_len) } else { (min..=len).any(try_len) }
    }

    /// A repeat of anything else, one iteration at a time.
    #[allow(clippy::too_many_arguments)]
    fn rep(
        &self,
        node: &Node,
        count: u32,
        min: u32,
        max: Option<u32>,
        greedy: bool,
        pos: usize,
        k: &mut dyn FnMut(usize) -> bool,
    ) -> bool {
        let can_more = max.is_none_or(|m| count < m);
        let more = |k: &mut dyn FnMut(usize) -> bool| {
            // An iteration that matched nothing would loop forever.
            can_more && self.m(node, pos, &mut |p| p != pos && self.rep(node, count + 1, min, max, greedy, p, k))
        };
        // Greedy tries one more iteration before stopping here; lazy the reverse.
        if greedy {
            if more(k) {
                return true;
            }
            count >= min && k(pos)
        } else {
            if count >= min && k(pos) {
                return true;
            }
            more(k)
        }
    }

    fn assert(&self, a: Assert, pos: usize) -> bool {
        let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let before = pos.checked_sub(1).and_then(|i| self.data.get(i)).is_some_and(|b| word(*b));
        let after = self.data.get(pos).is_some_and(|b| word(*b));
        match a {
            Assert::Start => pos == 0,
            Assert::End => pos == self.data.len(),
            Assert::WordBoundary => before != after,
            Assert::NotWordBoundary => before == after,
            Assert::LineStart => pos == 0 || self.data.get(pos - 1) == Some(&b'\n'),
            Assert::LineEnd => pos == self.data.len() || self.data.get(pos) == Some(&b'\n'),
        }
    }
}

/// The leftmost match of `node` (with `groups` groups) in `data`, the first
/// in priority order from there (as RE2's leftmost-first): its captures.
pub fn search_captures(node: &Node, data: &[u8], groups: u32) -> Option<Captures> {
    (0..=data.len()).find_map(|start| Matcher::new(data, start, true, data.len()).captures(node, start, groups))
}

/// Whether `node` matches anywhere in `data` (the `matches` operator).
pub fn search(node: &Node, data: &[u8]) -> bool {
    (0..=data.len()).any(|start| Matcher::new(data, start, true, data.len()).first(node, start).is_some())
}

#[cfg(test)]
#[path = "matcher_tests.rs"]
mod tests;
