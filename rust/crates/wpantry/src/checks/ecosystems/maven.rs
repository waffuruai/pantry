//! Maven ordering, as maven-artifact's `ComparableVersion` sorts (3.9): the
//! version splits on ".", "-" and digit/letter transitions into a tree of
//! numbers, qualifiers and sub-lists (each "-" or transition opens one);
//! trailing nulls (0, "", "final", "ga", "release") are dropped; qualifiers
//! order alpha < beta < milestone < rc = cr < snapshot < "" = ga = final =
//! release < sp, then unknown qualifiers alphabetically; "a1", "b1", "m1"
//! mean alpha, beta, milestone. Every string parses, so there's no fallback.

use crate::checks::ecosystems::versions::num_cmp;
use std::cmp::Ordering;

#[derive(Debug, PartialEq)]
enum Item {
    /// Digits without leading zeros ("0" for zero).
    Int(String),
    Str(String),
    List(Vec<Item>),
}

const QUALIFIERS: &[&str] = &["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];

fn qualifier(s: &str) -> String {
    match QUALIFIERS.iter().position(|q| *q == s) {
        Some(i) => i.to_string(),
        None => format!("{}-{s}", QUALIFIERS.len()),
    }
}

fn string_item(s: &str, followed_by_digit: bool) -> Item {
    let s = match (followed_by_digit, s) {
        (true, "a") => "alpha",
        (true, "b") => "beta",
        (true, "m") => "milestone",
        (_, "ga" | "final" | "release") => "",
        (_, "cr") => "rc",
        (_, s) => s,
    };
    Item::Str(s.to_string())
}

fn parse_item(digit: bool, s: &str) -> Item {
    if digit {
        let t = s.trim_start_matches('0');
        Item::Int(if t.is_empty() { "0".into() } else { t.into() })
    } else {
        string_item(s, false)
    }
}

impl Item {
    fn is_null(&self) -> bool {
        match self {
            Item::Int(n) => n == "0",
            Item::Str(s) => qualifier(s) == "5",
            Item::List(l) => l.is_empty(),
        }
    }

    /// `compareTo`, with None for the missing item past the end of a list.
    fn cmp_opt(&self, other: Option<&Item>) -> Ordering {
        use Item::*;
        match (self, other) {
            (Int(n), None) => {
                if n == "0" {
                    Ordering::Equal
                } else {
                    Ordering::Greater
                }
            }
            (Int(a), Some(Int(b))) => num_cmp(a, b),
            (Int(_), Some(_)) => Ordering::Greater,
            (Str(s), None) => qualifier(s).as_str().cmp("5"),
            (Str(_), Some(Int(_) | List(_))) => Ordering::Less,
            (Str(a), Some(Str(b))) => qualifier(a).cmp(&qualifier(b)),
            (List(l), None) => l.iter().map(|i| i.cmp_opt(None)).find(|o| o.is_ne()).unwrap_or(Ordering::Equal),
            (List(_), Some(Int(_))) => Ordering::Less,
            (List(_), Some(Str(_))) => Ordering::Greater,
            (List(a), Some(List(b))) => {
                for i in 0..a.len().max(b.len()) {
                    let o = match (a.get(i), b.get(i)) {
                        (Some(x), y) => x.cmp_opt(y),
                        (None, Some(y)) => y.cmp_opt(None).reverse(),
                        (None, None) => Ordering::Equal,
                    };
                    if o.is_ne() {
                        return o;
                    }
                }
                Ordering::Equal
            }
        }
    }
}

fn normalize(list: &mut Vec<Item>) {
    let mut i = list.len();
    while i > 0 {
        i -= 1;
        if list[i].is_null() {
            list.remove(i);
        } else if !matches!(list[i], Item::List(_)) {
            break;
        }
    }
}

fn cur(stack: &mut Vec<Vec<Item>>) -> &mut Vec<Item> {
    if stack.is_empty() {
        stack.push(Vec::new());
    }
    stack.last_mut().expect("a list")
}

/// `parseVersion`. The current list is always the last item of its parent,
/// so the open lists are a stack folded together at the end.
fn parse(version: &str) -> Item {
    let v = version.to_lowercase();
    let b = v.as_bytes();
    let mut stack: Vec<Vec<Item>> = vec![Vec::new()];
    let mut digit = false;
    let mut start = 0;
    for i in 0..b.len() {
        let c = b[i];
        if c == b'.' || c == b'-' {
            let item = if i == start { Item::Int("0".into()) } else { parse_item(digit, &v[start..i]) };
            cur(&mut stack).push(item);
            start = i + 1;
            if c == b'-' {
                stack.push(Vec::new());
            }
        } else if c.is_ascii_digit() {
            if !digit && i > start {
                if !cur(&mut stack).is_empty() {
                    stack.push(Vec::new());
                }
                cur(&mut stack).push(string_item(&v[start..i], true));
                start = i;
                stack.push(Vec::new());
            }
            digit = true;
        } else {
            if digit && i > start {
                cur(&mut stack).push(parse_item(true, &v[start..i]));
                start = i;
                stack.push(Vec::new());
            }
            digit = false;
        }
    }
    if v.len() > start {
        if !digit && !cur(&mut stack).is_empty() {
            stack.push(Vec::new());
        }
        cur(&mut stack).push(parse_item(digit, &v[start..]));
    }
    let mut list = stack.pop().unwrap_or_default();
    normalize(&mut list);
    while let Some(mut parent) = stack.pop() {
        parent.push(Item::List(list));
        normalize(&mut parent);
        list = parent;
    }
    Item::List(list)
}

pub fn cmp(a: &str, b: &str) -> Ordering {
    parse(a).cmp_opt(Some(&parse(b)))
}

#[cfg(test)]
#[path = "maven_tests.rs"]
mod tests;
