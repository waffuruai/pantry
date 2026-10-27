//! Maven ordering, as maven-artifact's `ComparableVersion` sorts (3.9): the
//! version splits on ".", "-" and digit/letter transitions into a tree of
//! numbers, qualifiers and sub-lists (each "-" or transition opens one);
//! trailing nulls (0, "", "final", "ga", "release") are dropped; qualifiers
//! order alpha < beta < milestone < rc = cr < snapshot < "" = ga = final =
//! release < sp, then unknown qualifiers alphabetically; "a1", "b1", "m1"
//! mean alpha, beta, milestone. Every string parses, so there's no fallback.

use crate::versions::num_cmp;
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
mod tests {
    use super::*;
    use crate::compare::assert_sorted;

    fn eq(a: &str, b: &str) {
        assert_eq!(cmp(a, b), Ordering::Equal, "{a} == {b}");
        assert_eq!(cmp(b, a), Ordering::Equal, "{b} == {a}");
        assert_eq!(parse(a), parse(b), "{a} and {b} parse alike");
    }

    fn lt(a: &str, b: &str) {
        assert_eq!(cmp(a, b), Ordering::Less, "{a} < {b}");
        assert_eq!(cmp(b, a), Ordering::Greater, "{b} > {a}");
    }

    // The vectors of maven-artifact's ComparableVersionTest (Apache-2.0,
    // apache/maven maven-3.9.x).
    #[test]
    fn comparable_version_test() {
        assert_sorted(
            cmp,
            &[
                "1-alpha2snapshot",
                "1-alpha2",
                "1-alpha-123",
                "1-beta-2",
                "1-beta123",
                "1-m2",
                "1-m11",
                "1-rc",
                "1-cr2",
                "1-rc123",
                "1-SNAPSHOT",
                "1",
                "1-sp",
                "1-sp2",
                "1-sp123",
                "1-abc",
                "1-def",
                "1-pom-1",
                "1-1-snapshot",
                "1-1",
                "1-2",
                "1-123",
            ],
        );
        assert_sorted(
            cmp,
            &[
                "2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1", "2.1.0.1",
                "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11", "11.a", "11b", "11c",
                "11m",
            ],
        );
        // testVersionsEqual
        for (a, b) in [
            ("1", "1"),
            ("1", "1.0"),
            ("1", "1.0.0"),
            ("1.0", "1.0.0"),
            ("1", "1-0"),
            ("1", "1.0-0"),
            ("1.0", "1.0-0"),
            ("1a", "1-a"),
            ("1a", "1.0-a"),
            ("1a", "1.0.0-a"),
            ("1.0a", "1-a"),
            ("1.0.0a", "1-a"),
            ("1x", "1-x"),
            ("1x", "1.0-x"),
            ("1x", "1.0.0-x"),
            ("1.0x", "1-x"),
            ("1.0.0x", "1-x"),
            ("1ga", "1"),
            ("1release", "1"),
            ("1final", "1"),
            ("1cr", "1rc"),
            ("1a1", "1-alpha-1"),
            ("1b2", "1-beta-2"),
            ("1m3", "1-milestone-3"),
            ("1X", "1x"),
            ("1A", "1a"),
            ("1B", "1b"),
            ("1M", "1m"),
            ("1Ga", "1"),
            ("1GA", "1"),
            ("1RELEASE", "1"),
            ("1release", "1"),
            ("1RELeaSE", "1"),
            ("1Final", "1"),
            ("1FinaL", "1"),
            ("1FINAL", "1"),
            ("1Cr", "1Rc"),
            ("1cR", "1rC"),
            ("1m3", "1Milestone3"),
            ("1m3", "1MileStone3"),
            ("1m3", "1MILESTONE3"),
            ("1-abcdefghijklmnopqrstuvwxyz", "1-ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ] {
            eq(a, b);
        }
        // testVersionComparing
        for (a, b) in [
            ("1", "2"),
            ("1.5", "2"),
            ("1", "2.5"),
            ("1.0", "1.1"),
            ("1.1", "1.2"),
            ("1.0.0", "1.1"),
            ("1.0.1", "1.1"),
            ("1.1", "1.2.0"),
            ("1.0-alpha-1", "1.0"),
            ("1.0-alpha-1", "1.0-alpha-2"),
            ("1.0-alpha-1", "1.0-beta-1"),
            ("1.0-beta-1", "1.0-SNAPSHOT"),
            ("1.0-SNAPSHOT", "1.0"),
            ("1.0-alpha-1-SNAPSHOT", "1.0-alpha-1"),
            ("1.0", "1.0-1"),
            ("1.0-1", "1.0-2"),
            ("1.0.0", "1.0-1"),
            ("2.0-1", "2.0.1"),
            ("2.0.1-klm", "2.0.1-lmn"),
            ("2.0.1", "2.0.1-xyz"),
            ("2.0.1", "2.0.1-123"),
            ("2.0.1-xyz", "2.0.1-123"),
            // MNG-5568
            ("6.1.0rc3", "6.1.0"),
            ("6.1.0rc3", "6.1H.5-beta"),
            ("6.1.0", "6.1H.5-beta"),
            // MNG-6572
            ("20190126.230843", "1234567890.12345"),
            ("1234567890.12345", "123456789012345.1H.5-beta"),
            ("20190126.230843", "123456789012345.1H.5-beta"),
            ("123456789012345.1H.5-beta", "12345678901234567890.1H.5-beta"),
            ("1234567890.12345", "12345678901234567890.1H.5-beta"),
            ("20190126.230843", "12345678901234567890.1H.5-beta"),
            // MNG-6964
            ("1-0.alpha", "1"),
            ("1-0.beta", "1"),
            ("1-0.alpha", "1-0.beta"),
        ] {
            lt(a, b);
        }
        // testVersionEqualWithLeadingZeroes, testVersionZeroEqualWithLeadingZeroes
        for n in 1..=19 {
            eq(&format!("{}1", "0".repeat(n - 1)), "1");
            eq(&"0".repeat(n), "0");
        }
        // testMng7644
        for x in ["abc", "alpha", "a", "beta", "b", "def", "milestone", "m", "RC"] {
            lt(&format!("1.0.0.{x}1"), &format!("1.0.0-{x}2"));
            eq(&format!("2-{x}"), &format!("2.0.{x}"));
            eq(&format!("2-{x}"), &format!("2.0.0.{x}"));
            eq(&format!("2.0.{x}"), &format!("2.0.0.{x}"));
        }
    }

    #[test]
    fn odd_input_never_panics() {
        for v in ["", "-", ".", "..-", "é", "1-é2", "--1", "1..", "v1.2"] {
            let _ = cmp(v, "1.0");
        }
        assert_eq!(cmp("", "0"), Ordering::Equal);
    }
}
