//! Packagist ordering, as Composer sorts: each version is normalized by
//! composer/semver's `VersionParser::normalize` ("v1.2" → "1.2.0.0",
//! "1.0RC1" → "1.0.0.0-RC1", "1.x-dev" → "1.9999999.9999999.9999999-dev"),
//! then compared with PHP's `version_compare` (dev < alpha = a < beta = b <
//! RC = rc < a number < pl = p; any other word below dev). `dev-` branches
//! sort as `Semver::sort` puts them: `dev-master`, `dev-trunk` and
//! `dev-default` last, others below every number, and two branches by
//! name. A version normalize rejects falls back to the generic order.

use crate::versions::num_cmp;
use std::cmp::Ordering;

#[derive(Debug, PartialEq)]
struct Modifier {
    /// The stability word as written and the number after it.
    stability: Option<(String, String)>,
    dev: bool,
}

const WORDS: &[&str] = &["stable", "beta", "b", "rc", "alpha", "a", "patch", "pl", "p"];

fn digits(s: &[u8], i: usize) -> usize {
    let mut j = i;
    while j < s.len() && s[j].is_ascii_digit() {
        j += 1;
    }
    j
}

/// The whole of `s` against `[._-]?(?:(word)((?:[.-]?\d+)*+)?)?([.-]?dev)?`,
/// case-insensitively, trying the alternatives in the regex's order.
fn modifier(s: &str) -> Option<Modifier> {
    let b = s.as_bytes();
    let starts = if !b.is_empty() && matches!(b[0], b'.' | b'_' | b'-') { vec![1, 0] } else { vec![0] };
    let dev_tail = |i: usize| -> Option<bool> {
        let rest = &s[i..];
        let r = rest.strip_prefix(['.', '-']).filter(|r| r.eq_ignore_ascii_case("dev"));
        if rest.is_empty() {
            Some(false)
        } else if rest.eq_ignore_ascii_case("dev") || r.is_some() {
            Some(true)
        } else {
            None
        }
    };
    for start in starts {
        for w in WORDS {
            let end = start + w.len();
            if end > b.len() || !b[start..end].eq_ignore_ascii_case(w.as_bytes()) {
                continue;
            }
            // ((?:[.-]?\d+)*+): possessive, so as many as match.
            let mut i = end;
            loop {
                let j = if i < b.len() && matches!(b[i], b'.' | b'-') { i + 1 } else { i };
                let k = digits(b, j);
                if k == j {
                    break;
                }
                i = k;
            }
            if let Some(dev) = dev_tail(i) {
                return Some(Modifier { stability: Some((s[start..end].to_string(), s[end..i].to_string())), dev });
            }
        }
        if let Some(dev) = dev_tail(start) {
            return Some(Modifier { stability: None, dev });
        }
    }
    None
}

fn expand(word: &str) -> String {
    match word.to_ascii_lowercase().as_str() {
        "a" => "alpha".into(),
        "b" => "beta".into(),
        "p" | "pl" => "patch".into(),
        "rc" => "RC".into(),
        w => w.into(),
    }
}

fn finish(mut version: String, m: Modifier) -> String {
    if let Some((word, num)) = m.stability {
        if word == "stable" {
            return version;
        }
        version.push('-');
        version.push_str(&expand(&word));
        version.push_str(num.trim_start_matches(['.', '-']));
    }
    if m.dev {
        version.push_str("-dev");
    }
    version
}

/// `^v?(\d{1,5}+)(\.\d++)?(\.\d++)?(\.\d++)?` then a modifier.
fn classical(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = usize::from(!b.is_empty() && (b[0] == b'v' || b[0] == b'V'));
    let start = i;
    i = digits(b, i);
    if i == start || i - start > 5 {
        return None;
    }
    let mut version = s[start..i].to_string();
    let mut parts = 0;
    while parts < 3 && i + 1 < b.len() && b[i] == b'.' && b[i + 1].is_ascii_digit() {
        let j = digits(b, i + 1);
        version.push_str(&s[i..j]);
        i = j;
        parts += 1;
    }
    for _ in parts..3 {
        version.push_str(".0");
    }
    Some(finish(version, modifier(&s[i..])?))
}

/// `^v?(\d{4}(?:[.:-]?\d{2}){1,6}(?:[.:-]?\d{1,3}){0,2})` then a modifier,
/// with the regex's backtracking order.
fn date(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let start = usize::from(!b.is_empty() && (b[0] == b'v' || b[0] == b'V'));
    if digits(b, start) < start + 4 {
        return None;
    }
    fn sep(b: &[u8], i: usize) -> Vec<usize> {
        if i < b.len() && matches!(b[i], b'.' | b':' | b'-') { vec![i + 1, i] } else { vec![i] }
    }
    fn tail(s: &str, start: usize, i: usize, n: usize) -> Option<String> {
        let b = s.as_bytes();
        if n < 2 {
            for j in sep(b, i) {
                for len in (1..=3).rev() {
                    if j + len <= b.len()
                        && b[j..j + len].iter().all(u8::is_ascii_digit)
                        && let Some(v) = tail(s, start, j + len, n + 1)
                    {
                        return Some(v);
                    }
                }
            }
        }
        let m = modifier(&s[i..])?;
        let version: String = s[start..i].chars().map(|c| if c.is_ascii_digit() { c } else { '.' }).collect();
        Some(finish(version, m))
    }
    fn pairs(s: &str, start: usize, i: usize, n: usize) -> Option<String> {
        let b = s.as_bytes();
        if n < 6 {
            for j in sep(b, i) {
                if j + 2 <= b.len()
                    && b[j..j + 2].iter().all(u8::is_ascii_digit)
                    && let Some(v) = pairs(s, start, j + 2, n + 1)
                {
                    return Some(v);
                }
            }
        }
        if n >= 1 { tail(s, start, i, 0) } else { None }
    }
    pairs(s, start, start + 4, 0)
}

/// `normalizeBranch` for a name that ended in "-dev": numeric branches only.
fn numeric_branch(name: &str) -> Option<String> {
    let name = name.trim();
    let name = name.strip_prefix(['v', 'V']).unwrap_or(name);
    let mut parts = name.split('.');
    let major = parts.next()?;
    if major.is_empty() || !major.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut version = major.to_string();
    let rest: Vec<&str> = parts.collect();
    if rest.len() > 3 {
        return None;
    }
    for i in 0..3 {
        match rest.get(i) {
            Some(p) if !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) => version.push_str(&format!(".{p}")),
            Some(&("x" | "X" | "*")) | None => version.push_str(".9999999"),
            Some(_) => return None,
        }
    }
    Some(version + "-dev")
}

/// composer/semver `VersionParser::normalize`; None where it throws.
pub fn normalize(v: &str) -> Option<String> {
    let mut v = v.trim();
    // "x as y" aliases: the version is x.
    let words: Vec<&str> = v.split(' ').filter(|w| !w.is_empty()).collect();
    let plain = |w: &str| !w.contains(|c: char| c == ',' || c.is_whitespace());
    if words.len() == 3 && words[1] == "as" && plain(words[0]) && plain(words[2]) {
        v = words[0];
    }
    // A stability flag.
    if let Some(at) = v.rfind('@') {
        let flag = &v[at + 1..];
        if ["stable", "rc", "beta", "alpha", "dev"].iter().any(|s| flag.eq_ignore_ascii_case(s)) {
            v = &v[..at];
        }
    }
    if matches!(v, "master" | "trunk" | "default") {
        return Some(format!("dev-{v}"));
    }
    if v.len() >= 4 && v.as_bytes()[..4].eq_ignore_ascii_case(b"dev-") {
        return Some(format!("dev-{}", &v[4..]));
    }
    // Build metadata.
    if let Some((head, meta)) = v.split_once('+')
        && !head.is_empty()
        && !head.contains([',', ' ', '\t', '\n', '\r'])
        && !meta.is_empty()
        && !meta.contains(char::is_whitespace)
    {
        v = head;
    }
    if let Some(n) = classical(v).or_else(|| date(v)) {
        return Some(n);
    }
    let lower = v.to_ascii_lowercase();
    if let Some(head) = lower.strip_suffix("dev") {
        let head = &v[..head.len()];
        let head = head.strip_suffix(['.', '-']).unwrap_or(head);
        return numeric_branch(head);
    }
    None
}

/// PHP's `php_canonicalize_version`: "-", "_" and "+" become ".", a dot
/// goes between digits and non-digits, other non-alphanumerics become ".".
fn canonicalize(v: &[u8]) -> Vec<u8> {
    let Some((&first, rest)) = v.split_first() else { return Vec::new() };
    let mut out = vec![first];
    let mut lp = first;
    let dig = |c: u8| c.is_ascii_digit();
    let ndig = |c: u8| !c.is_ascii_digit() && c != b'.';
    for &c in rest {
        let lq = *out.last().unwrap_or(&b'.');
        if matches!(c, b'-' | b'_' | b'+') {
            if lq != b'.' {
                out.push(b'.');
            }
        } else if (ndig(lp) && dig(c)) || (dig(lp) && ndig(c)) {
            if lq != b'.' {
                out.push(b'.');
            }
            out.push(c);
        } else if !c.is_ascii_alphanumeric() {
            if lq != b'.' {
                out.push(b'.');
            }
        } else {
            out.push(c);
        }
        lp = c;
    }
    out
}

fn special(form: &[u8]) -> i32 {
    const FORMS: &[(&[u8], i32)] = &[
        (b"dev", 0),
        (b"alpha", 1),
        (b"a", 1),
        (b"beta", 2),
        (b"b", 2),
        (b"RC", 3),
        (b"rc", 3),
        (b"#", 4),
        (b"pl", 5),
        (b"p", 5),
    ];
    FORMS.iter().find(|(name, _)| form.starts_with(name)).map_or(-1, |(_, order)| *order)
}

fn special_cmp(a: &[u8], b: &[u8]) -> Ordering {
    special(a).cmp(&special(b))
}

fn first_digit(s: &[u8]) -> bool {
    s.first().is_some_and(u8::is_ascii_digit)
}

/// PHP's `version_compare` (php-src ext/standard/versioning.c), with
/// numbers compared at any length where PHP saturates at `LONG_MAX`.
pub fn version_compare(a: &[u8], b: &[u8]) -> Ordering {
    if a.is_empty() || b.is_empty() {
        return (!a.is_empty()).cmp(&!b.is_empty());
    }
    let v1 = if a[0] == b'#' { a.to_vec() } else { canonicalize(a) };
    let v2 = if b[0] == b'#' { b.to_vec() } else { canonicalize(b) };
    let (mut p1, mut p2) = (&v1[..], &v2[..]);
    let (mut more1, mut more2) = (true, true);
    let mut compare = Ordering::Equal;
    while !p1.is_empty() && !p2.is_empty() && more1 && more2 {
        let (s1, r1) = match p1.iter().position(|c| *c == b'.') {
            Some(i) => (&p1[..i], Some(&p1[i + 1..])),
            None => (p1, None),
        };
        let (s2, r2) = match p2.iter().position(|c| *c == b'.') {
            Some(i) => (&p2[..i], Some(&p2[i + 1..])),
            None => (p2, None),
        };
        more1 = r1.is_some();
        more2 = r2.is_some();
        compare = match (first_digit(s1), first_digit(s2)) {
            (true, true) => {
                let n1 =
                    std::str::from_utf8(&s1[..s1.iter().take_while(|c| c.is_ascii_digit()).count()]).unwrap_or("0");
                let n2 =
                    std::str::from_utf8(&s2[..s2.iter().take_while(|c| c.is_ascii_digit()).count()]).unwrap_or("0");
                num_cmp(n1, n2)
            }
            (false, false) => special_cmp(s1, s2),
            (true, false) => special_cmp(b"#N#", s2),
            (false, true) => special_cmp(s1, b"#N#"),
        };
        if compare.is_ne() {
            break;
        }
        if let Some(r) = r1 {
            p1 = r;
        }
        if let Some(r) = r2 {
            p2 = r;
        }
    }
    if compare.is_eq() {
        if more1 {
            compare = if first_digit(p1) { Ordering::Greater } else { version_compare(p1, b"#N#") };
        } else if more2 {
            compare = if first_digit(p2) { Ordering::Less } else { version_compare(b"#N#", p2) };
        }
    }
    compare
}

/// `Semver::sort`'s key: the default branches normalize to 9999999-dev.
fn sort_key(v: &str) -> Option<String> {
    let n = normalize(v)?;
    Some(match n.as_str() {
        "dev-master" | "dev-default" | "dev-trunk" => "9999999-dev".to_string(),
        _ => n,
    })
}

pub fn cmp(a: &str, b: &str) -> Ordering {
    match (sort_key(a), sort_key(b)) {
        (Some(x), Some(y)) if x.starts_with("dev-") && y.starts_with("dev-") => x.cmp(&y),
        (Some(x), Some(y)) => version_compare(x.as_bytes(), y.as_bytes()),
        _ => crate::versions::cmp(a, b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // composer/semver tests/VersionParserTest.php (MIT):
    // successfulNormalizedVersions and failingNormalizedVersions.
    #[test]
    fn version_parser_normalize() {
        let ok = [
            ("1.0.0", "1.0.0.0"),
            ("1.2.3.4", "1.2.3.4"),
            ("1.0.0RC1dev", "1.0.0.0-RC1-dev"),
            ("1.0.0-rC15-dev", "1.0.0.0-RC15-dev"),
            ("1.0.0.RC.15-dev", "1.0.0.0-RC15-dev"),
            ("1.0.0-rc1", "1.0.0.0-RC1"),
            ("1.0.0.pl3-dev", "1.0.0.0-patch3-dev"),
            ("1.0-dev", "1.0.0.0-dev"),
            ("0", "0.0.0.0"),
            ("99999", "99999.0.0.0"),
            ("10.4.13-beta", "10.4.13.0-beta"),
            ("10.4.13beta2", "10.4.13.0-beta2"),
            ("10.4.13beta.2", "10.4.13.0-beta2"),
            ("v1.13.11-beta.0", "1.13.11.0-beta0"),
            ("1.13.11.0-beta0", "1.13.11.0-beta0"),
            ("10.4.13-b", "10.4.13.0-beta"),
            ("10.4.13-b5", "10.4.13.0-beta5"),
            ("v1.0.0", "1.0.0.0"),
            ("2010.01", "2010.01.0.0"),
            ("2010.01.02", "2010.01.02.0"),
            ("2010.1.555", "2010.1.555.0"),
            ("2010.10.200", "2010.10.200.0"),
            ("20230131.0.0", "20230131.0.0"),
            ("202301310000.0.0", "202301310000.0.0"),
            ("v20100102", "20100102"),
            ("20100102", "20100102"),
            ("20100102.0", "20100102.0"),
            ("20100102.1.0", "20100102.1.0"),
            ("20100102.0.3", "20100102.0.3"),
            ("100000", "100000"),
            ("2010-01-02-10-20-30.0.3", "2010.01.02.10.20.30.0.3"),
            ("2010-01-02-10-20-30.5", "2010.01.02.10.20.30.5"),
            ("2010-01-02", "2010.01.02"),
            ("2012.06.07", "2012.06.07.0"),
            ("2010-01-02.5", "2010.01.02.5"),
            ("20100102-203040", "20100102.203040"),
            ("20100102.x-dev", "20100102.9999999.9999999.9999999-dev"),
            ("20100102.203040.x-dev", "20100102.203040.9999999.9999999-dev"),
            ("20100102203040-10", "20100102203040.10"),
            ("20100102-203040-p1", "20100102.203040-patch1"),
            ("201903.0", "201903.0"),
            ("201903.x-dev", "201903.9999999.9999999.9999999-dev"),
            ("201903.0-p2", "201903.0-patch2"),
            ("dev-master", "dev-master"),
            ("master", "dev-master"),
            ("dev-trunk", "dev-trunk"),
            ("1.x-dev", "1.9999999.9999999.9999999-dev"),
            ("dev-feature-foo", "dev-feature-foo"),
            ("DEV-FOOBAR", "dev-FOOBAR"),
            ("dev-feature/foo", "dev-feature/foo"),
            ("dev-feature+issue-1", "dev-feature+issue-1"),
            ("dev-master as 1.0.0", "dev-master"),
            ("dev-load-varnish-only-when-used as ^2.0", "dev-load-varnish-only-when-used"),
            ("dev-load-varnish-only-when-used@dev as ^2.0@dev", "dev-load-varnish-only-when-used"),
            ("1.0.0+foo@dev", "1.0.0.0"),
            ("dev-load-varnish-only-when-used@stable", "dev-load-varnish-only-when-used"),
            ("1.0.0-beta.5+foo", "1.0.0.0-beta5"),
            ("1.0.0+foo", "1.0.0.0"),
            ("1.0.0-alpha.3.1+foo", "1.0.0.0-alpha3.1"),
            ("1.0.0-alpha2.1+foo", "1.0.0.0-alpha2.1"),
            ("1.0.0-alpha-2.1-3+foo", "1.0.0.0-alpha2.1-3"),
            ("1.0.0+foo as 2.0", "1.0.0.0"),
            ("00.01.03.04", "00.01.03.04"),
            ("000.001.003.004", "000.001.003.004"),
            ("0.000.103.204", "0.000.103.204"),
            ("0700", "0700.0.0.0"),
            ("041.x-dev", "041.9999999.9999999.9999999-dev"),
            ("dev-041.003", "dev-041.003"),
            ("dev-1.0.0-dev<1.0.5-dev", "dev-1.0.0-dev<1.0.5-dev"),
            ("dev-foo bar", "dev-foo bar"),
            (" 1.0.0", "1.0.0.0"),
            ("1.0.0 ", "1.0.0.0"),
        ];
        for (input, want) in ok {
            assert_eq!(normalize(input).as_deref(), Some(want), "{input:?}");
        }
        let bad = [
            "",
            "a",
            "1.0.0-meh",
            "1.0.0.0.0",
            "feature-foo",
            "1.0.0+foo bar",
            "1.0.1-SNAPSHOT",
            "1.0.0<1.0.5-dev",
            "1.0.0-dev<1.0.5-dev",
            "foo bar-dev",
            "1.0 .2",
            " as ",
            " as 1.2",
            "^",
            "^8 || ^",
            "~",
            "~1 ~",
            "~1",
            "^1",
            "1.*",
            "20100102.0.3.4",
            "100000.0.0.0",
            "2023013.0.0",
            "202301311.0.0",
            "20230131000.0.0",
            "2023013100000.0.0",
        ];
        for input in bad {
            assert_eq!(normalize(input), None, "{input:?}");
        }
    }

    // composer/semver tests/ComparatorTest.php compareProvider (MIT), on raw
    // strings as Comparator::compare passes them to version_compare.
    #[test]
    fn comparator_test() {
        use Ordering::*;
        let cases = [
            ("1.25.0", "1.24.0", Greater),
            ("1.25.0", "1.25.0", Equal),
            ("1.25.0", "1.26.0", Less),
            ("1.25.0-beta2.1", "1.25.0-b.3", Less),
            ("1.25.0-b2.1", "1.25.0beta.3", Less),
            ("1.25.0-b-2.1", "1.25.0-rc", Less),
            ("1.25.0-beta2.1", "1.25.0-b.2.1", Equal),
            ("1.25.0beta2.1", "1.25.0-b2.1", Equal),
            ("1.0.0", "1.2-dev", Less),
            ("dev-foo", "1.26.0", Less),
            ("1.26.0", "dev-foo", Greater),
        ];
        for (a, b, want) in cases {
            assert_eq!(version_compare(a.as_bytes(), b.as_bytes()), want, "{a} vs {b}");
            assert_eq!(cmp(a, b), want, "{a} vs {b} normalized");
        }
    }

    // composer/semver tests/SemverTest.php sortProvider (MIT).
    #[test]
    fn semver_sort() {
        let mut v = vec!["1.0", "0.1", "0.1", "3.2.1", "2.4.0-alpha", "2.4.0"];
        v.sort_by(|a, b| cmp(a, b));
        assert_eq!(v, ["0.1", "0.1", "1.0", "2.4.0-alpha", "2.4.0", "3.2.1"]);
        let mut v = vec!["dev-foo", "dev-master", "1.0", "50.2"];
        v.sort_by(|a, b| cmp(a, b));
        assert_eq!(v, ["dev-foo", "1.0", "50.2", "dev-master"]);
    }

    #[test]
    fn lockfile_spellings() {
        assert_eq!(cmp("v6.4.0", "6.4.0"), Ordering::Equal);
        assert_eq!(cmp("v6.4.1", "6.4.0"), Ordering::Greater);
        assert_eq!(cmp("2.0.0-RC1", "2.0.0"), Ordering::Less);
        assert_eq!(cmp("2.0.0", "2.0.0-p1"), Ordering::Less);
        assert_eq!(cmp("not a version", "1.0"), crate::versions::cmp("not a version", "1.0"));
        let _ = cmp(&"9".repeat(4000), "1");
    }
}
