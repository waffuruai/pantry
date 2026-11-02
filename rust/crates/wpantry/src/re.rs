//! A small backtracking regular-expression engine, in tree rather than a
//! crate (the PRD's dependency allowlist), for the patterns the scanner reads
//! tool output with: the catalog's version patterns, tool listings, release
//! feeds. It follows Python's `re` for the subset those use: literals, `.`,
//! `\d \D \s \S \w \W \b`, classes `[...]` with ranges and negation, groups
//! `( )` and `(?: )`, alternation, `* + ? {n} {n,} {n,m}` greedy or lazy,
//! `^ $`, lookahead `(?= )` and `(?! )`, and the flags i (ignore case), m
//! (multiline) and s (dot matches newline). Patterns are compiled from
//! constants, so a malformed one is a bug and panics; matching never panics
//! and gives up (no match) after a bounded number of steps.

#[derive(Clone, Debug)]
enum Item {
    Char(char),
    Range(char, char),
    Digit(bool),
    Space(bool),
    Word(bool),
}

#[derive(Clone, Debug)]
enum Node {
    Char(char),
    Any,
    Class(Vec<Item>, bool),
    Digit(bool),
    Space(bool),
    Word(bool),
    Start,
    End,
    Boundary,
    Group(Vec<Vec<Node>>, Option<usize>),
    Look(Vec<Vec<Node>>, bool),
    Repeat(Box<Node>, usize, usize, bool),
}

#[derive(Clone, Debug)]
pub struct Regex {
    alts: Vec<Vec<Node>>,
    groups: usize,
    icase: bool,
    multiline: bool,
    dotall: bool,
}

/// The groups of one match: 0 is the whole match.
#[derive(Clone, Debug, PartialEq)]
pub struct Captures {
    pub groups: Vec<Option<String>>,
    /// Character offsets of the whole match.
    pub start: usize,
    pub end: usize,
}

impl Captures {
    /// Group `i`, or "" when it didn't take part.
    pub fn get(&self, i: usize) -> &str {
        self.groups.get(i).and_then(|g| g.as_deref()).unwrap_or("")
    }

    pub fn opt(&self, i: usize) -> Option<&str> {
        self.groups.get(i).and_then(|g| g.as_deref())
    }
}

struct Parser<'a> {
    p: Vec<char>,
    i: usize,
    groups: usize,
    src: &'a str,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.p.get(self.i).copied()
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn bad(&self, why: &str) -> ! {
        panic!("bad regex {:?} at {}: {why}", self.src, self.i)
    }

    fn alts(&mut self) -> Vec<Vec<Node>> {
        let mut alts = vec![self.seq()];
        while self.eat('|') {
            alts.push(self.seq());
        }
        alts
    }

    fn seq(&mut self) -> Vec<Node> {
        let mut seq = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom();
            let atom = self.quantified(atom);
            seq.push(atom);
        }
        seq
    }

    fn number(&mut self) -> Option<usize> {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        (self.i > start).then(|| self.p[start..self.i].iter().collect::<String>().parse().unwrap_or(0))
    }

    fn quantified(&mut self, atom: Node) -> Node {
        let (min, max) = match self.peek() {
            Some('*') => (0, usize::MAX),
            Some('+') => (1, usize::MAX),
            Some('?') => (0, 1),
            Some('{') => {
                let save = self.i;
                self.i += 1;
                let Some(lo) = self.number() else {
                    self.i = save;
                    return atom;
                };
                let hi = if self.eat(',') { self.number().unwrap_or(usize::MAX) } else { lo };
                if !self.eat('}') {
                    self.i = save;
                    return atom;
                }
                self.i -= 1; // the '}' is consumed below
                (lo, hi)
            }
            _ => return atom,
        };
        self.i += 1;
        let greedy = !self.eat('?');
        if matches!(atom, Node::Start | Node::End | Node::Boundary | Node::Look(..)) {
            self.bad("nothing to repeat");
        }
        Node::Repeat(Box::new(atom), min, max, greedy)
    }

    fn escape(&mut self) -> Node {
        let c = self.peek().unwrap_or_else(|| self.bad("trailing backslash"));
        self.i += 1;
        match c {
            'd' => Node::Digit(true),
            'D' => Node::Digit(false),
            's' => Node::Space(true),
            'S' => Node::Space(false),
            'w' => Node::Word(true),
            'W' => Node::Word(false),
            'b' => Node::Boundary,
            'n' => Node::Char('\n'),
            't' => Node::Char('\t'),
            'r' => Node::Char('\r'),
            c if c.is_ascii_alphanumeric() => self.bad("unknown escape"),
            c => Node::Char(c),
        }
    }

    fn class(&mut self) -> Node {
        let neg = self.eat('^');
        let mut items = Vec::new();
        let mut first = true;
        loop {
            let c = self.peek().unwrap_or_else(|| self.bad("unclosed class"));
            if c == ']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            self.i += 1;
            let lo = if c == '\\' {
                let e = self.peek().unwrap_or_else(|| self.bad("trailing backslash"));
                self.i += 1;
                match e {
                    'd' => {
                        items.push(Item::Digit(true));
                        continue;
                    }
                    'D' => {
                        items.push(Item::Digit(false));
                        continue;
                    }
                    's' => {
                        items.push(Item::Space(true));
                        continue;
                    }
                    'S' => {
                        items.push(Item::Space(false));
                        continue;
                    }
                    'w' => {
                        items.push(Item::Word(true));
                        continue;
                    }
                    'W' => {
                        items.push(Item::Word(false));
                        continue;
                    }
                    'n' => '\n',
                    't' => '\t',
                    e => e,
                }
            } else {
                c
            };
            if self.peek() == Some('-') && self.p.get(self.i + 1).is_some_and(|n| *n != ']') {
                self.i += 1;
                let mut hi = self.peek().unwrap_or_else(|| self.bad("unclosed range"));
                self.i += 1;
                if hi == '\\' {
                    hi = self.peek().unwrap_or_else(|| self.bad("trailing backslash"));
                    self.i += 1;
                }
                items.push(Item::Range(lo, hi));
            } else {
                items.push(Item::Char(lo));
            }
        }
        Node::Class(items, neg)
    }

    fn atom(&mut self) -> Node {
        let c = self.peek().unwrap_or_else(|| self.bad("unexpected end"));
        self.i += 1;
        match c {
            '.' => Node::Any,
            '^' => Node::Start,
            '$' => Node::End,
            '\\' => self.escape(),
            '[' => self.class(),
            '(' => {
                let kind = if self.eat('?') {
                    match self.peek() {
                        Some(':') => {
                            self.i += 1;
                            0
                        }
                        Some('=') => {
                            self.i += 1;
                            1
                        }
                        Some('!') => {
                            self.i += 1;
                            2
                        }
                        _ => self.bad("unsupported group"),
                    }
                } else {
                    3
                };
                let cap = (kind == 3).then(|| {
                    self.groups += 1;
                    self.groups
                });
                let alts = self.alts();
                if !self.eat(')') {
                    self.bad("unclosed group");
                }
                match kind {
                    1 => Node::Look(alts, false),
                    2 => Node::Look(alts, true),
                    _ => Node::Group(alts, cap),
                }
            }
            '*' | '+' | '?' => self.bad("nothing to repeat"),
            c => Node::Char(c),
        }
    }
}

type Caps = Vec<Option<(usize, usize)>>;

struct Matcher<'r> {
    re: &'r Regex,
    text: Vec<char>,
    steps: usize,
}

const MAX_STEPS: usize = 5_000_000;

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

impl Matcher<'_> {
    fn eq(&self, a: char, b: char) -> bool {
        a == b || (self.re.icase && a.to_lowercase().eq(b.to_lowercase()))
    }

    fn class_hit(&self, items: &[Item], c: char) -> bool {
        items.iter().any(|it| match it {
            Item::Char(x) => self.eq(*x, c),
            Item::Range(lo, hi) => {
                (*lo..=*hi).contains(&c)
                    || (self.re.icase
                        && (c.to_lowercase().any(|l| (*lo..=*hi).contains(&l))
                            || c.to_uppercase().any(|u| (*lo..=*hi).contains(&u))))
            }
            Item::Digit(yes) => c.is_ascii_digit() == *yes,
            Item::Space(yes) => c.is_whitespace() == *yes,
            Item::Word(yes) => is_word(c) == *yes,
        })
    }

    /// Whether one character-consuming node matches at `pos`.
    fn single(&self, node: &Node, pos: usize) -> bool {
        let Some(&c) = self.text.get(pos) else { return false };
        match node {
            Node::Char(x) => self.eq(*x, c),
            Node::Any => self.re.dotall || c != '\n',
            Node::Class(items, neg) => self.class_hit(items, c) != *neg,
            Node::Digit(yes) => c.is_ascii_digit() == *yes,
            Node::Space(yes) => c.is_whitespace() == *yes,
            Node::Word(yes) => is_word(c) == *yes,
            _ => false,
        }
    }

    fn alts(
        &mut self,
        alts: &[Vec<Node>],
        pos: usize,
        caps: &mut Caps,
        k: &mut dyn FnMut(&mut Self, usize, &mut Caps) -> bool,
    ) -> bool {
        for seq in alts {
            if self.seq(seq, pos, caps, k) {
                return true;
            }
        }
        false
    }

    fn seq(
        &mut self,
        seq: &[Node],
        pos: usize,
        caps: &mut Caps,
        k: &mut dyn FnMut(&mut Self, usize, &mut Caps) -> bool,
    ) -> bool {
        self.steps += 1;
        if self.steps > MAX_STEPS {
            return false;
        }
        let Some((node, rest)) = seq.split_first() else { return k(self, pos, caps) };
        match node {
            Node::Start => {
                let ok = pos == 0 || (self.re.multiline && self.text[pos - 1] == '\n');
                ok && self.seq(rest, pos, caps, k)
            }
            Node::End => {
                let n = self.text.len();
                let ok = pos == n
                    || (pos == n - 1 && self.text[pos] == '\n')
                    || (self.re.multiline && self.text[pos] == '\n');
                ok && self.seq(rest, pos, caps, k)
            }
            Node::Boundary => {
                let before = pos > 0 && is_word(self.text[pos - 1]);
                let after = pos < self.text.len() && is_word(self.text[pos]);
                before != after && self.seq(rest, pos, caps, k)
            }
            Node::Look(alts, neg) => {
                let mut probe = caps.clone();
                let hit = self.alts(alts, pos, &mut probe, &mut |_, _, _| true);
                if hit == *neg {
                    return false;
                }
                if hit {
                    *caps = probe;
                }
                self.seq(rest, pos, caps, k)
            }
            Node::Group(alts, cap) => {
                let saved = caps.clone();
                let cap = *cap;
                let ok = self.alts(alts, pos, caps, &mut |m: &mut Self, end, caps: &mut Caps| {
                    let before = cap.map(|i| caps[i]);
                    if let Some(i) = cap {
                        caps[i] = Some((pos, end));
                    }
                    if m.seq(rest, end, caps, k) {
                        return true;
                    }
                    if let (Some(i), Some(b)) = (cap, before) {
                        caps[i] = b;
                    }
                    false
                });
                if !ok {
                    *caps = saved;
                }
                ok
            }
            Node::Repeat(inner, min, max, greedy) => self.repeat(inner, *min, *max, *greedy, 0, pos, rest, caps, k),
            single => self.single(single, pos) && self.seq(rest, pos + 1, caps, k),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn repeat(
        &mut self,
        inner: &Node,
        min: usize,
        max: usize,
        greedy: bool,
        count: usize,
        pos: usize,
        rest: &[Node],
        caps: &mut Caps,
        k: &mut dyn FnMut(&mut Self, usize, &mut Caps) -> bool,
    ) -> bool {
        self.steps += 1;
        if self.steps > MAX_STEPS {
            return false;
        }
        // A simple node repeats in a loop, without recursion per character.
        if !matches!(inner, Node::Group(..)) {
            let mut n = 0;
            while n < max && self.single(inner, pos + n) {
                n += 1;
                self.steps += 1;
                if self.steps > MAX_STEPS {
                    return false;
                }
            }
            if n < min {
                return false;
            }
            if greedy {
                for take in (min..=n).rev() {
                    if self.seq(rest, pos + take, caps, k) {
                        return true;
                    }
                }
            } else {
                for take in min..=n {
                    if self.seq(rest, pos + take, caps, k) {
                        return true;
                    }
                }
            }
            return false;
        }
        let one_more =
            |m: &mut Self, caps: &mut Caps, k: &mut dyn FnMut(&mut Self, usize, &mut Caps) -> bool| -> bool {
                let node = std::slice::from_ref(inner);
                m.seq(node, pos, caps, &mut |m: &mut Self, end, caps: &mut Caps| {
                    // An empty iteration can't make progress: stop repeating.
                    if end == pos && count >= min {
                        return false;
                    }
                    m.repeat(inner, min, max, greedy, count + 1, end, rest, caps, k)
                })
            };
        if count < min {
            return one_more(self, caps, k);
        }
        if greedy {
            if count < max && one_more(self, caps, k) {
                return true;
            }
            self.seq(rest, pos, caps, k)
        } else {
            if self.seq(rest, pos, caps, k) {
                return true;
            }
            count < max && one_more(self, caps, k)
        }
    }
}

impl Regex {
    /// Compile `pattern` with Python's flag letters: "i", "m", "s".
    pub fn with_flags(pattern: &str, flags: &str) -> Regex {
        let mut p = Parser { p: pattern.chars().collect(), i: 0, groups: 0, src: pattern };
        let alts = p.alts();
        if p.i != p.p.len() {
            p.bad("unbalanced ')'");
        }
        Regex {
            alts,
            groups: p.groups,
            icase: flags.contains('i'),
            multiline: flags.contains('m'),
            dotall: flags.contains('s'),
        }
    }

    pub fn new(pattern: &str) -> Regex {
        Regex::with_flags(pattern, "")
    }

    fn at(&self, m: &mut Matcher, start: usize, anchored_end: bool) -> Option<Captures> {
        let mut caps: Caps = vec![None; self.groups + 1];
        let len = m.text.len();
        let mut end = None;
        let hit = m.alts(&self.alts, start, &mut caps, &mut |_, e, _| {
            if anchored_end && e != len {
                return false;
            }
            end = Some(e);
            true
        });
        if !hit {
            return None;
        }
        let end = end?;
        caps[0] = Some((start, end));
        let groups = caps.iter().map(|c| c.map(|(a, b)| m.text[a..b].iter().collect())).collect();
        Some(Captures { groups, start, end })
    }

    fn matcher<'r>(&'r self, text: &str) -> Matcher<'r> {
        Matcher { re: self, text: text.chars().collect(), steps: 0 }
    }

    /// The leftmost match anywhere (Python: `re.search`).
    pub fn search(&self, text: &str) -> Option<Captures> {
        let mut m = self.matcher(text);
        (0..=m.text.len()).find_map(|start| self.at(&mut m, start, false))
    }

    /// A match at the start (Python: `re.match`).
    pub fn match_start(&self, text: &str) -> Option<Captures> {
        self.at(&mut self.matcher(text), 0, false)
    }

    /// Whether the whole text matches (Python: `re.fullmatch`).
    pub fn fullmatch(&self, text: &str) -> Option<Captures> {
        self.at(&mut self.matcher(text), 0, true)
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.search(text).is_some()
    }

    /// Every non-overlapping match, left to right (Python: `re.finditer`).
    pub fn find_all(&self, text: &str) -> Vec<Captures> {
        let mut m = self.matcher(text);
        let mut out = Vec::new();
        let mut start = 0;
        while start <= m.text.len() {
            match self.at(&mut m, start, false) {
                Some(c) => {
                    start = if c.end == c.start { c.end + 1 } else { c.end };
                    out.push(c);
                }
                None => start += 1,
            }
        }
        out
    }

    /// Every match replaced by `with` (literal text; Python: `re.sub`).
    pub fn replace_all(&self, text: &str, with: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::new();
        let mut last = 0;
        for c in self.find_all(text) {
            out.extend(&chars[last..c.start]);
            out.push_str(with);
            last = c.end;
        }
        out.extend(&chars[last..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(p: &str, t: &str) -> Option<String> {
        Regex::new(p).search(t).map(|c| c.get(1).to_string())
    }

    #[test]
    fn version_patterns_from_the_catalog() {
        assert_eq!(s(r"v(\d+\.\d+\.\d+)", "v24.11.1\n").as_deref(), Some("24.11.1"));
        assert_eq!(s(r"go(\d+\.\d+(?:\.\d+)?)", "go1.24").as_deref(), Some("1.24"));
        assert_eq!(s(r"go(\d+\.\d+(?:\.\d+)?)", "go1.24.7").as_deref(), Some("1.24.7"));
        assert_eq!(
            s(r#"version "(\d+(?:\.\d+)*)"#, "openjdk version \"21.0.5\" 2024-10-15").as_deref(),
            Some("21.0.5")
        );
        assert_eq!(s(r"OpenSSH_(\d+\.\d+p\d+)", "OpenSSH_9.6p1 Ubuntu").as_deref(), Some("9.6p1"));
        assert_eq!(
            Regex::with_flags(r"^g(?:cc|\+\+)\S* \(.*\) (\d+\.\d+\.\d+)", "m")
                .search("x\ngcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0\n")
                .map(|c| c.get(1).to_string()),
            Some("13.3.0".into())
        );
        assert_eq!(
            s(r"Ver (\d+\.\d+\.\d+)(?![\d.]*-MariaDB)", "mysql  Ver 8.0.36 for Linux").as_deref(),
            Some("8.0.36")
        );
        assert_eq!(s(r"Ver (\d+\.\d+\.\d+)(?![\d.]*-MariaDB)", "mysql  Ver 15.1 Distrib 10.11.6-MariaDB"), None);
        assert_eq!(s(r"(\d+\.\d+\.\d+)-MariaDB", "Ver 15.1 Distrib 10.11.6-MariaDB, for").as_deref(), Some("10.11.6"));
        assert_eq!(
            s(r#""gitVersion":\s*"v(\d+\.\d+\.\d+)""#, "{\"gitVersion\":  \"v1.31.2\"}").as_deref(),
            Some("1.31.2")
        );
        assert_eq!(s(r"(\d{4}\.\d+\.\d+)", "openclaw 2026.10.3").as_deref(), Some("2026.10.3"));
        assert!(Regex::with_flags(r"^(\d+\.\d+\.\d+)$", "m").search("hello\n0.9.1\n").is_some());
        assert!(Regex::new(r"^(\d+\.\d+\.\d+)$").search("0.9.1 extra").is_none());
    }

    #[test]
    fn classes_alternation_quantifiers_flags() {
        let r = Regex::new(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?(?:(?:==|@)([^,;<>=!~\s]+))?");
        let c = r.match_start("git-mcp[cli]@1.0.0").unwrap();
        assert_eq!((c.get(1), c.get(2)), ("git-mcp", "1.0.0"));
        assert_eq!(r.match_start("x").unwrap().opt(2), None);
        assert!(Regex::new(r"python3\.\d+").fullmatch("python3.12").is_some());
        assert!(Regex::new(r"python3\.\d+").fullmatch("python3.12-config").is_none());
        assert!(Regex::new(r"[0-9a-f]{12,40}").fullmatch("76b7feab363d").is_some());
        assert!(Regex::new(r"[0-9a-f]{12,40}").fullmatch("76b7feab363").is_none());
        assert_eq!(
            Regex::with_flags("<tr>(.*?)</tr>", "s")
                .find_all("<tr>a\n</tr><tr>b</tr>")
                .iter()
                .map(|c| c.get(1).to_string())
                .collect::<Vec<_>>(),
            ["a\n", "b"]
        );
        assert_eq!(Regex::new(r"[-_.]+").replace_all("Foo__bar..Baz", "-"), "Foo-bar-Baz");
        assert_eq!(Regex::with_flags("abc", "i").search("xABCx").map(|c| c.start), Some(1));
        assert_eq!(Regex::new(r"\bcat\b").find_all("cat concat cat").len(), 2);
        assert_eq!(
            Regex::new(r"(a|ab)(c|bcd)(d*)").search("abcd").unwrap().groups,
            vec![Some("abcd".into()), Some("a".into()), Some("bcd".into()), Some("".into())]
        );
    }

    #[test]
    fn pathological_patterns_give_up_instead_of_hanging() {
        let text = "a".repeat(40) + "b";
        assert!(Regex::new(r"(a*)*c").search(&text).is_none());
    }
}
