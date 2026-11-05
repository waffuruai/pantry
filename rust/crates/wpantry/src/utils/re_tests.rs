use super::*;

fn s(p: &str, t: &str) -> Option<String> {
    Regex::new(p).search(t).map(|c| c.get(1).to_string())
}

#[test]
fn version_patterns_from_the_catalog() {
    assert_eq!(s(r"v(\d+\.\d+\.\d+)", "v24.11.1\n").as_deref(), Some("24.11.1"));
    assert_eq!(s(r"go(\d+\.\d+(?:\.\d+)?)", "go1.24").as_deref(), Some("1.24"));
    assert_eq!(s(r"go(\d+\.\d+(?:\.\d+)?)", "go1.24.7").as_deref(), Some("1.24.7"));
    assert_eq!(s(r#"version "(\d+(?:\.\d+)*)"#, "openjdk version \"21.0.5\" 2024-10-15").as_deref(), Some("21.0.5"));
    assert_eq!(s(r"OpenSSH_(\d+\.\d+p\d+)", "OpenSSH_9.6p1 Ubuntu").as_deref(), Some("9.6p1"));
    assert_eq!(
        Regex::with_flags(r"^g(?:cc|\+\+)\S* \(.*\) (\d+\.\d+\.\d+)", "m")
            .search("x\ngcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0\n")
            .map(|c| c.get(1).to_string()),
        Some("13.3.0".into())
    );
    assert_eq!(s(r"Ver (\d+\.\d+\.\d+)(?![\d.]*-MariaDB)", "mysql  Ver 8.0.36 for Linux").as_deref(), Some("8.0.36"));
    assert_eq!(s(r"Ver (\d+\.\d+\.\d+)(?![\d.]*-MariaDB)", "mysql  Ver 15.1 Distrib 10.11.6-MariaDB"), None);
    assert_eq!(s(r"(\d+\.\d+\.\d+)-MariaDB", "Ver 15.1 Distrib 10.11.6-MariaDB, for").as_deref(), Some("10.11.6"));
    assert_eq!(s(r#""gitVersion":\s*"v(\d+\.\d+\.\d+)""#, "{\"gitVersion\":  \"v1.31.2\"}").as_deref(), Some("1.31.2"));
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
    // The step budget is also spent by one long run of a simple node, and
    // by the repeat that follows it.
    let long = "a".repeat(MAX_STEPS);
    assert!(Regex::new("a*").match_start(&long).is_none());
    assert!(Regex::new("a*b*").match_start(&long[..MAX_STEPS - 3]).is_none());
}

#[test]
fn escapes_classes_and_lookahead() {
    assert!(Regex::new(r"\D\S\W").fullmatch("1_ ").is_none());
    assert!(Regex::new(r"\D\S\W").fullmatch("x-!").is_some());
    assert!(Regex::new(r"\w+").fullmatch("héllo_1").is_some());
    assert!(Regex::new(r"\n\t\r").fullmatch("\n\t\r").is_some());
    assert!(Regex::new(r"[\d\D]").is_match("x") && Regex::new(r"[\s\S]").is_match("x"));
    assert!(Regex::new(r"[\w]+").fullmatch("ab_1").is_some() && Regex::new(r"[\W]").fullmatch("-").is_some());
    assert!(Regex::new(r"[\t\n]").fullmatch("\t").is_some());
    assert!(Regex::new(r"[\x-\z]").fullmatch("y").is_some(), "an escaped range end");
    assert!(Regex::new(r"[a-]").fullmatch("-").is_some(), "a trailing dash is literal");
    assert!(Regex::with_flags("[a-c]", "i").fullmatch("B").is_some(), "ranges ignore case too");
    assert!(Regex::with_flags("[A-C]", "i").fullmatch("b").is_some());
    assert_eq!(Regex::new(r"a(?=b)").search("ab").map(|c| c.end), Some(1));
    assert!(Regex::new(r"a(?=b)").search("ac").is_none());
    assert!(Regex::new(r"a(?!b)").search("ab").is_none());
    assert_eq!(Regex::new(r"(?=(a))a").search("a").unwrap().get(1), "a", "a lookahead's groups are kept");
    assert!(Regex::new("abc").is_match("xabcx") && !Regex::new("abd").is_match("xabcx"));
}

#[test]
fn braces_and_group_repeats() {
    assert!(Regex::new("a{2}").fullmatch("aa").is_some() && Regex::new("a{2}").fullmatch("aaa").is_none());
    assert!(Regex::new("a{2,}").fullmatch("aaaa").is_some());
    assert!(Regex::new("a{,2}").fullmatch("aa").is_none(), "no lower bound: a literal brace");
    assert!(Regex::new("a{").fullmatch("a{").is_some(), "a lone brace is literal");
    assert!(Regex::new("a{2").fullmatch("a{2").is_some(), "an unclosed brace is literal");
    assert!(Regex::new("a{2,3}?").match_start("aaa").map(|c| c.end) == Some(2), "lazy");
    assert_eq!(Regex::new("(ab){2}").fullmatch("abab").unwrap().get(1), "ab");
    assert!(Regex::new("(ab){2}").fullmatch("ab").is_none());
    assert_eq!(Regex::new("(ab)*?c").search("ababc").unwrap().get(1), "ab", "a lazy group repeat");
    assert_eq!(Regex::new("(ab)*?").match_start("abab").unwrap().end, 0);
    assert_eq!(Regex::new("(a|b)+?b").search("aab").unwrap().get(0), "aab");
    assert_eq!(Regex::new("(x?)*y").search("xxy").unwrap().get(0), "xxy", "an empty iteration stops");
    assert_eq!(Regex::new("").find_all("ab").len(), 3, "empty matches advance");
}

#[test]
fn malformed_patterns_are_bugs() {
    for bad in [r"a\", r"\q", "[a", "[a-", r"[a-\", "(a", "(?Pa)", "a)", "*a", "^*", "$+", r"\b?", "(?=a)*", "+", "a**"]
    {
        let got = std::panic::catch_unwind(|| Regex::new(bad));
        assert!(got.is_err(), "{bad:?} should not compile");
    }
}
