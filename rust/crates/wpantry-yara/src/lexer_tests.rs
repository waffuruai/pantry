use super::*;

fn all(src: &str) -> Vec<Tok> {
    let mut lx = Lexer::new(src);
    let mut out = Vec::new();
    loop {
        let t = lx.next().unwrap();
        if t == Tok::Eof {
            return out;
        }
        out.push(t);
    }
}

#[test]
fn lexes_operators_numbers_and_identifiers() {
    assert_eq!(
        all("rule a { condition: 0x10 << 2 >= 1KB and 2MB != 0o17 and 1.5 }"),
        vec![
            Tok::Ident("rule".into()),
            Tok::Ident("a".into()),
            Tok::Punct("{"),
            Tok::Ident("condition".into()),
            Tok::Punct(":"),
            Tok::Int(16),
            Tok::Punct("<<"),
            Tok::Int(2),
            Tok::Punct(">="),
            Tok::Int(1024),
            Tok::Ident("and".into()),
            Tok::Int(2 * 1024 * 1024),
            Tok::Punct("!="),
            Tok::Int(15),
            Tok::Ident("and".into()),
            Tok::Float(1.5),
            Tok::Punct("}"),
        ]
    );
}

#[test]
fn lexes_string_references_and_ranges() {
    assert_eq!(
        all("$a* # @b[1] !c $ (0..filesize)"),
        vec![
            Tok::StrId("a*".into()),
            Tok::StrCount(String::new()),
            Tok::StrOffset("b".into()),
            Tok::Punct("["),
            Tok::Int(1),
            Tok::Punct("]"),
            Tok::StrLength("c".into()),
            Tok::StrId(String::new()),
            Tok::Punct("("),
            Tok::Int(0),
            Tok::Punct(".."),
            Tok::Ident("filesize".into()),
            Tok::Punct(")"),
        ]
    );
}

#[test]
fn text_escapes_and_errors() {
    assert_eq!(all(r#""a\x41\n\"\\""#), vec![Tok::Text(b"aA\n\"\\".to_vec())]);
    assert!(Lexer::new(r#""\q""#).next().is_err());
    assert!(Lexer::new("\"open").next().is_err());
    assert!(Lexer::new("\"a\nb\"").next().is_err());
    assert!(Lexer::new(r#""\xZZ""#).next().is_err());
}

#[test]
fn regexes_keep_escapes_and_take_flags() {
    assert_eq!(
        all(r"/a\/b+/is /x/"),
        vec![
            Tok::Regex { src: br"a\/b+".to_vec(), nocase: true, dotall: true },
            Tok::Regex { src: b"x".to_vec(), nocase: false, dotall: false },
        ]
    );
    assert!(Lexer::new("/open").next().is_err());
}

#[test]
fn comments_count_lines() {
    let mut lx = Lexer::new("// one\n/* two\nthree */ x");
    assert_eq!(lx.line(), 3);
    assert_eq!(lx.next().unwrap(), Tok::Ident("x".into()));
    assert!(Lexer::new("/* open").next().is_err());
}

#[test]
fn hex_bodies_are_raw_until_the_brace() {
    let mut lx = Lexer::new("{ 4D 5A // c\n ?? /* x */ [2-4] } rest");
    assert_eq!(lx.next().unwrap(), Tok::Punct("{"));
    let (body, line) = lx.hex_body().unwrap();
    assert_eq!(body.split_whitespace().collect::<Vec<_>>(), ["4D", "5A", "??", "[2-4]"]);
    assert_eq!(line, 1);
    assert_eq!(lx.next().unwrap(), Tok::Ident("rest".into()));
    let mut open = Lexer::new("{ 4D");
    open.next().unwrap();
    assert!(open.hex_body().is_err());
}

#[test]
fn unexpected_characters_are_errors() {
    assert!(Lexer::new("`").next().is_err());
    assert!(Lexer::new("0xZZ").next().is_err());
}
