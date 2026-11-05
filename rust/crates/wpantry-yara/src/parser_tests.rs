use super::*;

fn one(src: &str) -> Rule {
    let mut f = parse(src, Syntax::Strict).unwrap();
    assert_eq!(f.rules.len(), 1);
    f.rules.pop().unwrap()
}

fn cond(c: &str) -> Expr {
    one(&format!("rule r {{ strings: $a = \"x\" $b = \"y\" condition: {c} }}")).condition
}

#[test]
fn rule_header_meta_and_tags() {
    let f = parse(
        r#"import "pe" import "math"
            private global rule r : t1 t2 { meta: a = "x" b = -3 c = true d = false e = 1.5 condition: true }"#,
        Syntax::Strict,
    )
    .unwrap();
    assert_eq!(f.imports, ["pe", "math"]);
    let r = &f.rules[0];
    assert!(r.private && r.global);
    assert_eq!(r.tags, ["t1", "t2"]);
    assert_eq!(r.meta[0], ("a".into(), Meta::Str(b"x".to_vec())));
    assert_eq!(r.meta[1].1, Meta::Int(-3));
    assert_eq!(r.meta[2].1, Meta::Bool(true));
    assert_eq!(r.meta[3].1, Meta::Bool(false));
    assert_eq!(r.meta[4].1, Meta::Str(b"1.5".to_vec()));
}

#[test]
fn strings_and_modifiers() {
    let r = one(r#"rule r { strings:
                $a = "abc" nocase wide ascii fullword private
                $b = "abc" xor(1-3)
                $c = "abc" base64 base64wide("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                $d = { 4D 5A } private
                $e = /a+b/i wide
                $ = "anon"
                $ = "anon2"
              condition: any of them }"#);
    assert_eq!(r.strings.len(), 7);
    let m = &r.strings[0].mods;
    assert!(m.nocase && m.wide && m.ascii && m.fullword && m.private);
    assert_eq!(r.strings[1].mods.xor, Some((1, 3)));
    assert_eq!(r.strings[2].mods.base64.as_deref(), Some(BASE64_STANDARD));
    assert!(r.strings[2].mods.base64wide.is_some());
    assert!(matches!(r.strings[3].kind, StringKind::Hex(_)));
    assert!(matches!(r.strings[4].kind, StringKind::Regex(_)));
    assert!(r.strings[5].id.starts_with('\0') && r.strings[5].id != r.strings[6].id);
    assert_eq!(one(r#"rule r { strings: $a = "x" xor condition: $a }"#).strings[0].mods.xor, Some((0, 255)));
    assert_eq!(one(r#"rule r { strings: $a = "x" xor(7) condition: $a }"#).strings[0].mods.xor, Some((7, 7)));
}

#[test]
fn string_errors() {
    for bad in [
        r#"rule r { strings: $a = "x" $a = "y" condition: $a }"#,
        r#"rule r { strings: $a = { 4D } nocase condition: $a }"#,
        r#"rule r { strings: $a = /x/ xor condition: $a }"#,
        r#"rule r { strings: $a = "x" xor nocase condition: $a }"#,
        r#"rule r { strings: $a = "x" base64 nocase condition: $a }"#,
        r#"rule r { strings: $a = "x" xor(3-1) condition: $a }"#,
        r#"rule r { strings: $a = "x" xor(300) condition: $a }"#,
        r#"rule r { strings: $a = "x" base64("short") condition: $a }"#,
        r#"rule r { strings: $a = "" condition: $a }"#,
        r#"rule r { strings: $a* = "x" condition: $a }"#,
        r#"rule r { strings: $a = 3 condition: $a }"#,
        r#"private private rule r { condition: true }"#,
        r#"rule and { condition: true }"#,
        r#"include "x.yar""#,
        r#"import pe"#,
        r#"rule r { meta: a = b condition: true }"#,
        r#"rule r { condition: true"#,
    ] {
        assert!(parse(bad, Syntax::Strict).is_err(), "{bad}");
    }
    // Relaxed mode allows a repeated modifier, as classic YARA does.
    assert!(parse("private private rule r { condition: true }", Syntax::Relaxed).is_ok());
}

#[test]
fn precedence() {
    // not binds looser than ==, and looser than or? no: or < and < not < ==.
    let Expr::Binary(BinOp::Or, a, b) = cond("true or false and $a") else { panic!() };
    assert!(matches!(*a, Expr::Bool(true)));
    assert!(matches!(*b, Expr::Binary(BinOp::And, ..)));
    let Expr::Unary(UnOp::Not, inner) = cond("not 1 == 2") else { panic!() };
    assert!(matches!(*inner, Expr::Binary(BinOp::Eq, ..)));
    let Expr::Binary(BinOp::Eq, l, _) = cond("1 + 2 * 3 == 7") else { panic!() };
    let Expr::Binary(BinOp::Add, _, r) = *l else { panic!() };
    assert!(matches!(*r, Expr::Binary(BinOp::Mul, ..)));
    assert!(matches!(cond("-1 < ~2"), Expr::Binary(BinOp::Lt, ..)));
    assert!(matches!(cond("1 | 2 ^ 3 & 4 << 5 > 0"), Expr::Binary(BinOp::Gt, ..)));
    assert!(matches!(cond("defined 1"), Expr::Unary(UnOp::Defined, _)));
}

#[test]
fn string_references() {
    assert!(matches!(cond("$a at 10 + 2"), Expr::StrMatch { anchor: Some(Anchor::At(_)), .. }));
    assert!(matches!(cond("$a in (0..100)"), Expr::StrMatch { anchor: Some(Anchor::In(..)), .. }));
    assert!(matches!(cond("#a in (0..filesize) > 2"), Expr::Binary(BinOp::Gt, ..)));
    assert!(matches!(cond("@a[2] == 5"), Expr::Binary(BinOp::Eq, ..)));
    assert!(matches!(cond("!a == 5"), Expr::Binary(BinOp::Eq, ..)));
    assert!(matches!(cond("@a"), Expr::StrOffset { index: None, .. }));
    assert!(parse("rule r { condition: $a* }", Syntax::Strict).is_err());
}

#[test]
fn quantifiers() {
    assert!(matches!(cond("all of them"), Expr::Of { quant: Quant::All, items: OfItems::Strings(StrSet::Them), .. }));
    assert!(matches!(
        cond("any of ($a*, $b)"),
        Expr::Of { quant: Quant::Any, items: OfItems::Strings(StrSet::Ids(_)), .. }
    ));
    assert!(matches!(cond("2 of them"), Expr::Of { quant: Quant::Count(_), .. }));
    assert!(matches!(cond("50% of them"), Expr::Of { quant: Quant::Percent(_), .. }));
    assert!(matches!(cond("none of them in (0..10)"), Expr::Of { anchor: Some(Anchor::In(..)), .. }));
    assert!(matches!(cond("any of them at 0"), Expr::Of { anchor: Some(Anchor::At(_)), .. }));
    let Expr::Of { items: OfItems::Rules(rules), .. } = cond("any of (r1, r2*)") else { panic!() };
    assert_eq!(rules, ["r1", "r2*"]);
    assert!(matches!(cond("1 of (true, $a, 1 > 2)"), Expr::Of { items: OfItems::Exprs(_), .. }));
    assert!(matches!(cond("10 % 3 == 1"), Expr::Binary(BinOp::Eq, ..)));
}

#[test]
fn loops_and_with() {
    assert!(matches!(cond("for any of ($a*) : ($ at 0)"), Expr::ForOf { .. }));
    assert!(matches!(cond("for all of them : (# > 1)"), Expr::ForOf { .. }));
    assert!(matches!(cond("for 2 i in (1..#a) : (@a[i] > 0)"), Expr::ForIn { iter: Iterable::Range(..), .. }));
    assert!(matches!(
        cond("for 50% i in (1, 2, 3) : (i > 0)"),
        Expr::ForIn { quant: Quant::Percent(_), iter: Iterable::List(_), .. }
    ));
    let Expr::ForIn { vars, iter: Iterable::Expr(_), .. } = cond("for any k, v in pe.version_info : (k == \"x\")")
    else {
        panic!()
    };
    assert_eq!(vars, ["k", "v"]);
    assert!(matches!(cond("with a = 1, b = 2 : (a < b)"), Expr::With { .. }));
    assert!(matches!(cond("pe.imports(\"k\", \"f\")"), Expr::Call(..)));
    assert!(matches!(cond("pe.sections[0].name == \".text\""), Expr::Binary(BinOp::Eq, ..)));
    assert!(matches!(cond("pe.number_of_sections matches /x/"), Expr::Binary(BinOp::Matches, ..)));
}

#[test]
fn recovery_skips_a_bad_rule() {
    let src = r#"rule good1 { condition: true }
            rule bad { strings: $a = "x" condition: $a and }
            rule good2 { strings: $h = { 4D } condition: $h }
            rule ` { }
            rule good3 { condition: false }"#;
    let (file, errors) = parse_recovering(src, Syntax::Strict);
    assert_eq!(file.rules.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["good1", "good2", "good3"]);
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].0, "bad");
    assert!(parse(src, Syntax::Strict).is_err());
}

#[test]
fn condition_errors() {
    for bad in
        ["(", "1 +", "for any i in x", "for any of $a : (true)", "with a 1 : (a)", "of them", "$a at", "pe.", "x[1"]
    {
        let src = format!("rule r {{ strings: $a = \"x\" condition: {bad} }}");
        assert!(parse(&src, Syntax::Strict).is_err(), "{bad}");
    }
}
