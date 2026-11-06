use super::*;

#[test]
fn option_specs_read_as_help_writes_them() {
    let o = Opt::new("-o, --out <file>", "write it there");
    assert_eq!(
        (o.short, o.long.as_deref(), o.name(), o.flags()),
        (Some('o'), Some("out"), "out".into(), "-o, --out <file>".into())
    );
    assert_eq!(Opt::new("--licenses [file]", "").flags(), "--licenses [file]");
    assert_eq!(Opt::new("--path <dir...>", "").takes, Takes::Value { name: "dir".into(), required: true, many: true });
    assert_eq!(Opt::new("--json", "").takes, Takes::Nothing);
    assert_eq!(Opt::new("-q", "").name(), "q");
    let a = Arg::new("<sample...>", "");
    assert_eq!((a.name.as_str(), a.required, a.many, a.spec()), ("sample", true, true, "<sample...>".into()));
    assert_eq!(Arg::new("[part]", "").spec(), "[part]");
}

#[test]
#[should_panic(expected = "bad option spec")]
fn a_bad_option_spec_is_the_programs_bug() {
    let _ = Opt::new("out <file>", "");
}

#[test]
#[should_panic(expected = "declared twice")]
fn an_option_declared_twice_is_the_programs_bug() {
    let _ = Command::new("x").option("--json", "").option("--json", "");
}

#[test]
#[should_panic(expected = "can't follow an optional one")]
fn a_required_argument_after_an_optional_one_is_the_programs_bug() {
    let _ = Command::new("x").argument("[a]", "").argument("<b>", "");
}

#[test]
#[should_panic(expected = "nothing can follow the variadic")]
fn nothing_follows_a_variadic_argument() {
    let _ = Command::new("x").argument("[a...]", "").argument("[b]", "");
}

#[test]
fn exits_say_where_they_go() {
    assert_eq!(Exit::Help("h".into()).code(), 0);
    assert_eq!(Exit::Version("v".into()).code(), 0);
    let e = Exit::Error("e".into());
    assert_eq!((e.code(), e.text()), (2, "e"));
}
