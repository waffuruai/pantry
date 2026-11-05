use crate::{Compiler, ScanOptions, Syntax};

fn holds(src: &str) -> bool {
    let mut c = Compiler::new();
    assert_eq!(c.add_source("t", src, Syntax::Relaxed), 1, "{src}");
    !c.build().scan(b"", &ScanOptions::default()).matches.is_empty()
}

#[test]
fn console_string_and_time() {
    assert!(holds(
        r#"import "console" rule r { condition: console.log("x") and console.log("n: ", 1) and console.hex(255) }"#
    ));
    assert!(holds(
        r#"import "string" rule r { condition: string.to_int("123") == 123 and string.to_int("-0x10") == -16 }"#
    ));
    assert!(holds(
        r#"import "string" rule r { condition: string.to_int("017") == 15 and string.to_int("ff", 16) == 255 }"#
    ));
    assert!(holds(
        r#"import "string" rule r { condition: string.to_int("0x1f", 16) == 31 and string.to_int("+7") == 7 }"#
    ));
    assert!(holds(
        r#"import "string" rule r { condition: not defined string.to_int("12x") and not defined string.to_int("1", 99) }"#
    ));
    assert!(holds(r#"import "string" rule r { condition: string.length("abc") == 3 }"#));
    assert!(holds(r#"import "time" rule r { condition: time.now() > 1700000000 }"#));
}
