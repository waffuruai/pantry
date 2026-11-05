use super::*;

#[test]
fn dumps_like_python() {
    let v = obj([
        ("schema", J::Int(1)),
        ("checked", J::Obj(vec![])),
        ("list", J::Arr(vec![J::from("\u{e9}\"x"), J::Bool(true), J::Null, J::Float(-1.5), J::Float(0.0)])),
    ]);
    assert_eq!(v.dumps(), r#"{"schema": 1, "checked": {}, "list": ["\u00e9\"x", true, null, -1.5, 0.0]}"#);
    assert_eq!(
        v.dumps_indent(1),
        "{\n \"schema\": 1,\n \"checked\": {},\n \"list\": [\n  \"\\u00e9\\\"x\",\n  true,\n  null,\n  -1.5,\n  0.0\n ]\n}"
    );
    assert_eq!(J::from("\u{1f600}\u{7f}").dumps(), r#""\ud83d\ude00\u007f""#);
}

#[test]
fn parse_caps_size() {
    assert!(parse(b"[1, 2]", 100).is_ok());
    assert!(matches!(parse(b"[1, 2]", 3), Err(Error::Invalid(_))));
    assert!(matches!(parse(b"{", 100), Err(Error::Invalid(_))));
    let deep = "[".repeat(1000) + &"]".repeat(1000);
    assert!(matches!(parse(deep.as_bytes(), 1 << 20), Err(Error::Invalid(_))));
}

#[test]
fn escapes_and_special_floats_like_python() {
    assert_eq!(J::from("a\\b\n\r\t\u{8}\u{c}".to_string()).dumps(), r#""a\\b\n\r\t\b\f""#);
    assert_eq!(J::Arr(vec![]).dumps(), "[]");
    assert_eq!(J::Arr(vec![J::from(true), J::from(7i64)]).dumps_indent(2), "[\n  true,\n  7\n]");
    assert_eq!(J::Float(f64::NAN).dumps(), "NaN");
    assert_eq!(J::Float(f64::INFINITY).dumps(), "Infinity");
    assert_eq!(J::Float(f64::NEG_INFINITY).dumps(), "-Infinity");
    assert_eq!(J::Float(1e16).dumps(), "10000000000000000");
    assert_eq!(J::Float(2.5).dumps(), "2.5");
    assert_eq!(strs_at(&serde_json::json!({"a": ["x", 1, "y"]}), "a"), ["x", "y"]);
    assert_eq!(str_at(&serde_json::json!({"a": 1}), "a"), "");
}
