use super::*;

#[test]
fn readers_stay_in_bounds() {
    let d = [1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(u16le(&d, 0), Some(0x0201));
    assert_eq!(u32be(&d, 0), Some(0x01020304));
    assert_eq!(u64le(&d, 0), Some(0x0807060504030201));
    assert_eq!(u64be(&d, 0), Some(0x0102030405060708));
    assert_eq!(u16be(&d, 6), Some(0x0708));
    assert_eq!(u32le(&d, 6), None);
    assert_eq!(u16le(&d, usize::MAX), None);
    assert_eq!(cstr(b"ab\0cd", 0, 10), Some(&b"ab"[..]));
    assert_eq!(cstr(b"abcd", 1, 2), Some(&b"bc"[..]));
    assert_eq!(cstr(b"ab", 5, 2), None);
    assert_eq!(hex(&[0, 255]), "00ff");
    assert_eq!(window(b"abcd", &Value::Int(1), &Value::Int(2)), Some(&b"bc"[..]));
    assert_eq!(window(b"abcd", &Value::Int(3), &Value::Int(2)), None);
    assert_eq!(window(b"abcd", &Value::Int(-1), &Value::Int(2)), None);
    assert_eq!(window(b"abcd", &Value::Undef, &Value::Int(2)), None);
    assert!(entry_point(b"plain text").is_undef());
    assert_eq!(
        builtin().iter().map(|m| m.name()).collect::<Vec<_>>(),
        ["math", "hash", "pe", "elf", "dotnet", "console", "string", "time"]
    );
}
