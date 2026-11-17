use super::*;
use crate::value::FieldKind;

#[test]
fn known_digests() {
    assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hex(&md5(b"The quick brown fox jumps over the lazy dog")), "9e107d9d372bb6826bd81d3542a419d6");
    assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let long = vec![b'a'; 1000];
    assert_eq!(hex(&sha256(&long)), "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(checksum32(b"\x01\x02"), 3);
}

#[test]
fn module_functions() {
    let m = Hash::default();
    assert_eq!(m.name(), "hash");
    let schema = m.schema();
    let this = m.parse(b"");
    let call = |name: &str, args: &str, data: &[u8], a: &[Value]| {
        let Some(FieldKind::Func(overloads)) = schema.lookup(name) else { panic!() };
        let f = overloads.iter().find(|f| f.args == args).unwrap();
        (f.f)(&FnCtx { data, this: &this }, a)
    };
    assert_eq!(
        call("md5", "ii", b"xabc", &[Value::Int(1), Value::Int(3)]).as_bytes(),
        Some(&b"900150983cd24fb0d6963f7d28e17f72"[..])
    );
    assert_eq!(
        call("sha1", "s", b"", &[Value::str("abc")]).as_bytes(),
        Some(&b"a9993e364706816aba3e25717850c26c9cd0d89d"[..])
    );
    assert!(call("sha256", "ii", b"ab", &[Value::Int(1), Value::Int(3)]).is_undef());
    assert!(call("md5", "s", b"", &[Value::Undef]).is_undef());
    assert_eq!(call("crc32", "s", b"", &[Value::str("123456789")]).as_int(), Some(0xCBF4_3926));
    assert_eq!(call("checksum32", "ii", b"\x01\x02", &[Value::Int(0), Value::Int(2)]).as_int(), Some(3));
    for (name, args) in [("sha1", "ii"), ("sha256", "s"), ("crc32", "ii"), ("checksum32", "s"), ("md5", "s")] {
        let a = if args == "ii" { vec![Value::Int(0), Value::Int(0)] } else { vec![Value::str("")] };
        assert!(!call(name, args, b"", &a).is_undef(), "{name}");
    }
}
