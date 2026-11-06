use super::*;
use crate::value::FieldKind;

fn call(name: &str, args: &str, data: &[u8], a: &[Value]) -> Value {
    let m = Math::new();
    let schema = m.schema();
    let Some(FieldKind::Func(overloads)) = schema.lookup(name) else { panic!("{name}") };
    let f = overloads.iter().find(|f| f.args == args).unwrap();
    let this = m.parse(data);
    (f.f)(&FnCtx { data, this: &this }, a)
}

fn float(v: Value) -> f64 {
    v.as_float().unwrap()
}

#[test]
fn entropy_mean_and_deviation() {
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(float(call("entropy", "ii", &all, &[Value::Int(0), Value::Int(256)])), 8.0);
    assert_eq!(float(call("entropy", "s", b"", &[Value::str("aaaa")])), 0.0);
    assert!(call("entropy", "ii", &all, &[Value::Int(250), Value::Int(10)]).is_undef());
    assert_eq!(float(call("mean", "s", b"", &[Value::str([0, 2])])), 1.0);
    assert_eq!(float(call("mean", "ii", b"\x04", &[Value::Int(0), Value::Int(1)])), 4.0);
    assert_eq!(float(call("deviation", "sf", b"", &[Value::str([0, 2]), Value::Float(1.0)])), 1.0);
    assert_eq!(float(call("deviation", "iif", b"\x00\x02", &[Value::Int(0), Value::Int(2), Value::Float(1.0)])), 1.0);
    assert_eq!(float(entropy(b"")), 0.0);
    assert_eq!(float(mean(b"")), 0.0);
    assert_eq!(float(deviation(b"", 1.0)), 0.0);
}

#[test]
fn correlation_and_pi() {
    assert_eq!(float(call("serial_correlation", "s", b"", &[Value::str("aaaa")])), -100_000.0);
    assert_eq!(float(serial_correlation(b"a")), 0.0);
    let seq: Vec<u8> = (0..=255).collect();
    assert!(float(call("serial_correlation", "ii", &seq, &[Value::Int(0), Value::Int(256)])) > 0.9);
    assert!(call("monte_carlo_pi", "s", b"", &[Value::str("abc")]).is_undef());
    let pseudo: Vec<u8> = (0..60000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    assert!(float(call("monte_carlo_pi", "ii", &pseudo, &[Value::Int(0), Value::Int(60000)])) < 0.1);
}

#[test]
fn integers_counts_and_strings() {
    assert_eq!(
        call("in_range", "fff", b"", &[Value::Float(2.0), Value::Float(1.0), Value::Float(3.0)]).as_int(),
        Some(1)
    );
    assert!(call("in_range", "fff", b"", &[Value::Undef, Value::Float(1.0), Value::Float(3.0)]).is_undef());
    assert_eq!(call("max", "ii", b"", &[Value::Int(2), Value::Int(5)]).as_int(), Some(5));
    assert_eq!(call("min", "ii", b"", &[Value::Int(2), Value::Int(5)]).as_int(), Some(2));
    assert!(call("min", "ii", b"", &[Value::Undef, Value::Int(5)]).is_undef());
    assert_eq!(call("abs", "i", b"", &[Value::Int(-3)]).as_int(), Some(3));
    assert_eq!(call("to_number", "i", b"", &[Value::Bool(true)]).as_int(), Some(1));
    assert_eq!(call("count", "i", b"aab", &[Value::Int(97)]).as_int(), Some(2));
    assert_eq!(call("count", "iii", b"aab", &[Value::Int(97), Value::Int(1), Value::Int(2)]).as_int(), Some(1));
    assert!(call("count", "i", b"aab", &[Value::Int(300)]).is_undef());
    assert_eq!(float(call("percentage", "i", b"aab", &[Value::Int(98)])), 1.0 / 3.0);
    assert!(call("percentage", "iii", b"aab", &[Value::Int(98), Value::Int(0), Value::Int(0)]).is_undef());
    assert_eq!(call("mode", "", b"abb", &[]).as_int(), Some(98));
    assert_eq!(call("mode", "ii", b"abb", &[Value::Int(0), Value::Int(1)]).as_int(), Some(97));
    assert!(mode(b"").is_undef());
    assert_eq!(call("to_string", "i", b"", &[Value::Int(42)]).as_bytes(), Some(&b"42"[..]));
    assert_eq!(call("to_string", "ii", b"", &[Value::Int(255), Value::Int(16)]).as_bytes(), Some(&b"ff"[..]));
    assert_eq!(call("to_string", "ii", b"", &[Value::Int(8), Value::Int(8)]).as_bytes(), Some(&b"10"[..]));
    assert_eq!(call("to_string", "ii", b"", &[Value::Int(8), Value::Int(10)]).as_bytes(), Some(&b"8"[..]));
    assert!(call("to_string", "ii", b"", &[Value::Int(8), Value::Int(3)]).is_undef());
    assert_eq!(Math::default().parse(b"").field(0).as_float(), Some(127.5));
}
