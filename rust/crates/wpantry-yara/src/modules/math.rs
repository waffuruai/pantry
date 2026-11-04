//! YARA's `math` module: statistics over a range of the file or a string.

use super::{Module, window};
use crate::value::{FnCtx, StructType, Type, Value};
use std::sync::Arc;

pub struct Math(Arc<StructType>);

impl Math {
    pub fn new() -> Self {
        // MEAN_BYTES is a float (127.5) and constants are integers, so it's a field.
        let t = StructType::new()
            .float("MEAN_BYTES")
            .func("entropy", "ii", Type::Float, |c, a| over_range(c, a, entropy))
            .func("entropy", "s", Type::Float, |_, a| over_str(a, entropy))
            .func("mean", "ii", Type::Float, |c, a| over_range(c, a, mean))
            .func("mean", "s", Type::Float, |_, a| over_str(a, mean))
            .func("deviation", "iif", Type::Float, |c, a| {
                window(c.data, &a[0], &a[1]).map_or(Value::Undef, |d| deviation(d, a[2].as_float().unwrap_or(0.0)))
            })
            .func("deviation", "sf", Type::Float, |_, a| {
                a[0].as_bytes().map_or(Value::Undef, |d| deviation(d, a[1].as_float().unwrap_or(0.0)))
            })
            .func("serial_correlation", "ii", Type::Float, |c, a| over_range(c, a, serial_correlation))
            .func("serial_correlation", "s", Type::Float, |_, a| over_str(a, serial_correlation))
            .func("monte_carlo_pi", "ii", Type::Float, |c, a| over_range(c, a, monte_carlo_pi))
            .func("monte_carlo_pi", "s", Type::Float, |_, a| over_str(a, monte_carlo_pi))
            .func("in_range", "fff", Type::Int, |_, a| {
                let (x, lo, hi) = (a[0].as_float(), a[1].as_float(), a[2].as_float());
                match (x, lo, hi) {
                    (Some(x), Some(lo), Some(hi)) => Value::Int(i64::from(lo <= x && x <= hi)),
                    _ => Value::Undef,
                }
            })
            .func("max", "ii", Type::Int, |_, a| int2(a, i64::max))
            .func("min", "ii", Type::Int, |_, a| int2(a, i64::min))
            .func("abs", "i", Type::Int, |_, a| a[0].as_int().map_or(Value::Undef, |i| Value::Int(i.wrapping_abs())))
            .func("to_number", "i", Type::Int, |_, a| a[0].as_int().map_or(Value::Undef, Value::Int))
            .func("count", "iii", Type::Int, |c, a| byte_stat(c.data, a, false))
            .func("count", "i", Type::Int, |c, a| {
                byte_stat(c.data, &[a[0].clone(), Value::Int(0), Value::Int(c.data.len() as i64)], false)
            })
            .func("percentage", "iii", Type::Float, |c, a| byte_stat(c.data, a, true))
            .func("percentage", "i", Type::Float, |c, a| {
                byte_stat(c.data, &[a[0].clone(), Value::Int(0), Value::Int(c.data.len() as i64)], true)
            })
            .func("mode", "ii", Type::Int, |c, a| window(c.data, &a[0], &a[1]).map_or(Value::Undef, mode))
            .func("mode", "", Type::Int, |c, _| mode(c.data))
            .func("to_string", "i", Type::Str, |_, a| a[0].as_int().map_or(Value::Undef, |i| Value::str(i.to_string())))
            .func("to_string", "ii", Type::Str, |_, a| match (a[0].as_int(), a[1].as_int()) {
                (Some(i), Some(base)) => to_base(i, base),
                _ => Value::Undef,
            });
        Math(Arc::new(t))
    }
}

impl Default for Math {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Math {
    fn name(&self) -> &'static str {
        "math"
    }

    fn schema(&self) -> Arc<StructType> {
        self.0.clone()
    }

    fn parse(&self, _: &[u8]) -> Value {
        let mut v = self.0.value();
        v.set("MEAN_BYTES", Value::Float(127.5));
        v.build()
    }
}

fn over_range(c: &FnCtx, a: &[Value], f: fn(&[u8]) -> Value) -> Value {
    window(c.data, &a[0], &a[1]).map_or(Value::Undef, f)
}

fn over_str(a: &[Value], f: fn(&[u8]) -> Value) -> Value {
    a[0].as_bytes().map_or(Value::Undef, f)
}

fn int2(a: &[Value], f: fn(i64, i64) -> i64) -> Value {
    match (a[0].as_int(), a[1].as_int()) {
        (Some(x), Some(y)) => Value::Int(f(x, y)),
        _ => Value::Undef,
    }
}

fn histogram(d: &[u8]) -> [u64; 256] {
    let mut h = [0u64; 256];
    for b in d {
        h[*b as usize] += 1;
    }
    h
}

/// Shannon entropy in bits per byte, 0 to 8.
fn entropy(d: &[u8]) -> Value {
    if d.is_empty() {
        return Value::Float(0.0);
    }
    let n = d.len() as f64;
    let h = histogram(d);
    let e = h.iter().filter(|c| **c > 0).map(|c| {
        let p = *c as f64 / n;
        -p * p.log2()
    });
    Value::Float(e.sum())
}

fn mean(d: &[u8]) -> Value {
    if d.is_empty() {
        return Value::Float(0.0);
    }
    Value::Float(d.iter().map(|b| f64::from(*b)).sum::<f64>() / d.len() as f64)
}

/// Mean absolute deviation from `m`.
fn deviation(d: &[u8], m: f64) -> Value {
    if d.is_empty() {
        return Value::Float(0.0);
    }
    Value::Float(d.iter().map(|b| (f64::from(*b) - m).abs()).sum::<f64>() / d.len() as f64)
}

/// The serial correlation coefficient of consecutive bytes, as `ent` computes it.
fn serial_correlation(d: &[u8]) -> Value {
    let n = d.len() as f64;
    if d.len() < 2 {
        return Value::Float(0.0);
    }
    let (mut t1, mut t2, mut t3) = (0.0, 0.0, 0.0);
    for (i, b) in d.iter().enumerate() {
        let x = f64::from(*b);
        let next = f64::from(d[(i + 1) % d.len()]);
        t1 += x * next;
        t2 += x;
        t3 += x * x;
    }
    let denom = n * t3 - t2 * t2;
    Value::Float(if denom == 0.0 { -100_000.0 } else { (n * t1 - t2 * t2) / denom })
}

/// π estimated from the bytes as points in a square, as `ent` does; the
/// result is the relative error, like YARA's.
fn monte_carlo_pi(d: &[u8]) -> Value {
    const COORDS: usize = 6;
    let radius = (256f64.powi(3) - 1.0).powi(2);
    let (mut inside, mut total) = (0u64, 0u64);
    for chunk in d.chunks_exact(COORDS) {
        let (mut x, mut y) = (0f64, 0f64);
        for j in 0..3 {
            x = x * 256.0 + f64::from(chunk[j]);
            y = y * 256.0 + f64::from(chunk[j + 3]);
        }
        total += 1;
        if x * x + y * y <= radius {
            inside += 1;
        }
    }
    if total == 0 {
        return Value::Undef;
    }
    let pi = 4.0 * inside as f64 / total as f64;
    Value::Float(((pi - std::f64::consts::PI) / std::f64::consts::PI).abs())
}

fn byte_stat(data: &[u8], a: &[Value], percent: bool) -> Value {
    let Some(byte) = a[0].as_int().filter(|b| (0..=255).contains(b)) else { return Value::Undef };
    let Some(d) = window(data, &a[1], &a[2]) else { return Value::Undef };
    let count = d.iter().filter(|b| i64::from(**b) == byte).count();
    if percent {
        if d.is_empty() {
            return Value::Undef;
        }
        Value::Float(count as f64 / d.len() as f64)
    } else {
        Value::Int(count as i64)
    }
}

/// The commonest byte (the lowest, on a tie).
fn mode(d: &[u8]) -> Value {
    if d.is_empty() {
        return Value::Undef;
    }
    let h = histogram(d);
    let best = (0..256).max_by_key(|b| (h[*b], std::cmp::Reverse(*b))).expect("256 bytes");
    Value::Int(best as i64)
}

fn to_base(i: i64, base: i64) -> Value {
    let s = match base {
        8 => format!("{i:o}"),
        10 => i.to_string(),
        16 => format!("{i:x}"),
        _ => return Value::Undef,
    };
    Value::str(s)
}

#[cfg(test)]
mod tests {
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
        assert_eq!(
            float(call("deviation", "iif", b"\x00\x02", &[Value::Int(0), Value::Int(2), Value::Float(1.0)])),
            1.0
        );
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
}
