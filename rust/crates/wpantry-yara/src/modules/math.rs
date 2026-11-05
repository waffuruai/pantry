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
#[path = "math_tests.rs"]
mod tests;
