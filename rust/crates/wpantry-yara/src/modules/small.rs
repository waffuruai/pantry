//! The small YARA modules: `console` (logging, always true), `string`
//! (`to_int`, `length`) and `time` (`now`).

use super::Module;
use crate::value::{StructType, Type, Value};
use std::sync::Arc;

/// `console.log(…)` and `console.hex(…)`: YARA prints and returns true. A
/// scanner of untrusted files prints nothing a rule asks it to; the calls
/// just hold.
pub struct Console(Arc<StructType>);

impl Console {
    pub fn new() -> Self {
        let t = ["s", "ss", "i", "si", "f", "sf"].iter().fold(StructType::new(), |t, args| {
            t.func("log", args, Type::Int, |_, _| Value::Int(1)).func("hex", args, Type::Int, |_, _| Value::Int(1))
        });
        Console(Arc::new(t))
    }
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Console {
    fn name(&self) -> &'static str {
        "console"
    }

    fn schema(&self) -> Arc<StructType> {
        self.0.clone()
    }

    fn parse(&self, _: &[u8]) -> Value {
        self.0.value().build()
    }
}

pub struct Strings(Arc<StructType>);

impl Strings {
    pub fn new() -> Self {
        let t = StructType::new()
            .func("to_int", "s", Type::Int, |_, a| a[0].as_bytes().map_or(Value::Undef, |s| to_int(s, None)))
            .func("to_int", "si", Type::Int, |_, a| match (a[0].as_bytes(), a[1].as_int()) {
                (Some(s), Some(base)) => to_int(s, Some(base)),
                _ => Value::Undef,
            })
            .func("length", "s", Type::Int, |_, a| {
                a[0].as_bytes().map_or(Value::Undef, |s| Value::Int(s.len() as i64))
            });
        Strings(Arc::new(t))
    }
}

impl Default for Strings {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Strings {
    fn name(&self) -> &'static str {
        "string"
    }

    fn schema(&self) -> Arc<StructType> {
        self.0.clone()
    }

    fn parse(&self, _: &[u8]) -> Value {
        self.0.value().build()
    }
}

/// `strtoll`'s reading: optional sign, then digits in `base` (with `0x` or
/// a leading `0` choosing 16 or 8 when no base is given). Anything left over
/// makes the value undefined, as YARA's `string.to_int` does.
fn to_int(s: &[u8], base: Option<i64>) -> Value {
    let text = String::from_utf8_lossy(s);
    let text = text.trim();
    let (neg, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let (radix, digits) = match base {
        Some(b) if (2..=36).contains(&b) => (b as u32, if b == 16 { digits.trim_start_matches("0x") } else { digits }),
        Some(0) | None => {
            if let Some(h) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
                (16, h)
            } else if digits.len() > 1 && digits.starts_with('0') {
                (8, &digits[1..])
            } else {
                (10, digits)
            }
        }
        _ => return Value::Undef,
    };
    match i64::from_str_radix(digits, radix) {
        Ok(v) => Value::Int(if neg { -v } else { v }),
        Err(_) => Value::Undef,
    }
}

pub struct Time(Arc<StructType>);

impl Time {
    pub fn new() -> Self {
        Time(Arc::new(StructType::new().func("now", "", Type::Int, |_, _| {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            Value::Int(now as i64)
        })))
    }
}

impl Default for Time {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Time {
    fn name(&self) -> &'static str {
        "time"
    }

    fn schema(&self) -> Arc<StructType> {
        self.0.clone()
    }

    fn parse(&self, _: &[u8]) -> Value {
        self.0.value().build()
    }
}

#[cfg(test)]
#[path = "small_tests.rs"]
mod tests;
