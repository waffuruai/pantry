//! Values conditions compute with, and the types modules declare.
//!
//! A module (`pe`, `elf`, …) describes its data once as a [`StructType`]:
//! fields with their types, constants (`pe.MACHINE_AMD64`) and functions
//! (`pe.imports("kernel32.dll", "VirtualAlloc")`). The compiler checks every
//! identifier against it, so a rule that names something we don't provide is
//! rejected with a reason instead of silently never matching, and it turns a
//! field name into a slot index once; at scan time the module fills a
//! [`StructVal`] whose fields sit in those slots.

use std::sync::Arc;

/// A value, or `Undef` when it doesn't exist for this file (a PE field of an
/// ELF, an offset past the end, a division by zero). YARA's rule: undefined
/// spreads through arithmetic and comparisons and is false as a condition.
#[derive(Clone, Debug, Default)]
pub enum Value {
    #[default]
    Undef,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Arc<[u8]>),
    Struct(Arc<StructVal>),
    Array(Arc<Vec<Value>>),
    Dict(Arc<Vec<(Arc<[u8]>, Value)>>),
    /// A regular expression literal passed to a module function.
    Regex(Arc<crate::pattern::Node>),
}

impl Value {
    pub fn str(bytes: impl AsRef<[u8]>) -> Value {
        Value::Str(Arc::from(bytes.as_ref()))
    }

    /// The value as a condition.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Undef => false,
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::Struct(_) | Value::Array(_) | Value::Dict(_) | Value::Regex(_) => true,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Bool(b) => Some(i64::from(*b)),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Int(i) => Some(*i as f64),
            Value::Bool(b) => Some(f64::from(u8::from(*b))),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_undef(&self) -> bool {
        matches!(self, Value::Undef)
    }

    /// A field of a structure by slot.
    pub fn field(&self, slot: usize) -> Value {
        match self {
            Value::Struct(s) => s.fields.get(slot).cloned().unwrap_or_default(),
            _ => Value::Undef,
        }
    }
}

/// The fields of a structure value, in its type's slot order.
#[derive(Debug, Default)]
pub struct StructVal {
    pub fields: Vec<Value>,
}

/// A value's type, checked when a rule compiles.
#[derive(Clone, Debug)]
pub enum Type {
    Bool,
    Int,
    Float,
    Str,
    Struct(Arc<StructType>),
    Array(Box<Type>),
    Dict(Box<Type>),
}

impl Type {
    pub fn name(&self) -> &'static str {
        match self {
            Type::Bool => "bool",
            Type::Int => "integer",
            Type::Float => "float",
            Type::Str => "string",
            Type::Struct(_) => "structure",
            Type::Array(_) => "array",
            Type::Dict(_) => "dictionary",
        }
    }

    pub fn is_numeric(&self) -> bool {
        matches!(self, Type::Int | Type::Float | Type::Bool)
    }
}

/// What a module function receives: the scanned data, and the structure the
/// function belongs to (the module itself, or `pe.signatures[i]` for a method).
pub struct FnCtx<'a> {
    pub data: &'a [u8],
    pub this: &'a Value,
}

/// A module function's argument kinds, one letter each: `i` integer, `f`
/// float, `s` string, `r` regex; and what it returns.
pub type FnPtr = fn(&FnCtx, &[Value]) -> Value;

#[derive(Clone)]
pub struct Func {
    pub args: &'static str,
    pub ret: Type,
    pub f: FnPtr,
}

impl std::fmt::Debug for Func {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fn({}) -> {}", self.args, self.ret.name())
    }
}

#[derive(Clone, Debug)]
pub enum FieldKind {
    /// A value at `slot` of the structure.
    Value { ty: Type, slot: usize },
    /// A constant, inlined when a rule compiles.
    Const(Value),
    /// One or more overloads.
    Func(Vec<Func>),
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: &'static str,
    pub kind: FieldKind,
}

/// A structure's declaration, built with the chained methods below.
#[derive(Clone, Debug, Default)]
pub struct StructType {
    pub fields: Vec<Field>,
    slots: usize,
}

impl StructType {
    pub fn new() -> Self {
        StructType::default()
    }

    pub fn field(mut self, name: &'static str, ty: Type) -> Self {
        self.fields.push(Field { name, kind: FieldKind::Value { ty, slot: self.slots } });
        self.slots += 1;
        self
    }

    pub fn int(self, name: &'static str) -> Self {
        self.field(name, Type::Int)
    }

    pub fn float(self, name: &'static str) -> Self {
        self.field(name, Type::Float)
    }

    pub fn string(self, name: &'static str) -> Self {
        self.field(name, Type::Str)
    }

    pub fn array(self, name: &'static str, elem: Type) -> Self {
        self.field(name, Type::Array(Box::new(elem)))
    }

    pub fn dict(self, name: &'static str, elem: Type) -> Self {
        self.field(name, Type::Dict(Box::new(elem)))
    }

    pub fn constant(mut self, name: &'static str, value: i64) -> Self {
        self.fields.push(Field { name, kind: FieldKind::Const(Value::Int(value)) });
        self
    }

    pub fn constant_str(mut self, name: &'static str, value: &str) -> Self {
        self.fields.push(Field { name, kind: FieldKind::Const(Value::str(value)) });
        self
    }

    /// Add an overload of function `name`.
    pub fn func(mut self, name: &'static str, args: &'static str, ret: Type, f: FnPtr) -> Self {
        let func = Func { args, ret, f };
        match self.fields.iter_mut().find(|fd| fd.name == name) {
            Some(Field { kind: FieldKind::Func(overloads), .. }) => overloads.push(func),
            _ => self.fields.push(Field { name, kind: FieldKind::Func(vec![func]) }),
        }
        self
    }

    pub fn lookup(&self, name: &str) -> Option<&FieldKind> {
        self.fields.iter().find(|f| f.name == name).map(|f| &f.kind)
    }

    fn slot(&self, name: &str) -> usize {
        match self.lookup(name) {
            Some(FieldKind::Value { slot, .. }) => *slot,
            _ => panic!("no value field {name} in this structure"),
        }
    }

    /// An empty value of this type, every field undefined.
    pub fn value(self: &Arc<Self>) -> StructBuilder {
        StructBuilder { ty: self.clone(), fields: vec![Value::Undef; self.slots] }
    }
}

/// Fills a structure value by field name.
pub struct StructBuilder {
    ty: Arc<StructType>,
    fields: Vec<Value>,
}

impl StructBuilder {
    pub fn set(&mut self, name: &str, value: Value) -> &mut Self {
        let slot = self.ty.slot(name);
        self.fields[slot] = value;
        self
    }

    pub fn int(&mut self, name: &str, value: impl Into<i64>) -> &mut Self {
        self.set(name, Value::Int(value.into()))
    }

    pub fn string(&mut self, name: &str, value: impl AsRef<[u8]>) -> &mut Self {
        self.set(name, Value::str(value))
    }

    pub fn build(self) -> Value {
        Value::Struct(Arc::new(StructVal { fields: self.fields }))
    }
}

/// An array value from a list.
pub fn array(items: Vec<Value>) -> Value {
    Value::Array(Arc::new(items))
}

#[cfg(test)]
#[path = "value_tests.rs"]
mod tests;
