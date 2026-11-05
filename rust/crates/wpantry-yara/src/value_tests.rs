use super::*;

fn double(_: &FnCtx, args: &[Value]) -> Value {
    Value::Int(args[0].as_int().unwrap() * 2)
}

#[test]
fn truthiness_follows_yara() {
    assert!(!Value::Undef.truthy());
    assert!(Value::Int(2).truthy() && !Value::Int(0).truthy());
    assert!(Value::Float(0.5).truthy() && !Value::Float(0.0).truthy());
    assert!(Value::str("x").truthy() && !Value::str("").truthy());
    assert!(array(vec![]).truthy());
    assert_eq!(Value::Bool(true).as_int(), Some(1));
    assert_eq!(Value::Int(3).as_float(), Some(3.0));
    assert_eq!(Value::Bool(true).as_float(), Some(1.0));
    assert_eq!(Value::str("a").as_int(), None);
    assert_eq!(Value::Int(1).as_bytes(), None);
    assert!(Value::Int(1).field(0).is_undef());
}

#[test]
fn structures_by_name_and_slot() {
    let ty = Arc::new(
        StructType::new()
            .int("a")
            .string("b")
            .float("c")
            .array("d", Type::Int)
            .dict("e", Type::Str)
            .constant("K", 7)
            .constant_str("S", "s")
            .func("twice", "i", Type::Int, double)
            .func("twice", "s", Type::Int, double),
    );
    let mut b = ty.value();
    b.int("a", 5).string("b", "x");
    let v = b.build();
    assert_eq!(v.field(0).as_int(), Some(5));
    assert_eq!(v.field(1).as_bytes(), Some(&b"x"[..]));
    assert!(v.field(2).is_undef());
    let Some(FieldKind::Func(overloads)) = ty.lookup("twice") else { panic!() };
    assert_eq!(overloads.len(), 2);
    assert_eq!(format!("{:?}", overloads[0]), "fn(i) -> integer");
    let ctx = FnCtx { data: b"", this: &v };
    assert_eq!((overloads[0].f)(&ctx, &[Value::Int(4)]).as_int(), Some(8));
    assert!(matches!(ty.lookup("K"), Some(FieldKind::Const(Value::Int(7)))));
    assert!(ty.lookup("nope").is_none());
    assert_eq!(Type::Dict(Box::new(Type::Int)).name(), "dictionary");
    assert!(Type::Bool.is_numeric() && !Type::Str.is_numeric());
}

#[test]
#[should_panic(expected = "no value field")]
fn setting_an_unknown_field_is_a_bug() {
    let ty = Arc::new(StructType::new().int("a"));
    ty.value().int("b", 1);
}
