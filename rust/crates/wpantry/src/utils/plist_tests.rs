use super::*;

const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.example.App</string>
	<key>CFBundleShortVersionString</key>
	<string>4.41.0 &amp; more</string>
	<!-- a comment -->
	<key>LSRequiresNativeExecution</key>
	<true/>
	<key>CFBundleDocumentTypes</key>
	<array><dict><key>n</key><integer>3</integer></dict><string/></array>
	<key>Empty</key>
	<dict/>
</dict>
</plist>"#;

#[test]
fn xml_plists() {
    let v = parse(XML.as_bytes()).unwrap();
    assert_eq!(v["CFBundleIdentifier"], "com.example.App");
    assert_eq!(v["CFBundleShortVersionString"], "4.41.0 & more");
    assert_eq!(v["LSRequiresNativeExecution"], true);
    assert_eq!(v["CFBundleDocumentTypes"][0]["n"], 3);
    assert_eq!(v["CFBundleDocumentTypes"][1], "");
    assert!(v["Empty"].as_object().unwrap().is_empty());
    assert!(parse(b"<plist><dict><key>x</key></dict></plist>").is_none());
}

#[test]
fn xml_values_and_malformed_documents() {
    let v = parse(b"<plist><dict><key>r</key><real>1.5</real><key>b</key><false/><key>d</key><data> AQID </data><key>bad</key><real>x</real><key>i</key><integer>q</integer></dict></plist>").unwrap();
    assert_eq!(v, serde_json::json!({"r": 1.5, "b": false, "d": "4", "bad": "x", "i": "q"}));
    assert!(parse(b"<plist><dict><string>x</string></dict></plist>").is_none(), "a dict entry without a key");
    assert!(parse(b"<plist><bogus/></plist>").is_none(), "an unknown element");
    assert!(parse(b"<plist></plist>").is_none(), "nothing inside");
    assert!(parse(b"<plist><array><string>x</string>").is_none(), "an array that never closes");
    assert!(parse(&[0xff, 0xfe, b'<']).is_none(), "not text");
    let deep = "<array>".repeat(70);
    assert!(parse(deep.as_bytes()).is_none(), "nesting past the cap");
    assert_eq!(parse(b"<array/>"), Some(serde_json::json!([])));
}

#[test]
fn read_gives_an_object_or_nothing() {
    let d = crate::utils::temp::TempDir::new("plist").unwrap();
    let f = d.path().join("Info.plist");
    std::fs::write(&f, XML).unwrap();
    assert_eq!(read(&f)["CFBundleIdentifier"], "com.example.App");
    std::fs::write(&f, "<plist><string>x</string></plist>").unwrap();
    assert_eq!(read(&f), serde_json::json!({}), "a top-level string isn't a plist we use");
    assert_eq!(read(&d.path().join("missing")), serde_json::json!({}));
}

/// A binary plist written by hand: {"CFBundleVersion": "1.2.3", "n": 7, "ok": true}.
fn bplist() -> Vec<u8> {
    let mut b = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    // 0: dict with 3 entries, keys 1 2 3, values 4 5 6
    offsets.push(b.len());
    b.extend([0xD3, 1, 2, 3, 4, 5, 6]);
    for s in ["CFBundleVersion", "n", "ok"] {
        offsets.push(b.len());
        if s.len() < 15 {
            b.push(0x50 | s.len() as u8);
        } else {
            b.extend([0x5F, 0x10, s.len() as u8]); // the length as a following integer
        }
        b.extend(s.as_bytes());
    }
    offsets.push(b.len());
    b.push(0x55);
    b.extend(b"1.2.3");
    offsets.push(b.len());
    b.extend([0x10, 7]);
    offsets.push(b.len());
    b.push(0x09);
    let table = b.len();
    b.extend(offsets.iter().map(|o| *o as u8));
    let mut trailer = vec![0u8; 6];
    trailer.extend([1, 1]);
    trailer.extend((offsets.len() as u64).to_be_bytes());
    trailer.extend(0u64.to_be_bytes());
    trailer.extend((table as u64).to_be_bytes());
    b.extend(trailer);
    b
}

#[test]
fn binary_plists() {
    let v = parse(&bplist()).unwrap();
    assert_eq!(v, serde_json::json!({"CFBundleVersion": "1.2.3", "n": 7, "ok": true}));
    let mut broken = bplist();
    let n = broken.len();
    broken[n - 1] = 0xff; // offset table out of range
    assert!(parse(&broken).is_none());
    let mut no_offsets = bplist();
    no_offsets[n - 26] = 0; // an offset size of zero
    assert!(parse(&no_offsets).is_none());
}

/// A binary plist of these objects (one-byte offsets and references),
/// object 0 on top.
fn bplist_of(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut b = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    for o in objects {
        offsets.push(b.len() as u8);
        b.extend(o);
    }
    let table = b.len();
    b.extend(&offsets);
    let mut trailer = vec![0u8; 6];
    trailer.extend([1, 1]);
    trailer.extend((objects.len() as u64).to_be_bytes());
    trailer.extend(0u64.to_be_bytes());
    trailer.extend((table as u64).to_be_bytes());
    b.extend(trailer);
    b
}

#[test]
fn binary_object_types() {
    let s = |t: &str| [&[0x50 | t.len() as u8], t.as_bytes()].concat();
    let objects = vec![
        vec![0xD5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        s("a"),
        s("b"),
        s("c"),
        s("d"),
        s("e"),
        vec![0xA3, 11, 12, 13],
        [&[0x22][..], &1.5f32.to_be_bytes()].concat(),
        [&[0x23][..], &2.5f64.to_be_bytes()].concat(),
        vec![0x43, 1, 2, 3],
        vec![0x61, 0x00, 0xE9],
        vec![0x08],
        vec![0x00],
        [&[0x33][..], &[0u8; 8]].concat(),
    ];
    assert_eq!(
        parse(&bplist_of(&objects)),
        Some(serde_json::json!({"a": [false, null, ""], "b": 1.5, "c": 2.5, "d": "3", "e": "\u{e9}"}))
    );
    assert_eq!(parse(&bplist_of(&[vec![0x70]])), None, "an unknown marker");
    assert_eq!(parse(&bplist_of(&[vec![0x21, 0, 0]])), None, "a real of two bytes");
    assert_eq!(parse(&bplist_of(&[vec![0x5F, 0x20, 1]])), None, "a count that isn't an integer");
    assert_eq!(parse(&bplist_of(&[[&[0x5F, 0x14][..], &[0u8; 16]].concat()])), None, "a 16-byte count");
    assert_eq!(parse(&bplist_of(&[vec![0xA1, 0]])), None, "an array holding itself");
    assert_eq!(parse(&bplist_of(&[vec![0xD1, 1, 1], vec![0x10, 1]])), None, "a key that isn't a string");
    assert_eq!(parse(b"bplist00short"), None);
}
