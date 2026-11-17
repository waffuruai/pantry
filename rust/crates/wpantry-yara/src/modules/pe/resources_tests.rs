use super::*;

fn wide(s: &str) -> Vec<u8> {
    s.bytes().flat_map(|b| [b, 0]).chain([0, 0]).collect()
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

/// A version block: header, key, aligned value, aligned children.
fn block(key: &str, kind: u16, value: &[u8], value_len: u16, children: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0, 0];
    b.extend(value_len.to_le_bytes());
    b.extend(kind.to_le_bytes());
    b.extend(wide(key));
    pad4(&mut b);
    b.extend(value);
    pad4(&mut b);
    for c in children {
        b.extend(c);
        pad4(&mut b);
    }
    let len = b.len() as u16;
    b[..2].copy_from_slice(&len.to_le_bytes());
    b
}

/// A VS_VERSIONINFO with the given strings.
pub fn version_resource(pairs: &[(&str, &str)]) -> Vec<u8> {
    let strings: Vec<Vec<u8>> = pairs.iter().map(|(k, v)| block(k, 1, &wide(v), (v.len() + 1) as u16, &[])).collect();
    let table = block("040904b0", 1, &[], 0, &strings);
    let sfi = block("StringFileInfo", 1, &[], 0, &[table]);
    block("VS_VERSION_INFO", 0, &[0; 52], 52, &[sfi])
}

/// A resource section with one RT_VERSION resource holding `payload`,
/// laid out at file offset 0 = RVA `rva`.
pub fn resource_section(rva: u32, payload: &[u8]) -> Vec<u8> {
    let mut s = vec![0u8; 0x80];
    let dir = |s: &mut Vec<u8>, at: usize, id: u32, child: u32| {
        s[at + 14..at + 16].copy_from_slice(&1u16.to_le_bytes());
        s[at + 16..at + 20].copy_from_slice(&id.to_le_bytes());
        s[at + 20..at + 24].copy_from_slice(&child.to_le_bytes());
    };
    s[4..8].copy_from_slice(&0x1234u32.to_le_bytes());
    s[8..10].copy_from_slice(&4u16.to_le_bytes());
    dir(&mut s, 0x00, RT_VERSION, 0x8000_0018);
    dir(&mut s, 0x18, 1, 0x8000_0030);
    dir(&mut s, 0x30, 0x409, 0x48);
    s[0x48..0x4C].copy_from_slice(&(rva + 0x80).to_le_bytes());
    s[0x4C..0x50].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    s.extend_from_slice(payload);
    s
}

#[test]
fn walks_the_tree_and_reads_version_strings() {
    let payload = version_resource(&[("CompanyName", "Evil Corp"), ("OriginalFilename", "x.exe")]);
    let section = resource_section(0x1000, &payload);
    let tree = walk(&section, 0, &|rva| Some((rva - 0x1000) as usize)).unwrap();
    assert_eq!((tree.timestamp, tree.major), (0x1234, 4));
    assert_eq!(tree.resources.len(), 1);
    let r = &tree.resources[0];
    assert_eq!((r.rva, r.offset, r.length as usize), (0x1080, Some(0x80), payload.len()));
    assert_eq!(r.path, [Ok(16), Ok(1), Ok(0x409)]);
    let pairs = version_info(&section, &tree);
    assert_eq!(
        pairs,
        vec![(b"CompanyName".to_vec(), b"Evil Corp".to_vec()), (b"OriginalFilename".to_vec(), b"x.exe".to_vec())]
    );
    let ty = Arc::new(resource_type());
    let vals = values(&tree, &ty);
    assert_eq!(vals[0].field(3).as_int(), Some(16));
    let kv = Arc::new(StructType::new().string("key").string("value"));
    let (dict, list) = version_values(&pairs, &kv);
    assert!(matches!(dict, Value::Dict(d) if d.len() == 2));
    assert!(matches!(list, Value::Array(a) if a.len() == 2));
}

#[test]
fn named_entries_and_junk() {
    let mut s = vec![0u8; 0x40];
    s[12..14].copy_from_slice(&1u16.to_le_bytes());
    s[16..20].copy_from_slice(&0x8000_0030u32.to_le_bytes());
    s[20..24].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    s[0x30..0x32].copy_from_slice(&2u16.to_le_bytes());
    s[0x32..0x36].copy_from_slice(b"A\0B\0");
    let tree = walk(&s, 0, &|_| None).unwrap();
    assert!(tree.resources.is_empty(), "a directory pointing at itself is not followed");
    assert!(walk(b"", 0, &|_| None).is_none());
    assert!(version_info(b"", &tree).is_empty());
    assert!(wide_cstr(&[0x41, 0], 0).is_none(), "unterminated");
}
