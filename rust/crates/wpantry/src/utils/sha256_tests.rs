use super::*;

#[test]
fn nist_vectors() {
    assert_eq!(hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(
        hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    let mut h = Sha256::new();
    for _ in 0..1000 {
        h.update(&[b'a'; 1000]);
    }
    assert_eq!(h.hex(), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

#[test]
fn split_updates_match_one_update() {
    let data: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
    for cut in [0, 1, 55, 56, 63, 64, 65, 200, 300] {
        let mut h = Sha256::new();
        h.update(&data[..cut]);
        h.update(&data[cut..]);
        assert_eq!(h.hex(), hex(&data));
    }
}
