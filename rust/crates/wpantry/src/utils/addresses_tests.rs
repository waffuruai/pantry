use super::*;

#[test]
fn real_addresses_classify_by_checksum() {
    // Published, well-known addresses of each shape.
    assert_eq!(classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), Some(Chain::Bitcoin), "the genesis P2PKH");
    assert_eq!(classify("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"), Some(Chain::Bitcoin), "P2SH");
    assert_eq!(classify("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), Some(Chain::Bitcoin), "bech32 v0");
    assert_eq!(
        classify("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"),
        Some(Chain::Bitcoin),
        "bech32m taproot"
    );
    assert_eq!(classify("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"), Some(Chain::Tron), "USDT TRC20 contract");
    assert_eq!(classify("rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH"), Some(Chain::Ripple));
    assert_eq!(classify("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"), Some(Chain::Stellar));
    assert_eq!(classify("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"), Some(Chain::Dogecoin));
    assert_eq!(classify("LVg2kJoFNg45Nbpy53h7Fe1wKyeXVRhMH9"), Some(Chain::Litecoin));
    assert_eq!(classify("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"), Some(Chain::Solana));
    assert_eq!(classify("0xdAC17F958D2ee523a2206206994597C13D831ec7"), Some(Chain::Evm), "USDT on Ethereum");
    assert_eq!(classify("0xD62Eb957610d49f77cFce8bCc9827b5428D790E6"), Some(Chain::Evm), "a clipper's address");
}

#[test]
fn near_misses_do_not() {
    assert_eq!(classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"), None, "one character off: checksum fails");
    assert_eq!(classify("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr"), None);
    assert_eq!(classify("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN8"), None);
    assert_eq!(classify("rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRJ"), None);
    assert_eq!(classify("0xdAC17F958D2ee523a2206206994597C13D831ecZ"), None, "not hex");
    assert_eq!(classify("0x0000000000000000000000000000000000000000"), None, "the zero address is nobody's");
    assert_eq!(classify("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"), None, "the native-token placeholder");
    assert_eq!(classify("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"), None, "the token program");
    assert_eq!(classify("11111111111111111111111111111111"), None, "the system program");
    assert_eq!(classify("averyordinaryidentifierthatislongish"), None);
    assert_eq!(classify("d41d8cd98f00b204e9800998ecf8427e"), None, "an md5: 32 hex isn't 32 bytes of base58");
    assert_eq!(classify("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"), None, "an IPFS CID is 34 bytes");
}

#[test]
fn find_walks_words_and_skips_identifiers() {
    let text = "const to = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'; // and 0xdAC17F958D2ee523a2206206994597C13D831ec7\nx_0xdAC17F958D2ee523a2206206994597C13D831ec7";
    let got = find(text, 10);
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!((got[0].chain, got[0].at), (Chain::Tron, 12));
    assert_eq!(got[1].chain, Chain::Evm);
    assert_eq!(chains_in(text), [Chain::Evm, Chain::Tron]);
    assert_eq!(find(text, 1).len(), 1, "the limit holds");
    assert!(find("0xdAC17F958D2ee523a2206206994597C13D831ec7ab", 10).is_empty(), "a longer hex string is not one");
}

#[test]
fn canaries_are_valid_addresses_of_their_chain() {
    for &c in [
        Chain::Evm,
        Chain::Bitcoin,
        Chain::Litecoin,
        Chain::Dogecoin,
        Chain::Tron,
        Chain::Solana,
        Chain::Ripple,
        Chain::Stellar,
    ]
    .iter()
    {
        let a = canary(c);
        assert_eq!(classify(&a), Some(c), "{a}");
        assert_eq!(canary(c), a, "stable across runs");
    }
    assert!(canary(Chain::Tron).starts_with('T'));
    assert!(canary(Chain::Ripple).starts_with('r'));
    assert!(canary(Chain::Stellar).starts_with('G'));
    assert!(canary(Chain::Bitcoin).starts_with("bc1q"));
    assert_ne!(canary(Chain::Evm), canary(Chain::Tron));
}

#[test]
fn codecs_round_trip() {
    let bytes = [0u8, 0, 1, 2, 255, 58];
    let s = base58_encode(&bytes, BTC58);
    assert!(s.starts_with("11"), "leading zero bytes are leading 1s: {s}");
    assert_eq!(base58_decode(&s, BTC58), Some(bytes.to_vec()));
    let r = base58_encode(&bytes, XRP58);
    assert!(r.starts_with("rr"), "{r}");
    assert_eq!(base58_decode(&r, XRP58), Some(bytes.to_vec()));
    assert_eq!(base32_decode(&base32_encode(b"hello")), Some(b"hello".to_vec()));
    assert_eq!(crc16_xmodem(b"123456789"), 0x31c3, "the CRC-16/XMODEM check value");
    assert!(bech32_valid("BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ", "bc"), "all upper case is allowed");
    assert!(!bech32_valid("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdQ", "bc"), "mixed case is not");
}
