use super::*;

#[test]
fn words_count_only_when_cased_as_words() {
    assert!(readable(b"certcrypto.RSA4096"));
    assert!(readable(b"getUserSettings"));
    assert!(readable(b"SERVICE_ACCOUNT_ID"));
    assert!(!readable(b"cErTiFiCaTe"), "random case isn't a word");
    assert!(!readable(b"xq7Rm2Kp9ZtW4vLnB8sQ"));
}

#[test]
fn runs_of_eight_climbing_or_falling_characters_are_placeholders() {
    assert!(has_run(b"0123456789abcdef"));
    assert!(has_run(b"key-hgfedcba"));
    assert!(!has_run(b"0123456x"));
}

#[test]
fn random_keys_read_as_keys() {
    // A fixed pseudo-random sequence: no key in it may read as text.
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut x: u64 = 0x9e3779b97f4a7c15;
    let mut readable_keys = 0;
    for _ in 0..2000 {
        let key: Vec<u8> = (0..32)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                ALNUM[(x % ALNUM.len() as u64) as usize]
            })
            .collect();
        readable_keys += usize::from(readable(&key));
    }
    // About 0.15% of random keys hold a word by chance (betterleaks' list: 0.3%).
    assert!(readable_keys <= 8, "{readable_keys} of 2000 random keys read as text");
}

#[test]
fn the_word_list_is_web2s() {
    assert!(words().len() > 100_000);
    assert!(words().contains(b"account".as_slice()));
    assert!(!words().contains(b"austin".as_slice()), "proper nouns are left out");
    assert!(!words().contains(b"cat".as_slice()), "short words are left out");
}
