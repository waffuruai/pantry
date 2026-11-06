//! Crypto wallet addresses, recognised by shape and checksum rather than
//! by a regular expression, so a 34-character word is an address only
//! when its checksum says so: Bitcoin, Litecoin and Dogecoin (Base58Check
//! and bech32), EVM chains (Ethereum, BSC, Polygon, Tempo: `0x` and 40
//! hex digits, no checksum), Tron (Base58Check, `T`), Solana (32 bytes of
//! Base58), the XRP Ledger (Base58Check over Ripple's alphabet, `r`) and
//! Stellar (StrKey, `G` and a CRC). The clipper check copies a canary of
//! each shape and watches whether it comes back changed; the suspicious
//! code rules look for addresses hardcoded beside clipboard or signing
//! calls.

use crate::utils::sha256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Chain {
    /// Ethereum and every EVM chain: BSC (USDT BEP20), Polygon, Tempo, …
    Evm,
    Bitcoin,
    Litecoin,
    Dogecoin,
    Tron,
    Solana,
    Ripple,
    Stellar,
}

impl Chain {
    pub fn name(self) -> &'static str {
        match self {
            Chain::Evm => "EVM (Ethereum, BSC, Tempo)",
            Chain::Bitcoin => "Bitcoin",
            Chain::Litecoin => "Litecoin",
            Chain::Dogecoin => "Dogecoin",
            Chain::Tron => "Tron",
            Chain::Solana => "Solana",
            Chain::Ripple => "XRP Ledger",
            Chain::Stellar => "Stellar",
        }
    }
}

/// An address found in some text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found<'a> {
    /// Byte offset in the text.
    pub at: usize,
    pub chain: Chain,
    pub text: &'a str,
}

// Base58 ------------------------------------------------------------------

const BTC58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const XRP58: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

fn base58_decode(s: &str, alphabet: &[u8; 58]) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    for c in s.bytes() {
        let v = alphabet.iter().position(|&a| a == c)? as u32;
        let mut carry = v;
        for b in out.iter_mut().rev() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == alphabet[0]).count();
    let mut full = vec![0u8; zeros];
    full.extend(out);
    Some(full)
}

#[cfg(test)]
fn base58_encode(bytes: &[u8], alphabet: &[u8; 58]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut s: Vec<u8> = vec![alphabet[0]; zeros];
    s.extend(digits.iter().rev().map(|&d| alphabet[d as usize]));
    String::from_utf8(s).unwrap_or_default()
}

fn double_sha(bytes: &[u8]) -> [u8; 32] {
    let mut h = sha256::Sha256::new();
    h.update(bytes);
    let first = h.finish();
    let mut h = sha256::Sha256::new();
    h.update(&first);
    h.finish()
}

/// The payload (version byte first) of a Base58Check string, when its
/// checksum holds.
fn base58check(s: &str, alphabet: &[u8; 58]) -> Option<Vec<u8>> {
    let raw = base58_decode(s, alphabet)?;
    if raw.len() < 5 {
        return None;
    }
    let (payload, check) = raw.split_at(raw.len() - 4);
    (double_sha(payload)[..4] == *check).then(|| payload.to_vec())
}

#[cfg(test)]
fn base58check_encode(payload: &[u8], alphabet: &[u8; 58]) -> String {
    let mut full = payload.to_vec();
    full.extend_from_slice(&double_sha(payload)[..4]);
    base58_encode(&full, alphabet)
}

// bech32 ------------------------------------------------------------------

const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|b| b & 31));
    v
}

/// A bech32 or bech32m address of `hrp` (`bc`, `ltc`): the checksum holds
/// and the witness version matches the checksum flavour.
fn bech32_valid(s: &str, hrp: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if s != lower && s != s.to_ascii_uppercase() {
        return false; // mixed case is forbidden
    }
    let Some(data) = lower.strip_prefix(hrp).and_then(|r| r.strip_prefix('1')) else { return false };
    if data.len() < 6 || lower.len() > 90 {
        return false;
    }
    let mut values = Vec::with_capacity(data.len());
    for c in data.bytes() {
        let Some(v) = BECH32.iter().position(|&a| a == c) else { return false };
        values.push(v as u8);
    }
    let mut all = bech32_hrp_expand(hrp);
    all.extend(&values);
    let version = values[0];
    match bech32_polymod(&all) {
        1 => version == 0,
        0x2bc830a3 => version >= 1,
        _ => false,
    }
}

#[cfg(test)]
fn bech32_encode(hrp: &str, version: u8, program: &[u8]) -> String {
    let mut data = vec![version];
    // 8-bit groups to 5-bit groups, padded.
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in program {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        data.push(((acc << (5 - bits)) & 31) as u8);
    }
    let constant = if version == 0 { 1 } else { 0x2bc830a3 };
    let mut all = bech32_hrp_expand(hrp);
    all.extend(&data);
    all.extend([0u8; 6]);
    let pm = bech32_polymod(&all) ^ constant;
    for i in 0..6 {
        data.push(((pm >> (5 * (5 - i))) & 31) as u8);
    }
    let mut s = format!("{hrp}1");
    s.extend(data.iter().map(|&d| BECH32[d as usize] as char));
    s
}

// Stellar StrKey ----------------------------------------------------------

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = BASE32.iter().position(|&a| a == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
fn base32_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            s.push(BASE32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        s.push(BASE32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    s
}

fn crc16_xmodem(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in bytes {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// The 32-byte key of a Stellar public-key StrKey (`G…`, 56 characters).
fn strkey_public(s: &str) -> Option<[u8; 32]> {
    if s.len() != 56 || !s.starts_with('G') {
        return None;
    }
    let raw = base32_decode(s)?;
    if raw.len() != 35 || raw[0] != 6 << 3 {
        return None;
    }
    let crc = crc16_xmodem(&raw[..33]);
    if raw[33] != (crc & 0xff) as u8 || raw[34] != (crc >> 8) as u8 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw[1..33]);
    Some(key)
}

#[cfg(test)]
fn strkey_encode(key: &[u8; 32]) -> String {
    let mut raw = vec![6u8 << 3];
    raw.extend_from_slice(key);
    let crc = crc16_xmodem(&raw);
    raw.push((crc & 0xff) as u8);
    raw.push((crc >> 8) as u8);
    base32_encode(&raw)
}

// Classification ----------------------------------------------------------

/// Addresses every honest program names: Solana's system and token
/// programs, the EVM zero and "native token" placeholders. Never counted.
fn well_known(token: &str) -> bool {
    const SOLANA_PROGRAMS: &[&str] = &[
        "11111111111111111111111111111111",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        "ComputeBudget111111111111111111111111111111",
        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
        "SysvarRent111111111111111111111111111111111",
        "SysvarC1ock11111111111111111111111111111111",
        "Stake11111111111111111111111111111111111111",
        "Vote111111111111111111111111111111111111111",
    ];
    if SOLANA_PROGRAMS.contains(&token) {
        return true;
    }
    if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
        // 0x000…, 0xEeee…, 0xdead…dead: placeholders, not someone's wallet.
        let mut seen = [false; 128];
        let distinct =
            hex.bytes().filter(|&b| !std::mem::replace(&mut seen[b.to_ascii_lowercase() as usize & 127], true)).count();
        return distinct <= 3;
    }
    false
}

/// Which chain a word is an address on, if any: the checksum decides,
/// except for EVM addresses, which have none.
pub fn classify(token: &str) -> Option<Chain> {
    let n = token.len();
    if !(25..=90).contains(&n) || !token.is_ascii() || well_known(token) {
        return None;
    }
    let first = token.as_bytes()[0];
    if n == 42 && (first == b'0') && (token.starts_with("0x") || token.starts_with("0X")) {
        return token[2..].bytes().all(|b| b.is_ascii_hexdigit()).then_some(Chain::Evm);
    }
    let lower_start = token.get(..4).map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    if lower_start.starts_with("bc1") {
        return bech32_valid(token, "bc").then_some(Chain::Bitcoin);
    }
    if lower_start.starts_with("ltc1") {
        return bech32_valid(token, "ltc").then_some(Chain::Litecoin);
    }
    if first == b'G' && n == 56 {
        return strkey_public(token).map(|_| Chain::Stellar);
    }
    if first == b'r' && (25..=35).contains(&n) {
        let payload = base58check(token, XRP58)?;
        return (payload.len() == 21 && payload[0] == 0).then_some(Chain::Ripple);
    }
    if (25..=35).contains(&n) && matches!(first, b'1' | b'3' | b'T' | b'L' | b'M' | b'D') {
        let payload = base58check(token, BTC58)?;
        if payload.len() == 21 {
            return match payload[0] {
                0x00 | 0x05 => Some(Chain::Bitcoin),
                0x30 | 0x32 => Some(Chain::Litecoin),
                0x1e => Some(Chain::Dogecoin),
                0x41 => Some(Chain::Tron),
                _ => None,
            };
        }
    }
    if (32..=44).contains(&n) {
        let raw = base58_decode(token, BTC58)?;
        return (raw.len() == 32).then_some(Chain::Solana);
    }
    None
}

/// Every address in `text`, in order; a word is a maximal run of letters,
/// digits and underscores, so an address inside an identifier or a longer
/// hex string isn't one. At most `limit` are returned.
pub fn find(text: &str, limit: usize) -> Vec<Found<'_>> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() && out.len() < limit {
        if !(bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let token = &text[start..i];
        if token.contains('_') {
            continue;
        }
        if let Some(chain) = classify(token) {
            out.push(Found { at: start, chain, text: token });
        }
    }
    out
}

/// The chains addressed in `text`, each once, in a fixed order.
pub fn chains_in(text: &str) -> Vec<Chain> {
    let mut chains: Vec<Chain> = find(text, 64).into_iter().map(|f| f.chain).collect();
    chains.sort();
    chains.dedup();
    chains
}

/// A valid address of `chain` that belongs to no one, derived from a fixed
/// string: the tests' proof that each shape's checksum is read right.
#[cfg(test)]
pub fn canary(chain: Chain) -> String {
    let mut h = sha256::Sha256::new();
    h.update(format!("wpantry clipboard canary {}", chain.name()).as_bytes());
    let seed = h.finish();
    match chain {
        Chain::Evm => format!("0x{}", &sha256::hex(&seed)[..40]),
        Chain::Bitcoin => bech32_encode("bc", 0, &seed[..20]),
        Chain::Litecoin => bech32_encode("ltc", 0, &seed[..20]),
        Chain::Dogecoin => {
            let mut p = vec![0x1e];
            p.extend_from_slice(&seed[..20]);
            base58check_encode(&p, BTC58)
        }
        Chain::Tron => {
            let mut p = vec![0x41];
            p.extend_from_slice(&seed[..20]);
            base58check_encode(&p, BTC58)
        }
        Chain::Solana => base58_encode(&seed, BTC58),
        Chain::Ripple => {
            let mut p = vec![0x00];
            p.extend_from_slice(&seed[..20]);
            base58check_encode(&p, XRP58)
        }
        Chain::Stellar => strkey_encode(&seed),
    }
}

#[cfg(test)]
#[path = "addresses_tests.rs"]
mod tests;
