//! Just enough ASN.1 DER to read Authenticode: elements, OIDs, X.509 names
//! (in OpenSSL's one-line form, as YARA prints them), integers and times.

/// One element: its tag, its contents, and the whole encoding.
#[derive(Clone, Copy, Debug)]
pub struct Elem<'a> {
    pub tag: u8,
    pub body: &'a [u8],
    pub raw: &'a [u8],
}

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const BMP_STRING: u8 = 0x1E;
/// `[0]` and `[1]`, constructed, context-specific.
pub const CTX0: u8 = 0xA0;
pub const CTX1: u8 = 0xA1;

/// Reads consecutive elements from a buffer.
pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader(data)
    }

    /// The next element, or `None` at the end or on malformed input
    /// (indefinite lengths and lengths past the buffer included).
    pub fn next(&mut self) -> Option<Elem<'a>> {
        let d = self.0;
        let tag = *d.first()?;
        let first = *d.get(1)?;
        let (len, header) = if first < 0x80 {
            (first as usize, 2)
        } else {
            let n = (first & 0x7F) as usize;
            if n == 0 || n > 4 {
                return None;
            }
            let len = d.get(2..2 + n)?.iter().fold(0usize, |l, b| l << 8 | *b as usize);
            (len, 2 + n)
        };
        let end = header.checked_add(len)?;
        let raw = d.get(..end)?;
        self.0 = &d[end..];
        Some(Elem { tag, body: &raw[header..], raw })
    }

    /// The next element if it has `tag`.
    pub fn expect(&mut self, tag: u8) -> Option<Elem<'a>> {
        self.next().filter(|e| e.tag == tag)
    }

    /// The next element if it has `tag`; otherwise nothing is consumed.
    pub fn optional(&mut self, tag: u8) -> Option<Elem<'a>> {
        let save = self.0;
        match self.next() {
            Some(e) if e.tag == tag => Some(e),
            _ => {
                self.0 = save;
                None
            }
        }
    }
}

impl<'a> Elem<'a> {
    pub fn children(&self) -> Reader<'a> {
        Reader(self.body)
    }
}

/// An OID in dotted form.
pub fn oid(body: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut value: u64 = 0;
    for (i, b) in body.iter().enumerate() {
        value = value << 7 | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            if parts.is_empty() && i < body.len() {
                let (first, second) = if value < 80 { (value / 40, value % 40) } else { (2, value - 80) };
                parts.push(first.to_string());
                parts.push(second.to_string());
            } else {
                parts.push(value.to_string());
            }
            value = 0;
        }
    }
    parts.join(".")
}

/// The short name OpenSSL prints for a name attribute.
fn attr_name(oid: &str) -> &str {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.15" => "businessCategory",
        "2.5.4.17" => "postalCode",
        "2.5.4.42" => "GN",
        "2.5.4.97" => "organizationIdentifier",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.3.6.1.4.1.311.60.2.1.1" => "jurisdictionL",
        "1.3.6.1.4.1.311.60.2.1.2" => "jurisdictionST",
        "1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionC",
        other => other,
    }
}

/// An X.509 name as `/C=US/O=Example/CN=Name`, with bytes outside printable
/// ASCII as `\xHH`, the way OpenSSL's `X509_NAME_oneline` writes it.
pub fn name(n: &Elem) -> String {
    let mut out = String::new();
    let mut rdns = n.children();
    while let Some(rdn) = rdns.next() {
        let mut attrs = rdn.children();
        while let Some(attr) = attrs.next() {
            let mut parts = attr.children();
            let (Some(o), Some(v)) = (parts.expect(OID), parts.next()) else { continue };
            out.push('/');
            out.push_str(attr_name(&oid(o.body)));
            out.push('=');
            // A BMPString of plain ASCII drops its zero high bytes.
            let bytes: Vec<u8> = if v.tag == BMP_STRING && v.body.chunks(2).all(|c| c[0] == 0 && c.len() == 2) {
                v.body.chunks(2).map(|c| c[1]).collect()
            } else {
                v.body.to_vec()
            };
            for b in bytes {
                if (b' '..=b'~').contains(&b) {
                    out.push(b as char);
                } else {
                    out.push_str(&format!("\\x{b:02X}"));
                }
            }
        }
    }
    out
}

/// A serial number as YARA prints it: `0b:96:7c`, leading zero bytes dropped.
pub fn serial(body: &[u8]) -> String {
    let start = body.iter().position(|b| *b != 0).unwrap_or(body.len().saturating_sub(1));
    body[start..].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// A UTCTime or GeneralizedTime as seconds since the epoch.
pub fn time(e: &Elem) -> Option<i64> {
    let s = std::str::from_utf8(e.body).ok()?;
    let digits = s.trim_end_matches('Z');
    let (year, rest) = match e.tag {
        UTC_TIME => {
            let yy: i64 = digits.get(..2)?.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, digits.get(2..)?)
        }
        GENERALIZED_TIME => (digits.get(..4)?.parse().ok()?, digits.get(4..)?),
        _ => return None,
    };
    let field = |i: usize| -> Option<i64> { rest.get(i..i + 2).map_or(Some(0), |f| f.parse().ok()) };
    let (month, day, hour, min, sec) = (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The name of a signature or digest algorithm, as OpenSSL calls it.
pub fn algorithm_name(oid: &str) -> &str {
    match oid {
        "1.2.840.113549.1.1.2" => "md2WithRSAEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "rsassaPss",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.2.840.10040.4.3" => "dsaWithSHA1",
        "1.3.14.3.2.26" => "sha1",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        "1.2.840.113549.2.5" => "md5",
        other => other,
    }
}

#[cfg(test)]
#[path = "der_tests.rs"]
pub mod tests;
