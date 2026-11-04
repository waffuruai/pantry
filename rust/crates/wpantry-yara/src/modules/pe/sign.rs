//! Authenticode signatures: the PKCS#7 blobs in a PE's security directory.
//!
//! Each signature (nested ones included) becomes one `pe.signatures[i]`
//! describing the certificate that signed it (issuer, subject, serial,
//! thumbprint, validity), with every certificate the blob carries in
//! `certificates`. Nothing is verified cryptographically: `verified` is 0,
//! and rules match on who signed, which is what signature rules check.

use super::der::{self, CTX0, CTX1, Elem, INTEGER, OCTET_STRING, OID, Reader, SEQUENCE, SET};
use crate::modules::hash::sha1;
use crate::modules::{hex, u16le, u32le};
use crate::value::{FnCtx, StructType, Type, Value, array};
use std::sync::Arc;

const NESTED_SIGNATURE: &str = "1.3.6.1.4.1.311.2.4.1";
/// `WIN_CERT_TYPE_PKCS_SIGNED_DATA`
const PKCS_SIGNED_DATA: u16 = 2;
/// Nested signatures deeper than this are ignored (a loop guard).
const MAX_DEPTH: usize = 4;

pub fn certificate_type() -> StructType {
    StructType::new()
        .string("issuer")
        .string("subject")
        .string("thumbprint")
        .int("version")
        .string("algorithm")
        .string("algorithm_oid")
        .string("serial")
        .int("not_before")
        .int("not_after")
}

pub fn signature_type() -> StructType {
    certificate_type()
        .int("verified")
        .string("digest_alg")
        .string("digest")
        .string("file_digest")
        .int("number_of_certificates")
        .array("certificates", Type::Struct(Arc::new(certificate_type())))
        .func("valid_on", "i", Type::Int, valid_on)
}

/// `pe.signatures[i].valid_on(timestamp)`
fn valid_on(c: &FnCtx, a: &[Value]) -> Value {
    let field = |name: &str| match c.this {
        Value::Struct(_) => {
            let ty = certificate_type();
            let slot = ty.fields.iter().position(|f| f.name == name).expect("field");
            c.this.field(slot).as_int()
        }
        _ => None,
    };
    match (a[0].as_int(), field("not_before"), field("not_after")) {
        (Some(t), Some(lo), Some(hi)) => Value::Int(i64::from(lo <= t && t <= hi)),
        _ => Value::Undef,
    }
}

/// A parsed certificate.
struct Cert<'a> {
    raw: &'a [u8],
    issuer_raw: &'a [u8],
    serial_raw: &'a [u8],
    issuer: String,
    subject: String,
    version: i64,
    algorithm_oid: String,
    not_before: Option<i64>,
    not_after: Option<i64>,
}

fn parse_cert<'a>(e: &Elem<'a>) -> Option<Cert<'a>> {
    let mut cert = e.children();
    let tbs = cert.expect(SEQUENCE)?;
    let sig_alg = cert.expect(SEQUENCE)?;
    let mut t = tbs.children();
    let version = match t.optional(CTX0) {
        Some(v) => v.children().expect(INTEGER)?.body.last().map_or(1, |b| i64::from(*b) + 1),
        None => 1,
    };
    let serial = t.expect(INTEGER)?;
    t.expect(SEQUENCE)?;
    let issuer = t.expect(SEQUENCE)?;
    let validity = t.expect(SEQUENCE)?;
    let subject = t.expect(SEQUENCE)?;
    let mut v = validity.children();
    let (nb, na) = (v.next()?, v.next()?);
    let alg = sig_alg.children().expect(OID).map(|o| der::oid(o.body)).unwrap_or_default();
    Some(Cert {
        raw: e.raw,
        issuer_raw: issuer.raw,
        serial_raw: serial.body,
        issuer: der::name(&issuer),
        subject: der::name(&subject),
        version,
        algorithm_oid: alg,
        not_before: der::time(&nb),
        not_after: der::time(&na),
    })
}

fn cert_value(c: &Cert, ty: &Arc<StructType>) -> crate::value::StructBuilder {
    let mut v = ty.value();
    v.string("issuer", &c.issuer)
        .string("subject", &c.subject)
        .string("thumbprint", hex(&sha1(c.raw)))
        .int("version", c.version)
        .string("algorithm", der::algorithm_name(&c.algorithm_oid))
        .string("algorithm_oid", &c.algorithm_oid)
        .string("serial", der::serial(c.serial_raw));
    if let Some(t) = c.not_before {
        v.int("not_before", t);
    }
    if let Some(t) = c.not_after {
        v.int("not_after", t);
    }
    v
}

/// The signatures in a PE's security directory (`offset`, `size` are a file range).
pub fn signatures(data: &[u8], offset: usize, size: usize, sig_ty: &Arc<StructType>) -> Vec<Value> {
    let mut out = Vec::new();
    let Some(dir) = data.get(offset..offset.saturating_add(size)) else { return out };
    let mut pos = 0;
    // WIN_CERTIFICATE entries, each 8-byte aligned.
    while let (Some(len), Some(kind)) = (u32le(dir, pos), u16le(dir, pos + 6)) {
        let len = len as usize;
        if len < 8 {
            break;
        }
        if kind == PKCS_SIGNED_DATA
            && let Some(blob) = dir.get(pos + 8..pos + len)
        {
            content_info(blob, sig_ty, 0, &mut out);
        }
        pos += len.div_ceil(8) * 8;
    }
    out
}

/// A PKCS#7 ContentInfo holding SignedData: one signature, plus any nested in it.
fn content_info(blob: &[u8], sig_ty: &Arc<StructType>, depth: usize, out: &mut Vec<Value>) -> Option<()> {
    if depth > MAX_DEPTH {
        return None;
    }
    let ci = Reader::new(blob).expect(SEQUENCE)?;
    let mut ci = ci.children();
    ci.expect(OID)?;
    let signed = ci.expect(CTX0)?.children().expect(SEQUENCE)?;
    let mut sd = signed.children();
    sd.expect(INTEGER)?;
    sd.expect(SET)?;
    let content = sd.expect(SEQUENCE)?;
    let certs_elem = sd.optional(CTX0);
    sd.optional(CTX1);
    let signer_infos = sd.expect(SET)?;

    let (digest_alg, digest) = indirect_digest(&content).unwrap_or_default();
    let mut certs = Vec::new();
    if let Some(ce) = certs_elem {
        let mut r = ce.children();
        while let Some(c) = r.next() {
            if let Some(cert) = parse_cert(&c) {
                certs.push(cert);
            }
        }
    }
    let cert_ty = Arc::new(certificate_type());
    let all: Vec<Value> = certs.iter().map(|c| cert_value(c, &cert_ty).build()).collect();
    let mut infos = signer_infos.children();
    while let Some(si) = infos.next() {
        let mut s = si.children();
        s.expect(INTEGER);
        let Some(ias) = s.expect(SEQUENCE) else { continue };
        let mut ias = ias.children();
        let (Some(issuer), Some(serial)) = (ias.expect(SEQUENCE), ias.expect(INTEGER)) else { continue };
        let signer = certs.iter().find(|c| c.issuer_raw == issuer.raw && c.serial_raw == serial.body);
        let mut v = match signer {
            Some(c) => cert_value(c, sig_ty),
            None => sig_ty.value(),
        };
        v.int("verified", 0)
            .string("digest_alg", &digest_alg)
            .string("digest", &digest)
            .int("number_of_certificates", all.len() as i64)
            .set("certificates", array(all.clone()));
        out.push(v.build());
        // Nested signatures ride in the unauthenticated attributes.
        s.expect(SEQUENCE);
        s.optional(CTX0);
        s.expect(SEQUENCE);
        s.expect(OCTET_STRING);
        if let Some(unauth) = s.optional(CTX1) {
            let mut attrs = unauth.children();
            while let Some(attr) = attrs.next() {
                let mut a = attr.children();
                let Some(o) = a.expect(OID) else { continue };
                if der::oid(o.body) != NESTED_SIGNATURE {
                    continue;
                }
                if let Some(values) = a.expect(SET) {
                    let mut vals = values.children();
                    while let Some(nested) = vals.next() {
                        content_info(nested.raw, sig_ty, depth + 1, out);
                    }
                }
            }
        }
    }
    Some(())
}

/// The file digest Authenticode signed: (algorithm name, hex).
fn indirect_digest(content: &Elem) -> Option<(String, String)> {
    let mut c = content.children();
    c.expect(OID)?;
    let spc = c.expect(CTX0)?.children().expect(SEQUENCE)?;
    let mut spc = spc.children();
    spc.expect(SEQUENCE)?;
    let digest_info = spc.expect(SEQUENCE)?;
    let mut di = digest_info.children();
    let alg = di.expect(SEQUENCE)?.children().expect(OID)?;
    let digest = di.expect(OCTET_STRING)?;
    Some((der::algorithm_name(&der::oid(alg.body)).to_string(), hex(digest.body)))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::modules::pe::der::tests::{enc, oid_bytes};

    fn name(cn: &str) -> Vec<u8> {
        enc(SEQUENCE, &enc(SET, &enc(SEQUENCE, &[enc(OID, &oid_bytes("2.5.4.3")), enc(0x13, cn.as_bytes())].concat())))
    }

    fn cert(issuer: &str, subject: &str, serial: &[u8]) -> Vec<u8> {
        let alg = enc(SEQUENCE, &enc(OID, &oid_bytes("1.2.840.113549.1.1.11")));
        let validity = enc(SEQUENCE, &[enc(0x17, b"110615000000Z"), enc(0x17, b"300101000000Z")].concat());
        let tbs = enc(
            SEQUENCE,
            &[
                enc(CTX0, &enc(INTEGER, &[2])),
                enc(INTEGER, serial),
                alg.clone(),
                name(issuer),
                validity,
                name(subject),
                enc(SEQUENCE, &[]),
            ]
            .concat(),
        );
        enc(SEQUENCE, &[tbs, alg, enc(0x03, &[0])].concat())
    }

    /// A ContentInfo/SignedData with one signer, optionally nesting another blob.
    pub fn signed_data(subject: &str, serial: &[u8], nested: Option<Vec<u8>>) -> Vec<u8> {
        let c = cert("Test CA", subject, serial);
        let sha256 = enc(SEQUENCE, &enc(OID, &oid_bytes("2.16.840.1.101.3.4.2.1")));
        let digest_info = enc(SEQUENCE, &[sha256.clone(), enc(OCTET_STRING, &[0xAB; 4])].concat());
        let spc = enc(SEQUENCE, &[enc(SEQUENCE, &[]), digest_info].concat());
        let content = enc(SEQUENCE, &[enc(OID, &oid_bytes("1.3.6.1.4.1.311.2.1.4")), enc(CTX0, &spc)].concat());
        let ias = enc(SEQUENCE, &[name("Test CA"), enc(INTEGER, serial)].concat());
        let mut si = vec![enc(INTEGER, &[1]), ias, sha256.clone(), sha256, enc(OCTET_STRING, &[1])];
        if let Some(n) = nested {
            let attr = enc(SEQUENCE, &[enc(OID, &oid_bytes(NESTED_SIGNATURE)), enc(SET, &n)].concat());
            si.push(enc(CTX1, &attr));
        }
        let signer_info = enc(SEQUENCE, &si.concat());
        let sd = enc(
            SEQUENCE,
            &[enc(INTEGER, &[1]), enc(SET, &[]), content, enc(CTX0, &c), enc(SET, &signer_info)].concat(),
        );
        enc(SEQUENCE, &[enc(OID, &oid_bytes("1.2.840.113549.1.7.2")), enc(CTX0, &sd)].concat())
    }

    /// A security directory holding `blob` as one WIN_CERTIFICATE.
    pub fn win_certificate(blob: &[u8]) -> Vec<u8> {
        let len = 8 + blob.len();
        let mut out = (len as u32).to_le_bytes().to_vec();
        out.extend([0, 2, 2, 0]);
        out.extend_from_slice(blob);
        out.resize(len.div_ceil(8) * 8, 0);
        out
    }

    #[test]
    fn reads_signers_and_nested_signatures() {
        let inner = signed_data("Inner Signer", &[0x05, 0xe2], None);
        let outer = signed_data("Outer Signer", &[0x00, 0x77, 0x01], Some(inner));
        let dir = win_certificate(&outer);
        let ty = Arc::new(signature_type());
        let sigs = signatures(&dir, 0, dir.len(), &ty);
        assert_eq!(sigs.len(), 2);
        let field = |v: &Value, name: &str| {
            let slot = ty
                .fields
                .iter()
                .filter(|f| matches!(f.kind, crate::value::FieldKind::Value { .. }))
                .position(|f| f.name == name)
                .unwrap();
            v.field(slot)
        };
        assert_eq!(field(&sigs[0], "subject").as_bytes(), Some(&b"/CN=Outer Signer"[..]));
        assert_eq!(field(&sigs[0], "issuer").as_bytes(), Some(&b"/CN=Test CA"[..]));
        assert_eq!(field(&sigs[0], "serial").as_bytes(), Some(&b"77:01"[..]));
        assert_eq!(field(&sigs[0], "version").as_int(), Some(3));
        assert_eq!(field(&sigs[0], "algorithm").as_bytes(), Some(&b"sha256WithRSAEncryption"[..]));
        assert_eq!(field(&sigs[0], "not_before").as_int(), Some(1_308_096_000));
        assert_eq!(field(&sigs[0], "digest_alg").as_bytes(), Some(&b"sha256"[..]));
        assert_eq!(field(&sigs[0], "digest").as_bytes(), Some(&b"abababab"[..]));
        assert_eq!(field(&sigs[0], "number_of_certificates").as_int(), Some(1));
        assert_eq!(field(&sigs[0], "thumbprint").as_bytes().unwrap().len(), 40);
        assert_eq!(field(&sigs[1], "subject").as_bytes(), Some(&b"/CN=Inner Signer"[..]));
        let this = sigs[0].clone();
        let ctx = FnCtx { data: b"", this: &this };
        assert_eq!(valid_on(&ctx, &[Value::Int(1_400_000_000)]).as_int(), Some(1));
        assert_eq!(valid_on(&ctx, &[Value::Int(1)]).as_int(), Some(0));
        assert!(valid_on(&FnCtx { data: b"", this: &Value::Undef }, &[Value::Int(1)]).is_undef());
    }

    #[test]
    fn junk_is_ignored() {
        let ty = Arc::new(signature_type());
        assert!(signatures(b"", 0, 0, &ty).is_empty());
        assert!(signatures(&win_certificate(b"\x30\x03junk"), 0, 16, &ty).is_empty());
        assert!(signatures(&[4, 0, 0, 0, 0, 2, 2, 0], 0, 8, &ty).is_empty(), "a length under 8 stops");
    }
}
