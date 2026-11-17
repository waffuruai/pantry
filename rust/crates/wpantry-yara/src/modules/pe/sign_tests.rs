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
    let sd =
        enc(SEQUENCE, &[enc(INTEGER, &[1]), enc(SET, &[]), content, enc(CTX0, &c), enc(SET, &signer_info)].concat());
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
