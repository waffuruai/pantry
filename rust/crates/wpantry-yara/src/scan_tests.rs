use super::*;

#[test]
fn detects_file_types() {
    assert_eq!(FileType::detect(b"MZ\x90\x00"), FileType::Mz);
    assert_eq!(FileType::detect(b"\x7fELF\x02"), FileType::Elf);
    assert_eq!(FileType::detect(b"\xcf\xfa\xed\xfe"), FileType::MachO);
    assert_eq!(FileType::detect(b"\xca\xfe\xba\xbe"), FileType::MachO);
    assert_eq!(FileType::detect(b"#!/bin/sh"), FileType::Other);
    assert_eq!(FileType::detect(b""), FileType::Other);
}
