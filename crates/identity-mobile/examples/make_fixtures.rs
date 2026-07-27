//! Builds the passport data groups and the LDS security object the tests verify.
//!
//! Run through `tests/fixtures/generate.sh`, which then has OpenSSL sign the security
//! object into a real CMS `SignedData` — the same shape a passport's EF.SOD carries.
//!
//! The data groups are built with `dmrtd`'s own TLV encoder rather than hand-rolled
//! bytes, so the fixture cannot drift from the encoding the parser expects.

use std::io::Write;

use dmrtd::lds::tlv::Tlv;
use sha2::{Digest, Sha256};

/// Tags from ICAO 9303 Part 10 / ISO 19794-5, matching `dmrtd`'s constants.
const DG1_TAG: u32 = 0x61;
const MRZ_TAG: u32 = 0x5F1F;
const DG2_TAG: u32 = 0x75;
const BIOMETRIC_INFORMATION_GROUP_TEMPLATE: u32 = 0x7F61;
const BIOMETRIC_INFORMATION_TEMPLATE: u32 = 0x7F60;
const BIOMETRIC_HEADER_TEMPLATE: u32 = 0xA1;
const BIOMETRIC_DATA_BLOCK: u32 = 0x5F2E;
const BIOMETRIC_INFORMATION_COUNT: u32 = 0x02;
const FACIAL_RECORD_VERSION: i32 = 0x3031_3000;

fn main() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&dir).expect("create fixtures directory");

    let dg1 = build_dg1();
    let dg2 = build_dg2();
    let lds = build_lds_security_object(&[(1, Sha256::digest(&dg1)), (2, Sha256::digest(&dg2))]);

    for (name, bytes) in [("dg1.bin", &dg1), ("dg2.bin", &dg2), ("lds.der", &lds)] {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).expect("create fixture");
        file.write_all(bytes).expect("write fixture");
        println!("{} ({} bytes)", path.display(), bytes.len());
    }
}

/// EF.DG1 wrapping a TD3 machine readable zone.
fn build_dg1() -> Vec<u8> {
    let line1 = pad("P<GBRSHARMA<<PRIYA<<<<<<<<<<<<<<<<<<<<<<<<<<");

    // Document number, nationality, date of birth, sex, date of expiry, then the
    // optional field — each with the check digit ICAO 9303 requires.
    let document_number = "123456789";
    let birth = "880314";
    let expiry = "300101";
    let optional = pad_to("", 14);

    let composite = format!(
        "{document_number}{}{birth}{}{expiry}{}{optional}{}",
        check_digit(document_number),
        check_digit(birth),
        check_digit(expiry),
        check_digit(&optional),
    );
    // Nationality deliberately differs from the issuing state (GBR, in line 1). They
    // match on most documents, which is exactly why a fixture where they match cannot
    // catch code that confuses the two.
    let line2 = format!(
        "{document_number}{}FRA{birth}{}F{expiry}{}{optional}{}{}",
        check_digit(document_number),
        check_digit(birth),
        check_digit(expiry),
        check_digit(&optional),
        check_digit(&composite),
    );

    assert_eq!(line1.len(), 44, "TD3 line 1 is 44 characters");
    assert_eq!(line2.len(), 44, "TD3 line 2 is 44 characters");

    let mrz = format!("{line1}{line2}");
    Tlv::encode(DG1_TAG, &Tlv::encode(MRZ_TAG, mrz.as_bytes()))
}

/// EF.DG2 carrying one facial image, per ISO/IEC 19794-5.
fn build_dg2() -> Vec<u8> {
    // A JPEG header is enough: nothing in the verification path decodes the image, and
    // a real photograph would make the fixture large for no gain.
    let jpeg: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];

    let mut record = Vec::new();
    record.extend_from_slice(b"FAC\0");
    record.extend_from_slice(&FACIAL_RECORD_VERSION.to_be_bytes());
    record.extend_from_slice(&0u32.to_be_bytes()); // length of record
    record.extend_from_slice(&1u16.to_be_bytes()); // number of facial images
    record.extend_from_slice(&0u32.to_be_bytes()); // facial record data length
    record.extend_from_slice(&0u16.to_be_bytes()); // feature points
    record.push(2); // gender
    record.push(0); // eye colour
    record.push(0); // hair colour
    record.extend_from_slice(&[0, 0, 0]); // feature mask
    record.extend_from_slice(&0u16.to_be_bytes()); // expression
    record.extend_from_slice(&[0, 0, 0]); // pose angle
    record.extend_from_slice(&[0, 0, 0]); // pose angle uncertainty
    record.push(0); // face image type
    record.push(0); // image data type: JPEG
    record.extend_from_slice(&600u16.to_be_bytes()); // width
    record.extend_from_slice(&800u16.to_be_bytes()); // height
    record.push(0); // colour space
    record.push(0); // source type
    record.extend_from_slice(&0u16.to_be_bytes()); // device type
    record.extend_from_slice(&0u16.to_be_bytes()); // quality
    record.extend_from_slice(jpeg);

    let mut template = Tlv::encode(BIOMETRIC_HEADER_TEMPLATE, &[]);
    template.extend_from_slice(&Tlv::encode(BIOMETRIC_DATA_BLOCK, &record));

    let mut group = Tlv::encode(BIOMETRIC_INFORMATION_COUNT, &[1]);
    group.extend_from_slice(&Tlv::encode(BIOMETRIC_INFORMATION_TEMPLATE, &template));

    Tlv::encode(
        DG2_TAG,
        &Tlv::encode(BIOMETRIC_INFORMATION_GROUP_TEMPLATE, &group),
    )
}

/// The `LDSSecurityObject` that EF.SOD signs (ICAO 9303 Part 10, Appendix D):
///
/// ```text
/// LDSSecurityObject ::= SEQUENCE {
///   version               INTEGER,
///   hashAlgorithm         AlgorithmIdentifier,
///   dataGroupHashValues   SEQUENCE OF DataGroupHash }
/// ```
fn build_lds_security_object(hashes: &[(u8, impl AsRef<[u8]>)]) -> Vec<u8> {
    // 2.16.840.1.101.3.4.2.1 — SHA-256.
    let sha256_oid = der(
        0x06,
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
    );
    let algorithm = der(0x30, &sha256_oid);

    let mut group_hashes = Vec::new();
    for (number, hash) in hashes {
        let mut entry = der(0x02, &[*number]);
        entry.extend_from_slice(&der(0x04, hash.as_ref()));
        group_hashes.extend_from_slice(&der(0x30, &entry));
    }

    let mut body = der(0x02, &[0x00]); // version 0
    body.extend_from_slice(&algorithm);
    body.extend_from_slice(&der(0x30, &group_hashes));

    der(0x30, &body)
}

/// Minimal DER: tag, length, value. Lengths here never exceed two bytes.
fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match value.len() {
        len if len < 0x80 => out.push(len as u8),
        len if len < 0x100 => out.extend_from_slice(&[0x81, len as u8]),
        len => out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xFF) as u8]),
    }
    out.extend_from_slice(value);
    out
}

/// The ICAO 9303 check digit: weights 7, 3, 1 repeating.
fn check_digit(input: &str) -> char {
    let total: u32 = input
        .chars()
        .zip([7, 3, 1].into_iter().cycle())
        .map(|(c, weight)| {
            let value = match c {
                '0'..='9' => c as u32 - '0' as u32,
                'A'..='Z' => c as u32 - 'A' as u32 + 10,
                '<' => 0,
                other => panic!("{other:?} is not an MRZ character"),
            };
            value * weight
        })
        .sum();

    char::from_digit(total % 10, 10).expect("a single digit")
}

fn pad(line: &str) -> String {
    pad_to(line, 44)
}

fn pad_to(value: &str, width: usize) -> String {
    let mut out = value.to_string();
    while out.len() < width {
        out.push('<');
    }
    out
}
