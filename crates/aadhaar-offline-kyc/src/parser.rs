//! Aadhaar Secure QR v2 payload parser.
//!
//! The QR content is a single base-10 digit string encoding a big integer
//! whose big-endian bytes are gzip-compressed (most v2 records). The
//! decompressed blob is a sequence of text fields delimited by `0xFF`,
//! followed by a JPEG photo, optional 32-byte SHA-256 mobile/email hashes,
//! and a 256-byte RSA-SHA256 signature at the tail.

use chrono::NaiveDate;
use flate2::read::GzDecoder;
use num_bigint::BigUint;
use std::io::Read;

use super::data::{AadhaarData, Gender};
use super::error::AadhaarError;

/// Number of delimited text fields before the photo.
const TEXT_FIELD_COUNT: usize = 16;
/// Size of the RSA-SHA256 signature at the tail of every payload.
const SIGNATURE_LEN: usize = 256;
/// Size of the SHA-256 mobile / email hashes.
const HASH_LEN: usize = 32;
/// Maximum number of bytes we will inflate from a gzip payload. A genuine Aadhaar
/// record is far smaller; the cap guards against a crafted "gzip bomb".
const MAX_DECOMPRESSED_SIZE: usize = 32 * 1024 * 1024;

/// Parses the raw QR text (a base-10 digit string) into an [`AadhaarData`].
pub fn parse_secure_qr_text(text: &str) -> Result<AadhaarData, AadhaarError> {
    let trimmed = text.trim();
    if trimmed.is_empty() || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Err(AadhaarError::NotDecimal);
    }
    let num = BigUint::parse_bytes(trimmed.as_bytes(), 10).ok_or(AadhaarError::NotDecimal)?;
    let bytes = num.to_bytes_be();
    parse_secure_qr_bytes(&bytes)
}

/// Parses a compressed payload (the BigUint → bytes form, before gzip
/// decompression). Falls back to raw parsing if the blob is not gzipped.
pub fn parse_secure_qr_bytes(bytes: &[u8]) -> Result<AadhaarData, AadhaarError> {
    // The v2 default is gzip. Only fall back to treating the blob as raw when it
    // genuinely lacks the gzip magic (older / unpacked traces). A blob that
    // *claims* to be gzip but fails to inflate is corrupt and must error rather
    // than be silently mis-parsed as raw bytes.
    let decompressed = if is_gzip(bytes) {
        try_gunzip(bytes)?
    } else {
        bytes.to_vec()
    };
    parse_decompressed(&decompressed)
}

/// Returns `true` when `bytes` begins with the gzip magic (`0x1F 0x8B`).
fn is_gzip(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1F && bytes[1] == 0x8B
}

fn try_gunzip(bytes: &[u8]) -> Result<Vec<u8>, AadhaarError> {
    gunzip_capped(bytes, MAX_DECOMPRESSED_SIZE)
}

/// Inflates a gzip stream, refusing to produce more than `limit` bytes. Reading
/// through `take(limit + 1)` lets us detect an over-limit (bomb) payload without
/// first allocating it in full.
fn gunzip_capped(bytes: &[u8], limit: usize) -> Result<Vec<u8>, AadhaarError> {
    let decoder = GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| AadhaarError::Gunzip(e.to_string()))?;
    if out.len() > limit {
        return Err(AadhaarError::DecompressionLimitExceeded { limit });
    }
    Ok(out)
}

/// Parses the already-decompressed payload blob.
pub fn parse_decompressed(raw: &[u8]) -> Result<AadhaarData, AadhaarError> {
    let (text_fields, tail) = split_text_fields(raw)?;

    if tail.len() < SIGNATURE_LEN {
        return Err(AadhaarError::PayloadTooShort { len: raw.len() });
    }
    let signature = tail[tail.len() - SIGNATURE_LEN..].to_vec();
    let tail_minus_sig = &tail[..tail.len() - SIGNATURE_LEN];

    let indicator = parse_indicator(text_fields[0])?;
    let mobile_present = indicator & 0b01 != 0;
    let email_present = indicator & 0b10 != 0;

    let mut hash_total = 0usize;
    if mobile_present {
        hash_total += HASH_LEN;
    }
    if email_present {
        hash_total += HASH_LEN;
    }
    if tail_minus_sig.len() < hash_total {
        return Err(AadhaarError::PayloadTooShort { len: raw.len() });
    }

    let photo_end = tail_minus_sig.len() - hash_total;
    let photo = &tail_minus_sig[..photo_end];
    let hashes_region = &tail_minus_sig[photo_end..];

    let (mobile_hash, email_hash) = match (mobile_present, email_present) {
        (true, true) => (
            Some(hashes_region[..HASH_LEN].to_vec()),
            Some(hashes_region[HASH_LEN..].to_vec()),
        ),
        (true, false) => (Some(hashes_region[..HASH_LEN].to_vec()), None),
        (false, true) => (None, Some(hashes_region[..HASH_LEN].to_vec())),
        (false, false) => (None, None),
    };

    let reference_id = utf8(text_fields[1], "reference_id")?;
    // The reference id is the last 4 Aadhaar digits followed by a timestamp, so
    // the first four characters must be ASCII digits.
    let last_four_aadhaar: String = reference_id.chars().take(4).collect();
    if last_four_aadhaar.len() != 4 || !last_four_aadhaar.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AadhaarError::InvalidReferenceId { raw: reference_id });
    }

    let dob = parse_dob(text_fields[3])?;
    let gender = Gender::parse_byte(text_fields[4]);

    Ok(AadhaarData {
        email_mobile_indicator: indicator,
        reference_id,
        last_four_aadhaar,
        name: utf8(text_fields[2], "name")?,
        dob,
        gender,
        care_of: utf8_opt(text_fields[5], "care_of")?,
        district: utf8_opt(text_fields[6], "district")?,
        landmark: utf8_opt(text_fields[7], "landmark")?,
        house: utf8_opt(text_fields[8], "house")?,
        location: utf8_opt(text_fields[9], "location")?,
        pincode: utf8_opt(text_fields[10], "pincode")?,
        post_office: utf8_opt(text_fields[11], "post_office")?,
        state: utf8_opt(text_fields[12], "state")?,
        street: utf8_opt(text_fields[13], "street")?,
        sub_district: utf8_opt(text_fields[14], "sub_district")?,
        village_town_city: utf8_opt(text_fields[15], "village_town_city")?,
        photo_jpeg: if photo.is_empty() {
            None
        } else {
            Some(photo.to_vec())
        },
        mobile_hash,
        email_hash,
        signature,
    })
}

/// Splits `raw` at the first [`TEXT_FIELD_COUNT`] `0xFF` delimiters. Returns
/// `(text_fields, tail)` where `tail` contains the photo, optional hashes,
/// and the trailing signature.
fn split_text_fields(raw: &[u8]) -> Result<(Vec<&[u8]>, &[u8]), AadhaarError> {
    let mut fields = Vec::with_capacity(TEXT_FIELD_COUNT);
    let mut start = 0;
    for (i, &b) in raw.iter().enumerate() {
        if b == 0xFF {
            fields.push(&raw[start..i]);
            start = i + 1;
            if fields.len() == TEXT_FIELD_COUNT {
                return Ok((fields, &raw[start..]));
            }
        }
    }
    Err(AadhaarError::InsufficientFields {
        expected: TEXT_FIELD_COUNT,
        got: fields.len(),
    })
}

fn parse_indicator(raw: &[u8]) -> Result<u8, AadhaarError> {
    let s = std::str::from_utf8(raw).map_err(|_| AadhaarError::InvalidIndicator {
        raw: format!("{raw:?}"),
    })?;
    s.trim()
        .parse::<u8>()
        .map_err(|_| AadhaarError::InvalidIndicator { raw: s.to_string() })
        .and_then(|v| {
            if v > 3 {
                Err(AadhaarError::InvalidIndicator { raw: s.to_string() })
            } else {
                Ok(v)
            }
        })
}

fn parse_dob(raw: &[u8]) -> Result<Option<NaiveDate>, AadhaarError> {
    let s = std::str::from_utf8(raw)
        .map_err(|_| AadhaarError::InvalidUtf8 { field: "dob" })?
        .trim();
    if s.is_empty() {
        return Ok(None);
    }
    // UIDAI emits `DD-MM-YYYY` in most regions; tolerate `/` separators and
    // `YYYY-MM-DD` ISO order too.
    let formats = ["%d-%m-%Y", "%d/%m/%Y", "%Y-%m-%d"];
    for fmt in formats {
        if let Ok(d) = NaiveDate::parse_from_str(s, fmt) {
            return Ok(Some(d));
        }
    }
    Err(AadhaarError::InvalidDate { raw: s.to_string() })
}

fn utf8(raw: &[u8], field: &'static str) -> Result<String, AadhaarError> {
    std::str::from_utf8(raw)
        .map(|s| s.to_string())
        .map_err(|_| AadhaarError::InvalidUtf8 { field })
}

/// Decode an optional address field. Empty → `None`; non-empty must be valid
/// UTF-8 (invalid bytes are reported, not silently dropped).
fn utf8_opt(raw: &[u8], field: &'static str) -> Result<Option<String>, AadhaarError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let s = std::str::from_utf8(raw).map_err(|_| AadhaarError::InvalidUtf8 { field })?;
    Ok(Some(s.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    /// Builds a synthetic decompressed Aadhaar payload for testing.
    struct Payload<'a> {
        indicator: &'a str,
        reference_id: &'a str,
        name: &'a str,
        dob: &'a str,
        gender: &'a str,
        care_of: &'a str,
        district: &'a str,
        landmark: &'a str,
        house: &'a str,
        location: &'a str,
        pincode: &'a str,
        post_office: &'a str,
        state: &'a str,
        street: &'a str,
        sub_district: &'a str,
        village_town_city: &'a str,
        photo: &'a [u8],
        mobile_hash: Option<&'a [u8]>,
        email_hash: Option<&'a [u8]>,
        signature: &'a [u8],
    }

    impl Payload<'_> {
        fn encode(&self) -> Vec<u8> {
            let mut out = Vec::new();
            let fields = [
                self.indicator.as_bytes(),
                self.reference_id.as_bytes(),
                self.name.as_bytes(),
                self.dob.as_bytes(),
                self.gender.as_bytes(),
                self.care_of.as_bytes(),
                self.district.as_bytes(),
                self.landmark.as_bytes(),
                self.house.as_bytes(),
                self.location.as_bytes(),
                self.pincode.as_bytes(),
                self.post_office.as_bytes(),
                self.state.as_bytes(),
                self.street.as_bytes(),
                self.sub_district.as_bytes(),
                self.village_town_city.as_bytes(),
            ];
            for f in fields {
                out.extend_from_slice(f);
                out.push(0xFF);
            }
            out.extend_from_slice(self.photo);
            if let Some(h) = self.mobile_hash {
                out.extend_from_slice(h);
            }
            if let Some(h) = self.email_hash {
                out.extend_from_slice(h);
            }
            out.extend_from_slice(self.signature);
            out
        }
    }

    fn sample() -> Payload<'static> {
        Payload {
            indicator: "3",
            reference_id: "1234202401011230500123",
            name: "RAVI KUMAR",
            dob: "01-01-1990",
            gender: "M",
            care_of: "S/O Suresh Kumar",
            district: "Bangalore Urban",
            landmark: "Near Park",
            house: "42",
            location: "Indiranagar",
            pincode: "560038",
            post_office: "HAL Airport",
            state: "Karnataka",
            street: "100ft Road",
            sub_district: "Bangalore East",
            village_town_city: "Bangalore",
            photo: b"\xFF\xD8\xFF\xE0JFIF-fake-jpeg-bytes\xFF\xD9",
            mobile_hash: Some(&[0x11u8; 32]),
            email_hash: Some(&[0x22u8; 32]),
            signature: &[0x33u8; 256],
        }
    }

    #[test]
    fn parses_fully_populated_payload() {
        let raw = sample().encode();
        let data = parse_decompressed(&raw).unwrap();
        assert_eq!(data.email_mobile_indicator, 3);
        assert_eq!(data.reference_id, "1234202401011230500123");
        assert_eq!(data.last_four_aadhaar, "1234");
        assert_eq!(data.name, "RAVI KUMAR");
        assert_eq!(data.dob, Some(NaiveDate::from_ymd_opt(1990, 1, 1).unwrap()));
        assert_eq!(data.gender, Some(Gender::Male));
        assert_eq!(data.pincode.as_deref(), Some("560038"));
        assert_eq!(data.village_town_city.as_deref(), Some("Bangalore"));
        assert_eq!(data.signature.len(), 256);
        assert_eq!(data.mobile_hash.as_ref().unwrap().len(), 32);
        assert_eq!(data.email_hash.as_ref().unwrap().len(), 32);
        assert!(data.photo_jpeg.as_ref().unwrap().starts_with(&[0xFF, 0xD8]));
    }

    #[test]
    fn indicator_0_has_no_hashes() {
        let mut p = sample();
        p.indicator = "0";
        p.mobile_hash = None;
        p.email_hash = None;
        let raw = p.encode();
        let data = parse_decompressed(&raw).unwrap();
        assert!(!data.mobile_declared());
        assert!(!data.email_declared());
        assert!(data.mobile_hash.is_none());
        assert!(data.email_hash.is_none());
    }

    #[test]
    fn indicator_1_has_only_mobile_hash() {
        let mut p = sample();
        p.indicator = "1";
        p.email_hash = None;
        let raw = p.encode();
        let data = parse_decompressed(&raw).unwrap();
        assert!(data.mobile_declared());
        assert!(!data.email_declared());
        assert_eq!(data.mobile_hash.as_ref().unwrap().len(), 32);
        assert!(data.email_hash.is_none());
    }

    #[test]
    fn indicator_2_has_only_email_hash() {
        let mut p = sample();
        p.indicator = "2";
        p.mobile_hash = None;
        let raw = p.encode();
        let data = parse_decompressed(&raw).unwrap();
        assert!(!data.mobile_declared());
        assert!(data.email_declared());
        assert!(data.mobile_hash.is_none());
        assert_eq!(data.email_hash.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn photo_bytes_with_internal_0xff_are_preserved() {
        let raw = sample().encode();
        let data = parse_decompressed(&raw).unwrap();
        let photo = data.photo_jpeg.unwrap();
        // The sample photo contains embedded 0xFF bytes — ensure they survive.
        assert!(photo.windows(2).any(|w| w == [0xFF, 0xD8]));
        assert!(photo.ends_with(&[0xFF, 0xD9]));
    }

    #[test]
    fn parses_gzipped_bytes() {
        let raw = sample().encode();
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&raw).unwrap();
        let compressed = enc.finish().unwrap();
        let data = parse_secure_qr_bytes(&compressed).unwrap();
        assert_eq!(data.name, "RAVI KUMAR");
    }

    #[test]
    fn parses_decimal_text_roundtrip() {
        let raw = sample().encode();
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&raw).unwrap();
        let compressed = enc.finish().unwrap();
        let num = BigUint::from_bytes_be(&compressed);
        let text = num.to_str_radix(10);
        let data = parse_secure_qr_text(&text).unwrap();
        assert_eq!(data.name, "RAVI KUMAR");
        assert_eq!(data.pincode.as_deref(), Some("560038"));
    }

    #[test]
    fn rejects_non_decimal_text() {
        assert!(matches!(
            parse_secure_qr_text("abc123").unwrap_err(),
            AadhaarError::NotDecimal
        ));
    }

    #[test]
    fn rejects_short_payload() {
        let err = parse_decompressed(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, AadhaarError::InsufficientFields { .. }));
    }

    #[test]
    fn rejects_invalid_dob() {
        let mut p = sample();
        p.dob = "not-a-date";
        let raw = p.encode();
        assert!(matches!(
            parse_decompressed(&raw).unwrap_err(),
            AadhaarError::InvalidDate { .. }
        ));
    }

    #[test]
    fn dob_iso_format_is_accepted() {
        let mut p = sample();
        p.dob = "1990-01-01";
        let raw = p.encode();
        let data = parse_decompressed(&raw).unwrap();
        assert_eq!(data.dob, Some(NaiveDate::from_ymd_opt(1990, 1, 1).unwrap()));
    }

    #[test]
    fn optional_empty_fields_map_to_none() {
        let mut p = sample();
        p.landmark = "";
        p.street = "";
        let raw = p.encode();
        let data = parse_decompressed(&raw).unwrap();
        assert!(data.landmark.is_none());
        assert!(data.street.is_none());
    }

    #[test]
    fn female_gender_parses() {
        let mut p = sample();
        p.gender = "F";
        let raw = p.encode();
        let data = parse_decompressed(&raw).unwrap();
        assert_eq!(data.gender, Some(Gender::Female));
    }

    #[test]
    fn transgender_parses() {
        let mut p = sample();
        p.gender = "T";
        let raw = p.encode();
        let data = parse_decompressed(&raw).unwrap();
        assert_eq!(data.gender, Some(Gender::Transgender));
    }

    #[test]
    fn multibyte_gender_is_rejected() {
        // More than one byte (or non-ASCII) must not be silently truncated.
        let mut p = sample();
        p.gender = "MM";
        let raw = p.encode();
        let data = parse_decompressed(&raw).unwrap();
        assert_eq!(data.gender, None);
    }

    #[test]
    fn malformed_reference_id_is_rejected() {
        let mut p = sample();
        p.reference_id = "AB12rest-of-id";
        let raw = p.encode();
        assert!(matches!(
            parse_decompressed(&raw).unwrap_err(),
            AadhaarError::InvalidReferenceId { .. }
        ));
    }

    #[test]
    fn gunzip_capped_rejects_bomb() {
        // 1000 highly-compressible bytes deflate small but inflate past a tiny
        // limit, so the cap must reject them rather than allocate the full output.
        let data = vec![0u8; 1000];
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&data).unwrap();
        let compressed = enc.finish().unwrap();
        assert!(matches!(
            gunzip_capped(&compressed, 10),
            Err(AadhaarError::DecompressionLimitExceeded { limit: 10 })
        ));
        // A limit large enough for the real output inflates normally.
        assert_eq!(gunzip_capped(&compressed, 1000).unwrap(), data);
    }

    #[test]
    fn corrupt_gzip_is_rejected_not_silently_raw() {
        // Gzip magic present but the stream is garbage → must error, not fall
        // back to parsing the raw bytes.
        let bytes = [0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef];
        assert!(matches!(
            parse_secure_qr_bytes(&bytes).unwrap_err(),
            AadhaarError::Gunzip(_)
        ));
    }

    #[test]
    fn invalid_utf8_address_field_is_reported() {
        // Build a payload with invalid UTF-8 in an optional address field
        // (district, field index 6) and confirm it is reported, not dropped.
        let mut out = Vec::new();
        let mut fields: Vec<Vec<u8>> = vec![
            b"0".to_vec(), // indicator 0 → no mobile/email hashes
            b"1234202401011230500123".to_vec(),
            b"RAVI KUMAR".to_vec(),
            b"01-01-1990".to_vec(),
            b"M".to_vec(),
            b"care".to_vec(),
            vec![0xFE, 0xFE], // invalid UTF-8 bytes (and not the 0xFF delimiter)
        ];
        while fields.len() < 16 {
            fields.push(b"x".to_vec());
        }
        for f in &fields {
            out.extend_from_slice(f);
            out.push(0xFF);
        }
        out.extend_from_slice(&[0u8; 256]); // signature
        assert!(matches!(
            parse_decompressed(&out).unwrap_err(),
            AadhaarError::InvalidUtf8 { field: "district" }
        ));
    }
}
