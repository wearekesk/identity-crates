//! EF.DG2 — Encoded face biometrics.
//!
//! Parses the Biometric Information Group Template (tag `7F61`) that wraps
//! an ISO 19794-5 facial record. Only the **first** Biometric Information
//! Template is inspected — this matches the reference behaviour.

use crate::lds::df1::dg::{parse_dg_content, DgTag};
use crate::lds::ef::{EfParseError, ElementaryFile};
use crate::lds::tlv::Tlv;

/// EF.DG2 file ID.
pub const EF_DG2_FID: u16 = 0x0102;
/// EF.DG2 short file ID.
pub const EF_DG2_SFI: u8 = 0x02;
/// EF.DG2 outer tag.
pub const EF_DG2_TAG: DgTag = DgTag(0x75);

const BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG: u32 = 0x7F61;
const BIOMETRIC_INFORMATION_TEMPLATE_TAG: u32 = 0x7F60;
const BIOMETRIC_HEADER_TEMPLATE_BASE_TAG: u32 = 0xA1;
const BIOMETRIC_DATA_BLOCK_TAG: u32 = 0x5F2E;
const BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG: u32 = 0x7F2E;
const BIOMETRIC_INFORMATION_COUNT_TAG: u32 = 0x02;
const SMT_TAG: u32 = 0x7D;

/// Expected facial record version number (`"010\0"` = `0x30313000`).
const VERSION_NUMBER: i32 = 0x3031_3000;

/// ISO 19794-5 facial image encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageType {
    Jpeg,
    Jpeg2000,
}

/// EF.DG2 — encoded face.
#[derive(Debug, Clone, Default)]
pub struct EfDG2 {
    encoded: Vec<u8>,

    pub version_number: i32,
    pub length_of_record: i32,
    pub number_of_facial_images: i32,
    pub facial_record_data_length: i32,
    pub nr_feature_points: i32,
    pub gender: i32,
    pub eye_color: i32,
    pub hair_color: i32,
    pub feature_mask: i32,
    pub expression: i32,
    pub pose_angle: i32,
    pub pose_angle_uncertainty: i32,
    pub face_image_type: i32,
    pub image_width: i32,
    pub image_height: i32,
    pub image_color_space: i32,
    pub source_type: i32,
    pub device_type: i32,
    pub quality: i32,

    image_data_type: Option<i32>,
    pub image_data: Option<Vec<u8>>,
}

impl EfDG2 {
    /// Parses EF.DG2 bytes.
    pub fn from_bytes(data: impl Into<Vec<u8>>) -> Result<Self, EfParseError> {
        let encoded = data.into();
        let body = parse_dg_content(&encoded, EF_DG2_TAG.value())?;

        let bigt = Tlv::decode(&body)
            .map_err(|e| EfParseError::new(format!("Invalid DG2 BIGT TLV: {e}")))?;
        if bigt.tag.value != BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG {
            return Err(EfParseError::new(format!(
                "Invalid object tag={:X}, expected tag={:X}",
                bigt.tag.value, BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG
            )));
        }

        let bict = Tlv::decode(&bigt.value)
            .map_err(|e| EfParseError::new(format!("Invalid DG2 BICT TLV: {e}")))?;
        if bict.tag.value != BIOMETRIC_INFORMATION_COUNT_TAG {
            return Err(EfParseError::new(format!(
                "Invalid object tag={:X}, expected tag={:X}",
                bict.tag.value, BIOMETRIC_INFORMATION_COUNT_TAG
            )));
        }
        if bict.value.is_empty() {
            return Err(EfParseError::new("DG2 BICT value is empty"));
        }
        let bit_count = bict.value[0] & 0xFF;

        let mut out = Self {
            encoded,
            ..Self::default()
        };
        if bit_count > 0 {
            // Only the first BIT is inspected — this matches the reference
            // behaviour and covers every known DG2 payload.
            out.read_bit(&bigt.value[bict.encoded_len..])?;
        }
        Ok(out)
    }

    fn read_bit(&mut self, stream: &[u8]) -> Result<(), EfParseError> {
        let tvl = Tlv::decode(stream)
            .map_err(|e| EfParseError::new(format!("Invalid DG2 BIT TLV: {e}")))?;
        if tvl.tag.value != BIOMETRIC_INFORMATION_TEMPLATE_TAG {
            return Err(EfParseError::new(format!(
                "Invalid object tag={:X}, expected tag={:X}",
                tvl.tag.value, BIOMETRIC_INFORMATION_TEMPLATE_TAG
            )));
        }

        let bht = Tlv::decode(&tvl.value)
            .map_err(|e| EfParseError::new(format!("Invalid DG2 BHT TLV: {e}")))?;

        if bht.tag.value == SMT_TAG {
            // Secure-messaging protected BIT — not yet supported (matches TODO).
            return Ok(());
        }
        if (bht.tag.value & 0xA0) == 0xA0 {
            let elements = read_bht(&tvl.value)?;
            self.read_biometric_data_block(&elements)?;
            return Ok(());
        }
        // Anything else is an unrecognized BIT structure — reject it rather
        // than silently succeeding.
        Err(EfParseError::new(format!(
            "Unrecognized DG2 BHT tag={:X}",
            bht.tag.value
        )))
    }

    fn read_biometric_data_block(
        &mut self,
        elements: &[crate::lds::tlv::DecodedTv],
    ) -> Result<(), EfParseError> {
        let first = elements
            .first()
            .ok_or_else(|| EfParseError::new("DG2 BDB: no elements"))?;
        if first.tag.value != BIOMETRIC_DATA_BLOCK_TAG
            && first.tag.value != BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG
        {
            return Err(EfParseError::new(format!(
                "Invalid object tag={:X}, expected {:X} or {:X}",
                first.tag.value, BIOMETRIC_DATA_BLOCK_TAG, BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG
            )));
        }

        let data = &first.value;
        // The fixed header up to (and including) the pose-angle-uncertainty
        // field occupies 34 bytes; `extract` indexes the slice directly, so a
        // shorter block would panic. Validate the minimum length upfront.
        if data.len() < 34
            || data[0] != b'F'
            || data[1] != b'A'
            || data[2] != b'C'
            || data[3] != 0x00
        {
            return Err(EfParseError::new("Biometric data block is invalid"));
        }

        let mut offset = 4;
        self.version_number = extract(data, offset, offset + 4);
        if self.version_number != VERSION_NUMBER {
            return Err(EfParseError::new("Version of Biometric data is not valid"));
        }
        offset += 4;

        self.length_of_record = extract(data, offset, offset + 4);
        offset += 4;
        self.number_of_facial_images = extract(data, offset, offset + 2);
        offset += 2;
        self.facial_record_data_length = extract(data, offset, offset + 4);
        offset += 4;
        self.nr_feature_points = extract(data, offset, offset + 2);
        offset += 2;
        self.gender = extract(data, offset, offset + 1);
        offset += 1;
        self.eye_color = extract(data, offset, offset + 1);
        offset += 1;
        self.hair_color = extract(data, offset, offset + 1);
        offset += 1;
        self.feature_mask = extract(data, offset, offset + 3);
        offset += 3;
        self.expression = extract(data, offset, offset + 2);
        offset += 2;
        self.pose_angle = extract(data, offset, offset + 3);
        offset += 3;
        self.pose_angle_uncertainty = extract(data, offset, offset + 3);
        offset += 3;
        // Skip 8 bytes per feature point (comment: features not handled).
        if self.nr_feature_points < 0 {
            return Err(EfParseError::new(
                "Negative number of feature points in biometric data block",
            ));
        }
        offset += (self.nr_feature_points as usize).saturating_mul(8);

        // The remaining static image-information fields occupy 12 bytes; a
        // truncated block would otherwise panic inside `extract`.
        if data.len() < offset + 12 {
            return Err(EfParseError::new("Truncated biometric data block"));
        }

        self.face_image_type = extract(data, offset, offset + 1);
        offset += 1;
        self.image_data_type = Some(extract(data, offset, offset + 1));
        offset += 1;
        self.image_width = extract(data, offset, offset + 2);
        offset += 2;
        self.image_height = extract(data, offset, offset + 2);
        offset += 2;
        self.image_color_space = extract(data, offset, offset + 1);
        offset += 1;
        self.source_type = extract(data, offset, offset + 1);
        offset += 1;
        self.device_type = extract(data, offset, offset + 2);
        offset += 2;
        self.quality = extract(data, offset, offset + 2);
        offset += 2;

        if offset <= data.len() {
            // The per-image facial record begins right after the fixed facial
            // header (FAC\0 (4) + version (4) + length_of_record (4) +
            // number_of_facial_images (2) = 14 bytes) and spans
            // `facial_record_data_length` bytes. Bound the image data by the end
            // of that record when the length is valid and in range; fall back to
            // the remainder of the block for absent/out-of-range lengths.
            const FACIAL_RECORD_BLOCK_START: usize = 14;
            let end = if self.facial_record_data_length > 0 {
                FACIAL_RECORD_BLOCK_START
                    .checked_add(self.facial_record_data_length as usize)
                    .filter(|&e| e >= offset && e <= data.len())
                    .unwrap_or(data.len())
            } else {
                data.len()
            };
            self.image_data = Some(data[offset..end].to_vec());
        }
        Ok(())
    }

    /// Returns the encoded image type if the BDB was successfully parsed and the
    /// `image_data_type` field holds a value defined by ISO 19794-5
    /// (`0` = JPEG, `1` = JPEG2000). Any other value yields `None` rather than
    /// being silently treated as JPEG2000.
    pub fn image_type(&self) -> Option<ImageType> {
        match self.image_data_type? {
            0 => Some(ImageType::Jpeg),
            1 => Some(ImageType::Jpeg2000),
            _ => None,
        }
    }
}

impl ElementaryFile for EfDG2 {
    const FID: u16 = EF_DG2_FID;
    const SFI: u8 = EF_DG2_SFI;

    fn to_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

fn read_bht(stream: &[u8]) -> Result<Vec<crate::lds::tlv::DecodedTv>, EfParseError> {
    let bht = Tlv::decode(stream)
        .map_err(|e| EfParseError::new(format!("Invalid DG2 BHT header: {e}")))?;
    if bht.tag.value != BIOMETRIC_HEADER_TEMPLATE_BASE_TAG {
        return Err(EfParseError::new(format!(
            "Invalid object tag={:X}, expected tag={:X}",
            bht.tag.value, BIOMETRIC_HEADER_TEMPLATE_BASE_TAG
        )));
    }
    let mut offset = bht.encoded_len;
    let mut out = Vec::new();
    while offset < stream.len() {
        let tlv = Tlv::decode(&stream[offset..])
            .map_err(|e| EfParseError::new(format!("Invalid DG2 BDB element TLV: {e}")))?;
        offset += tlv.encoded_len;
        out.push(tlv);
    }
    Ok(out)
}

/// Reads a big-endian signed integer from `data[start..end]`, matching the
/// reference `_extractContent` dispatch:
///   - size 1   → signed 8-bit
///   - size 2   → signed 16-bit
///   - size 3   → signed 24-bit (all three bytes, sign-extended to i32)
///   - size 4   → signed 32-bit
fn extract(data: &[u8], start: usize, end: usize) -> i32 {
    let size = end - start;
    match size {
        1 => data[start] as i8 as i32,
        2 => i16::from_be_bytes([data[start], data[start + 1]]) as i32,
        3 => {
            // Read all three bytes big-endian as an UNSIGNED 24-bit value.
            // These fields (notably `feature_mask`) are packed bit masks, so
            // sign-extending bit 23 would wrongly produce a negative value and
            // corrupt mask checks. The result always fits in a positive i32.
            ((data[start] as i32) << 16) | ((data[start + 1] as i32) << 8) | data[start + 2] as i32
        }
        4 => i32::from_be_bytes([
            data[start],
            data[start + 1],
            data[start + 2],
            data[start + 3],
        ]),
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal DG2 blob with a single facial image. Returns the full
    /// DG2 TLV bytes.
    fn build_minimal_dg2(
        jpeg_payload: &[u8],
        image_type: u8, // 0 = JPEG, 1 = JPEG2000
        width: u16,
        height: u16,
    ) -> Vec<u8> {
        // ------ Facial record (FAC marker + header + image) ------
        let mut bdb = Vec::new();
        bdb.extend_from_slice(b"FAC\0");
        bdb.extend_from_slice(&VERSION_NUMBER.to_be_bytes()); // version
        bdb.extend_from_slice(&0u32.to_be_bytes()); // length_of_record
        bdb.extend_from_slice(&1u16.to_be_bytes()); // number_of_facial_images
        bdb.extend_from_slice(&0u32.to_be_bytes()); // facial_record_data_length
        bdb.extend_from_slice(&0u16.to_be_bytes()); // nr_feature_points
        bdb.push(0); // gender
        bdb.push(0); // eye color
        bdb.push(0); // hair color
        bdb.extend_from_slice(&[0, 0, 0]); // feature mask (3 bytes)
        bdb.extend_from_slice(&0u16.to_be_bytes()); // expression
        bdb.extend_from_slice(&[0, 0, 0]); // pose angle
        bdb.extend_from_slice(&[0, 0, 0]); // pose angle uncertainty
                                           // (no feature points)
        bdb.push(0); // face_image_type
        bdb.push(image_type); // image_data_type
        bdb.extend_from_slice(&width.to_be_bytes()); // image_width
        bdb.extend_from_slice(&height.to_be_bytes()); // image_height
        bdb.push(0); // color space
        bdb.push(0); // source type
        bdb.extend_from_slice(&0u16.to_be_bytes()); // device type
        bdb.extend_from_slice(&0u16.to_be_bytes()); // quality
        bdb.extend_from_slice(jpeg_payload); // raw image data

        // ------ BIT contents: BHT (A1) + BDB (5F2E) ------
        let bht = Tlv::encode(BIOMETRIC_HEADER_TEMPLATE_BASE_TAG, &[]);
        let bdb_tlv = Tlv::encode(BIOMETRIC_DATA_BLOCK_TAG, &bdb);
        let mut bit_body = bht;
        bit_body.extend_from_slice(&bdb_tlv);

        // ------ BIT (7F60) ------
        let bit = Tlv::encode(BIOMETRIC_INFORMATION_TEMPLATE_TAG, &bit_body);

        // ------ BIGT = BICT (02) + BIT (7F60) ------
        let bict = Tlv::encode(BIOMETRIC_INFORMATION_COUNT_TAG, &[1u8]);
        let mut bigt_body = bict;
        bigt_body.extend_from_slice(&bit);
        let bigt = Tlv::encode(BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG, &bigt_body);

        // ------ Outer DG2 (0x75) ------
        Tlv::encode(EF_DG2_TAG.value(), &bigt)
    }

    #[test]
    fn parses_minimal_dg2_with_jpeg_payload() {
        let jpeg = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10]; // JPEG header bytes
        let dg2_bytes = build_minimal_dg2(&jpeg, 0, 320, 240);
        let dg = EfDG2::from_bytes(dg2_bytes.clone()).unwrap();

        assert_eq!(dg.version_number, VERSION_NUMBER);
        assert_eq!(dg.image_width, 320);
        assert_eq!(dg.image_height, 240);
        assert_eq!(dg.image_type(), Some(ImageType::Jpeg));
        assert_eq!(dg.image_data.as_ref().unwrap(), &jpeg);
        assert_eq!(dg.to_bytes(), dg2_bytes.as_slice());
    }

    #[test]
    fn parses_jpeg2000_image_type() {
        let blob = vec![0x00u8, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20]; // JP2 signature box
        let dg2_bytes = build_minimal_dg2(&blob, 1, 100, 50);
        let dg = EfDG2::from_bytes(dg2_bytes).unwrap();
        assert_eq!(dg.image_type(), Some(ImageType::Jpeg2000));
    }

    #[test]
    fn unknown_image_type_is_none() {
        // image_data_type = 2 is not defined by ISO 19794-5; must not default
        // to JPEG2000.
        let blob = vec![0xFFu8, 0xD8];
        let dg2_bytes = build_minimal_dg2(&blob, 2, 1, 1);
        let dg = EfDG2::from_bytes(dg2_bytes).unwrap();
        assert_eq!(dg.image_type(), None);
    }

    /// Builds a DG2 whose facial record sets an explicit
    /// `facial_record_data_length` and appends `trailing` junk bytes after the
    /// declared record end.
    fn build_dg2_with_record_len(
        image_payload: &[u8],
        facial_record_data_length: u32,
        trailing: &[u8],
    ) -> Vec<u8> {
        let mut bdb = Vec::new();
        bdb.extend_from_slice(b"FAC\0");
        bdb.extend_from_slice(&VERSION_NUMBER.to_be_bytes());
        bdb.extend_from_slice(&0u32.to_be_bytes()); // length_of_record
        bdb.extend_from_slice(&1u16.to_be_bytes()); // number_of_facial_images
        bdb.extend_from_slice(&facial_record_data_length.to_be_bytes());
        bdb.extend_from_slice(&0u16.to_be_bytes()); // nr_feature_points
        bdb.push(0); // gender
        bdb.push(0); // eye color
        bdb.push(0); // hair color
        bdb.extend_from_slice(&[0, 0, 0]); // feature mask
        bdb.extend_from_slice(&0u16.to_be_bytes()); // expression
        bdb.extend_from_slice(&[0, 0, 0]); // pose angle
        bdb.extend_from_slice(&[0, 0, 0]); // pose angle uncertainty
        bdb.push(0); // face_image_type
        bdb.push(0); // image_data_type = JPEG
        bdb.extend_from_slice(&1u16.to_be_bytes()); // width
        bdb.extend_from_slice(&1u16.to_be_bytes()); // height
        bdb.push(0); // color space
        bdb.push(0); // source type
        bdb.extend_from_slice(&0u16.to_be_bytes()); // device type
        bdb.extend_from_slice(&0u16.to_be_bytes()); // quality
        bdb.extend_from_slice(image_payload);
        bdb.extend_from_slice(trailing);

        let bht = Tlv::encode(BIOMETRIC_HEADER_TEMPLATE_BASE_TAG, &[]);
        let bdb_tlv = Tlv::encode(BIOMETRIC_DATA_BLOCK_TAG, &bdb);
        let mut bit_body = bht;
        bit_body.extend_from_slice(&bdb_tlv);
        let bit = Tlv::encode(BIOMETRIC_INFORMATION_TEMPLATE_TAG, &bit_body);
        let bict = Tlv::encode(BIOMETRIC_INFORMATION_COUNT_TAG, &[1u8]);
        let mut bigt_body = bict;
        bigt_body.extend_from_slice(&bit);
        let bigt = Tlv::encode(BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG, &bigt_body);
        Tlv::encode(EF_DG2_TAG.value(), &bigt)
    }

    #[test]
    fn image_data_is_bounded_by_record_length() {
        // The fixed header consumed before image data is 46 bytes; the facial
        // record begins at offset 14, so a 6-byte image gives a record length of
        // 46 - 14 + 6 = 38. Trailing junk after the record must be excluded.
        let image = vec![0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
        let trailing = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let dg2 = build_dg2_with_record_len(&image, 38, &trailing);
        let dg = EfDG2::from_bytes(dg2).unwrap();
        assert_eq!(dg.image_data.as_ref().unwrap(), &image);
    }

    #[test]
    fn image_data_falls_back_for_out_of_range_record_length() {
        // An absurd record length is ignored; image data falls back to the rest
        // of the block (image payload, here with no trailing bytes).
        let image = vec![0x01u8, 0x02, 0x03];
        let dg2 = build_dg2_with_record_len(&image, 0xFFFF_FFFF, &[]);
        let dg = EfDG2::from_bytes(dg2).unwrap();
        assert_eq!(dg.image_data.as_ref().unwrap(), &image);
    }

    #[test]
    fn rejects_unrecognized_bht_tag() {
        // BIT(7F60) whose first inner TLV has a tag that is neither the SMT tag
        // nor an A0-masked BHT — must be rejected, not silently accepted.
        let weird = Tlv::encode(0x80, &[0x00]);
        let bit = Tlv::encode(BIOMETRIC_INFORMATION_TEMPLATE_TAG, &weird);
        let bict = Tlv::encode(BIOMETRIC_INFORMATION_COUNT_TAG, &[1u8]);
        let mut bigt_body = bict;
        bigt_body.extend_from_slice(&bit);
        let bigt = Tlv::encode(BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG, &bigt_body);
        let dg2 = Tlv::encode(EF_DG2_TAG.value(), &bigt);
        let err = EfDG2::from_bytes(dg2).unwrap_err();
        assert!(err.0.contains("Unrecognized DG2 BHT tag"));
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        let dg2_bytes = build_minimal_dg2(&[0xFF, 0xD8], 0, 1, 1);
        // Rewrap with wrong outer tag.
        let body_start = 2; // 0x75 tag, then length byte(s) — for short length only
                            // Extract the inner body (skip the outer 0x75 tag + length).
                            // Simpler: rebuild with a different outer tag.
        let inner = &dg2_bytes[body_start..];
        let bogus = Tlv::encode(0x76, inner);
        assert!(EfDG2::from_bytes(bogus).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        // Build normally, then corrupt the version bytes.
        let jpeg = vec![0xFFu8, 0xD8];
        let mut bytes = build_minimal_dg2(&jpeg, 0, 1, 1);
        // Find the FAC marker and corrupt the version bytes that follow.
        let fac_pos = bytes.windows(4).position(|w| w == b"FAC\0").unwrap();
        let ver_pos = fac_pos + 4;
        bytes[ver_pos] = 0xDE;
        bytes[ver_pos + 1] = 0xAD;
        let err = EfDG2::from_bytes(bytes).unwrap_err();
        assert!(err.0.contains("Version"));
    }

    #[test]
    fn constants() {
        assert_eq!(EfDG2::FID, 0x0102);
        assert_eq!(EfDG2::SFI, 0x02);
        assert_eq!(EF_DG2_TAG.value(), 0x75);
    }
}
