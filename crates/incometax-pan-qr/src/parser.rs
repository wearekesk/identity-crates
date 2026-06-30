//! Top-level parser for the unpacked PAN Secure-QR byte stream.
//!
//! It parses the outer block, validates a few reserved fields, walks the control
//! blocks, and extracts the embedded image and PII.

use crate::enums::{SCBlobIdentifier, SecureCodeType};
use crate::error::PanQrError;
use crate::image_processor::ImageProcessor;
use crate::inflater;
use crate::structs::{PanInnerBlock, PanOuterBlock, ScBlob};
use crate::values::{
    is_whitelisted_version, ECC_KEY_1, ECC_KEY_2, WHITELISTED_VERSION_2, WHITELISTED_VERSION_4,
};

/// Personally-identifiable information extracted from a PAN QR.
///
/// The PII fields are stored as positional text elements in the QR payload. Two
/// layouts exist, distinguished by how many elements are present:
///
/// - 4 elements (individual): PAN, name, father's name, date of birth.
/// - 3 elements (organization): PAN, entity name, date of incorporation. A
///   company/organization QR carries no photo and no father's name / DOB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanPii {
    /// An individual PAN: PAN, name, father's name and date of birth.
    Individual {
        /// Permanent Account Number.
        pan: String,
        /// Whether `pan` passes structural PAN validation.
        pan_valid: bool,
        /// Holder name.
        name: String,
        /// Father's name.
        father_name: String,
        /// Date of birth.
        dob: String,
    },
    /// A company/organization PAN: PAN, entity name and date of incorporation.
    Organization {
        /// Permanent Account Number.
        pan: String,
        /// Whether `pan` passes structural PAN validation.
        pan_valid: bool,
        /// Entity name.
        name: String,
        /// Date of incorporation.
        date_of_incorporation: String,
    },
}

impl PanPii {
    /// The PAN from either variant.
    pub fn pan(&self) -> &str {
        match self {
            PanPii::Individual { pan, .. } | PanPii::Organization { pan, .. } => pan,
        }
    }

    /// The entity / person name from either variant.
    pub fn name(&self) -> &str {
        match self {
            PanPii::Individual { name, .. } | PanPii::Organization { name, .. } => name,
        }
    }

    /// The `pan_valid` flag from either variant.
    pub fn pan_valid(&self) -> bool {
        match self {
            PanPii::Individual { pan_valid, .. } | PanPii::Organization { pan_valid, .. } => {
                *pan_valid
            }
        }
    }
}

/// Parses an unpacked PAN-QR byte stream into its constituent parts.
pub struct Parser {
    /// The parsed outer block.
    pub pan_outer: PanOuterBlock,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
    /// The re-serialised message bytes (the signed data).
    pub message: Vec<u8>,
    /// The base64 ECC public key for this QR's version, if known.
    pub public_key: Option<&'static str>,
    /// The extracted (header-fixed) WebP image, if present.
    pub image: Option<Vec<u8>>,
    /// The extracted PII, if present.
    pub pii: Option<PanPii>,
}

impl Parser {
    /// Parses the outer block and pre-computes the signature, message bytes and
    /// public key.
    pub fn new(input: &[u8]) -> Result<Self, PanQrError> {
        let pan_outer = PanOuterBlock::parse(input)?;
        let signature = pan_outer.signature_data.clone();
        let message = pan_outer.message.build();
        let public_key = Self::set_key(pan_outer.message.reserved_1);
        Ok(Self {
            pan_outer,
            signature,
            message,
            public_key,
            image: None,
            pii: None,
        })
    }

    /// Validates a few fields in the outermost struct: `reserved_1` must be a
    /// whitelisted version and `reserved_3 <= 6`.
    pub fn validate(&self) -> bool {
        if !is_whitelisted_version(self.pan_outer.message.reserved_1) {
            return false;
        }
        if self.pan_outer.message.reserved_3 > 6 {
            return false;
        }
        true
    }

    /// Walks the control units in both block parts, dispatching `SCBlob`s.
    pub fn handle_control(&mut self) -> Result<(), PanQrError> {
        log::debug!(
            "Found {} block(s) in part 1",
            self.pan_outer.message.num_blocks_1
        );
        let blocks_1 = self.pan_outer.message.blocks_1.clone();
        for block in &blocks_1 {
            self.dispatch_block(block)?;
        }

        log::debug!(
            "Found {} blocks(s) in part 2",
            self.pan_outer.message.num_blocks_2
        );
        let blocks_2 = self.pan_outer.message.blocks_2.clone();
        for block in &blocks_2 {
            self.dispatch_block(block)?;
        }
        Ok(())
    }

    fn dispatch_block(&mut self, block: &PanInnerBlock) -> Result<(), PanQrError> {
        if SecureCodeType::from_u8(block.metadata.control_type) == Some(SecureCodeType::ScBlob) {
            self.handle_blob(&block.data)?;
        }
        Ok(())
    }

    /// Parses an `SCBlob` and routes it by identifier: `Image` -> fix header,
    /// `PII` -> zlib inflate then scan. `Mixed` blobs and unknown identifiers
    /// (e.g. `0xFF01`) are not parsed; they are skipped and logged rather than
    /// treated as errors, since no decodable sample is available.
    pub fn handle_blob(&mut self, blob: &[u8]) -> Result<(), PanQrError> {
        let parsed = ScBlob::parse(blob)?;
        match SCBlobIdentifier::from_u16(parsed.identifier) {
            Some(SCBlobIdentifier::Image) => {
                log::debug!("Image blob encountered!");
                self.image = Some(ImageProcessor::new(&parsed.data).fix_header()?);
            }
            Some(SCBlobIdentifier::Pii) => {
                log::debug!("PII blob encountered!");
                let inflated = inflater::inflate(&parsed.data)?;
                self.handle_pii(&inflated)?;
            }
            Some(SCBlobIdentifier::Mixed) => {
                log::debug!("Mixed SCBlob encountered! Parsing has not been implemented!");
            }
            None => {
                log::debug!("Unknown SCBlob encountered");
            }
        }
        Ok(())
    }

    /// Extracts PII as positional text elements: find each `08 02` marker, read
    /// the following length byte, then that many payload bytes.
    ///
    /// The element count selects the layout: 4 elements is an individual layout
    /// (PAN, name, father's name, DOB), 3 elements is an organization layout
    /// (PAN, entity name, date of incorporation). Both store elements in that
    /// fixed positional order.
    pub fn handle_pii(&mut self, data: &[u8]) -> Result<(), PanQrError> {
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        let mut i = 0usize;
        // Elements are a flat, sequential `08 02 <len> <payload>` series. After
        // a match we resume *past* the whole element (`i = end`) so that bytes
        // inside a payload (e.g. a name that happens to contain `08 02`) cannot
        // be misread as the start of the next element.
        while i + 2 < data.len() {
            if data[i] == 0x08 && data[i + 1] == 0x02 {
                let length = data[i + 2] as usize;
                let start = i + 3;
                let end = start + length;
                // A truncated element must be rejected, not silently clamped:
                // partial PII would otherwise be parsed as if complete.
                if end > data.len() {
                    return Err(PanQrError::UnexpectedEof("PII element"));
                }
                payloads.push(data[start..end].to_vec());
                i = end;
            } else {
                i += 1;
            }
        }

        let decode = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        self.pii = Some(if payloads.len() >= 4 {
            let pan = decode(&payloads[0]);
            let pan_valid = crate::check_pan_details(&pan).is_valid;
            PanPii::Individual {
                pan,
                pan_valid,
                name: decode(&payloads[1]),
                father_name: decode(&payloads[2]),
                dob: decode(&payloads[3]),
            }
        } else if payloads.len() == 3 {
            let pan = decode(&payloads[0]);
            let pan_valid = crate::check_pan_details(&pan).is_valid;
            PanPii::Organization {
                pan,
                pan_valid,
                name: decode(&payloads[1]),
                date_of_incorporation: decode(&payloads[2]),
            }
        } else {
            return Err(PanQrError::MissingPii);
        });
        Ok(())
    }

    /// Selects the ECC public key for the QR's version: `WHITELISTED_VERSION_2`
    /// -> [`ECC_KEY_1`], `WHITELISTED_VERSION_4` -> [`ECC_KEY_2`], else `None`.
    pub fn set_key(reserved_1: u32) -> Option<&'static str> {
        if WHITELISTED_VERSION_2.contains(&reserved_1) {
            Some(ECC_KEY_1)
        } else if WHITELISTED_VERSION_4.contains(&reserved_1) {
            Some(ECC_KEY_2)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_key_selects_correctly() {
        assert_eq!(Parser::set_key(0x1E), Some(ECC_KEY_1));
        assert_eq!(Parser::set_key(0x20), Some(ECC_KEY_1));
        assert_eq!(Parser::set_key(0x1F), Some(ECC_KEY_2));
        assert_eq!(Parser::set_key(0x21), Some(ECC_KEY_2));
        assert_eq!(Parser::set_key(0x9990), None);
        assert_eq!(Parser::set_key(0xDEAD), None);
    }

    fn build_outer(reserved_1: u32, reserved_3: u16) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(0x03); // code_type
        data.push(0x00); // reserved_0
        data.extend_from_slice(&reserved_1.to_be_bytes());
        data.push(0x00); // reserved_2
        data.extend_from_slice(&reserved_3.to_be_bytes());
        data.push(0x00); // num_blocks_1
        data.push(0x00); // num_blocks_2
        data.push(0x01); // reserved_4
        data.push(0x00); // signature_scheme
        data.extend_from_slice(&[0x00, 0x00]); // padding
        data.extend_from_slice(&0u16.to_be_bytes()); // signature_length
        data
    }

    #[test]
    fn validate_accepts_whitelisted() {
        let p = Parser::new(&build_outer(0x1E, 6)).unwrap();
        assert!(p.validate());
    }

    #[test]
    fn validate_rejects_bad_version() {
        let p = Parser::new(&build_outer(0xDEAD, 1)).unwrap();
        assert!(!p.validate());
    }

    #[test]
    fn validate_rejects_reserved_3_over_6() {
        let p = Parser::new(&build_outer(0x1E, 7)).unwrap();
        assert!(!p.validate());
    }

    #[test]
    fn handle_pii_extracts_four_elements() {
        // Four `08 02 <len> <payload>` markers.
        let mut data = Vec::new();
        for s in [
            b"ABCPE1234F".as_slice(),
            b"JOHN DOE",
            b"RICHARD DOE",
            b"01/01/1990",
        ] {
            data.push(0x08);
            data.push(0x02);
            data.push(s.len() as u8);
            data.extend_from_slice(s);
        }
        // Parser needs a real outer block to construct; build a minimal one and
        // then exercise handle_pii directly.
        let mut p = Parser::new(&build_outer(0x1E, 1)).unwrap();
        p.handle_pii(&data).unwrap();
        let pii = p.pii.unwrap();
        assert!(pii.pan_valid());
        assert_eq!(pii.pan(), "ABCPE1234F");
        assert_eq!(pii.name(), "JOHN DOE");
        let PanPii::Individual {
            pan,
            name,
            father_name,
            dob,
            ..
        } = pii
        else {
            panic!("expected an individual PII layout");
        };
        assert_eq!(pan, "ABCPE1234F");
        assert_eq!(name, "JOHN DOE");
        assert_eq!(father_name, "RICHARD DOE");
        assert_eq!(dob, "01/01/1990");
    }

    #[test]
    fn handle_pii_three_elements_is_organization() {
        // Three `08 02 <len> <payload>` markers: PAN, entity name, date of
        // incorporation.
        let mut data = Vec::new();
        for s in [
            b"ABCCE1234F".as_slice(),
            b"ACME WIDGETS PRIVATE LIMITED",
            b"15/08/1947",
        ] {
            data.push(0x08);
            data.push(0x02);
            data.push(s.len() as u8);
            data.extend_from_slice(s);
        }
        let mut p = Parser::new(&build_outer(0x1E, 1)).unwrap();
        p.handle_pii(&data).unwrap();
        let pii = p.pii.unwrap();
        assert!(pii.pan_valid());
        assert_eq!(pii.pan(), "ABCCE1234F");
        assert_eq!(pii.name(), "ACME WIDGETS PRIVATE LIMITED");
        let PanPii::Organization {
            pan,
            name,
            date_of_incorporation,
            ..
        } = pii
        else {
            panic!("expected an organization PII layout");
        };
        assert_eq!(pan, "ABCCE1234F");
        assert_eq!(name, "ACME WIDGETS PRIVATE LIMITED");
        assert_eq!(date_of_incorporation, "15/08/1947");
    }

    #[test]
    fn handle_pii_too_few_is_err() {
        let data = [0x08u8, 0x02, 0x01, b'X'];
        let mut p = Parser::new(&build_outer(0x1E, 1)).unwrap();
        assert!(p.handle_pii(&data).is_err());
    }

    #[test]
    fn handle_pii_truncated_element_is_err() {
        // Marker claims a 5-byte payload but only 1 byte follows: a truncated
        // element must be rejected, not silently clamped to the buffer end.
        let data = [0x08u8, 0x02, 0x05, b'X'];
        let mut p = Parser::new(&build_outer(0x1E, 1)).unwrap();
        assert!(matches!(
            p.handle_pii(&data),
            Err(PanQrError::UnexpectedEof("PII element"))
        ));
    }
}
