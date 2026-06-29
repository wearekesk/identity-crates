//! Ordered BER-TLV collection.
//!
//! A [`TlvSet`] is an ordered sequence of [`Tlv`] objects. Decoding a byte
//! string consumes successive TLV records until the buffer is exhausted (or a
//! malformed TLV stops the scan); encoding concatenates the byte form of each
//! record.

use thiserror::Error;

use crate::lds::tlv::Tlv;

/// Error type for [`TlvSet`] operations.
#[derive(Debug, Error)]
#[error("TLVSetError: {0}")]
pub struct TlvSetError(pub String);

/// Ordered collection of [`Tlv`] records.
#[derive(Default)]
pub struct TlvSet {
    tlvs: Vec<Tlv>,
}

impl TlvSet {
    /// Creates an empty [`TlvSet`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a [`TlvSet`] from the given ordered [`Tlv`] records.
    pub fn with_tlvs(tlvs: Vec<Tlv>) -> Self {
        Self { tlvs }
    }

    /// Decodes `encoded_data` as a sequence of BER-TLV records.
    ///
    /// Matches the reference behaviour of stopping the scan on the first decode
    /// error (no error is returned — malformed trailing bytes are ignored).
    pub fn decode(encoded_data: &[u8]) -> Self {
        let mut tlvs = Vec::new();
        let mut offset = 0;
        while offset < encoded_data.len() {
            match Tlv::decode(&encoded_data[offset..]) {
                Ok(decoded) => {
                    tlvs.push(Tlv::new(decoded.tag.value, decoded.value));
                    offset += decoded.encoded_len;
                }
                Err(_) => break,
            }
        }
        Self { tlvs }
    }

    /// Appends `tlv` to the set.
    pub fn add(&mut self, tlv: Tlv) {
        self.tlvs.push(tlv);
    }

    /// Concatenates the BER-TLV encoding of each contained record.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for tlv in &self.tlvs {
            out.extend_from_slice(&tlv.to_bytes());
        }
        out
    }

    /// Returns the number of records.
    pub fn len(&self) -> usize {
        self.tlvs.len()
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.tlvs.is_empty()
    }

    /// Returns the record at `index`.
    ///
    /// # Errors
    /// Returns [`TlvSetError`] if `index` is out of range.
    pub fn at(&self, index: usize) -> Result<&Tlv, TlvSetError> {
        self.tlvs
            .get(index)
            .ok_or_else(|| TlvSetError("Index out of bounds".into()))
    }

    /// Returns all contained records.
    pub fn all(&self) -> &[Tlv] {
        &self.tlvs
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_set_roundtrips() {
        let s = TlvSet::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.to_bytes(), Vec::<u8>::new());
    }

    #[test]
    fn add_and_get() {
        let mut s = TlvSet::new();
        s.add(Tlv::new(0x80, vec![0xAA, 0xBB]));
        s.add(Tlv::new(0x81, vec![0xCC]));
        assert_eq!(s.len(), 2);
        assert_eq!(s.at(0).unwrap().tag, 0x80);
        assert_eq!(s.at(1).unwrap().value, vec![0xCC]);
    }

    #[test]
    fn at_out_of_bounds_errors() {
        let s = TlvSet::new();
        assert!(s.at(0).is_err());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut s = TlvSet::new();
        s.add(Tlv::new(0x80, vec![0x01, 0x02]));
        s.add(Tlv::new(0x81, vec![0x03]));
        s.add(Tlv::new(0x82, vec![0x04, 0x05, 0x06]));

        let bytes = s.to_bytes();
        let decoded = TlvSet::decode(&bytes);
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded.at(0).unwrap().tag, 0x80);
        assert_eq!(decoded.at(1).unwrap().value, vec![0x03]);
        assert_eq!(decoded.at(2).unwrap().value, vec![0x04, 0x05, 0x06]);
    }

    #[test]
    fn decode_stops_on_malformed_trailer() {
        let mut s = TlvSet::new();
        s.add(Tlv::new(0x80, vec![0xFF]));
        let mut bytes = s.to_bytes();
        // Append garbage that isn't a valid TLV start.
        bytes.extend_from_slice(&[0xFF]); // length byte missing after a long tag would be invalid
        let decoded = TlvSet::decode(&bytes);
        assert_eq!(decoded.len(), 1);
    }

    #[test]
    fn with_tlvs_preserves_order() {
        let s = TlvSet::with_tlvs(vec![
            Tlv::new(0x80, vec![0x01]),
            Tlv::new(0x81, vec![0x02]),
        ]);
        assert_eq!(s.all().len(), 2);
        assert_eq!(s.all()[0].tag, 0x80);
        assert_eq!(s.all()[1].tag, 0x81);
    }
}
