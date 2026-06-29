//! BER-TLV encoding and decoding.
//!
//! Implements the subset of BER-TLV required by ISO/IEC 7816-4 and ICAO 9303:
//! - Tag encoding/decoding (single-byte and multi-byte BER forms)
//! - Length encoding/decoding (short form and long form up to 3 length bytes)
//! - Full TLV encode/decode round-trips

use thiserror::Error;

use crate::utils::{byte_count, int_to_bin};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during TLV encoding or decoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TlvError {
    #[error("Can't encode negative or greater than 16 777 215 length")]
    LengthTooLarge,

    #[error("Can't decode empty encodedTag")]
    EmptyTag,

    #[error("Invalid encoded tag")]
    InvalidTag,

    #[error("Can't decode empty encodedLength")]
    EmptyLength,

    #[error("Invalid encoded length")]
    InvalidLength,

    #[error("Encoded length is too big")]
    LengthTooBig,

    /// BER indefinite-length form (`0x80`) is not permitted in the DER subset
    /// used by ICAO 9303 / ISO 7816-4.
    #[error("Indefinite length (0x80) is not allowed")]
    IndefiniteLength,

    /// Returned when the declared value length exceeds the available bytes
    /// (mirrors the `RangeError` thrown by `Uint8List.sublist`).
    #[error("Not enough data to decode TLV value")]
    NotEnoughData,
}

// ---------------------------------------------------------------------------
// Decoded-result types
// ---------------------------------------------------------------------------

/// A decoded BER tag together with the number of bytes it occupied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTag {
    /// Numeric tag value.
    pub value: u32,
    /// Number of bytes the encoded tag consumed.
    pub encoded_len: usize,
}

/// A decoded BER length together with the number of bytes it occupied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLen {
    /// Numeric length value.
    pub value: usize,
    /// Number of bytes the encoded length consumed.
    pub encoded_len: usize,
}

/// A decoded BER-TLV tag-value pair.
#[derive(Debug, Clone)]
pub struct DecodedTv {
    /// Decoded tag.
    pub tag: DecodedTag,
    /// Raw value bytes.
    pub value: Vec<u8>,
    /// Total bytes consumed (tag bytes + length bytes + value bytes).
    pub encoded_len: usize,
}

/// A decoded BER-TLV tag-length pair (without the value bytes).
#[derive(Debug, Clone)]
pub struct DecodedTl {
    /// Decoded tag.
    pub tag: DecodedTag,
    /// Decoded length.
    pub length: DecodedLen,
    /// Total bytes consumed (tag bytes + length bytes).
    pub encoded_len: usize,
}

// ---------------------------------------------------------------------------
// TlvEmpty
// ---------------------------------------------------------------------------

/// A TLV object with a fixed tag and an empty (zero-length) value.
pub struct TlvEmpty {
    /// Tag value.
    pub tag: u32,
}

impl TlvEmpty {
    /// Creates a new [`TlvEmpty`] with the given `tag`.
    pub fn new(tag: u32) -> Self {
        Self { tag }
    }

    /// Returns the BER-TLV encoding of this empty object: `encode(tag, &[])`.
    pub fn to_bytes(&self) -> Vec<u8> {
        Tlv::encode(self.tag, &[])
    }
}

// ---------------------------------------------------------------------------
// Tlv
// ---------------------------------------------------------------------------

/// BER-TLV object: a tag and an associated value byte-string.
pub struct Tlv {
    /// Tag value.
    pub tag: u32,
    /// Value bytes.
    pub value: Vec<u8>,
}

impl Tlv {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Creates a new [`Tlv`] from a tag and raw value bytes.
    pub fn new(tag: u32, value: Vec<u8>) -> Self {
        Self { tag, value }
    }

    /// Decodes a [`Tlv`] from a BER-TLV encoded byte slice.
    ///
    /// # Errors
    /// Returns [`TlvError`] if the slice is empty or the encoding is invalid.
    pub fn from_bytes(encoded_tlv: &[u8]) -> Result<Self, TlvError> {
        let tv = Self::decode(encoded_tlv)?;
        Ok(Self::new(tv.tag.value, tv.value))
    }

    /// Constructs a [`Tlv`] from `tag` and an integer `n` serialised as
    /// big-endian bytes (leading zeros stripped, minimum 1 byte).
    pub fn from_int_value(tag: u32, n: u64) -> Self {
        Self::new(tag, int_to_bin(n, 1))
    }

    // -----------------------------------------------------------------------
    // Instance methods
    // -----------------------------------------------------------------------

    /// Returns the BER-TLV encoding of this object.
    pub fn to_bytes(&self) -> Vec<u8> {
        Self::encode(self.tag, &self.value)
    }

    // -----------------------------------------------------------------------
    // Static encode helpers
    // -----------------------------------------------------------------------

    /// Returns the BER-TLV encoding of `tag` and `data`.
    ///
    /// # Panics
    /// Panics if `data.len()` exceeds 16 777 215 (extremely unlikely in
    /// practice; the same constraint exists in the reference).
    pub fn encode(tag: u32, data: &[u8]) -> Vec<u8> {
        let t = Self::encode_tag(tag);
        let l = Self::encode_length(data.len())
            .expect("data length exceeds maximum BER-TLV encodable length (16 777 215)");
        let mut out = Vec::with_capacity(t.len() + l.len() + data.len());
        out.extend_from_slice(&t);
        out.extend_from_slice(&l);
        out.extend_from_slice(data);
        out
    }

    /// Returns the BER-TLV encoding of `tag` and the big-endian bytes of `n`.
    pub fn encode_int_value(tag: u32, n: u64) -> Vec<u8> {
        Self::from_int_value(tag, n).to_bytes()
    }

    // -----------------------------------------------------------------------
    // Static decode helpers
    // -----------------------------------------------------------------------

    /// Decodes a BER-TLV tag-value pair from `encoded_tlv`.
    ///
    /// Returns the tag, value bytes, and total number of bytes consumed
    /// (tag + length + value).
    ///
    /// # Errors
    /// - [`TlvError::EmptyTag`] — `encoded_tlv` is empty.
    /// - [`TlvError::InvalidTag`] — multi-byte tag encoding is truncated.
    /// - [`TlvError::EmptyLength`] — no bytes remain for the length field.
    /// - [`TlvError::InvalidLength`] — long-form length is truncated.
    /// - [`TlvError::LengthTooBig`] — long-form length byte-count exceeds 3.
    /// - [`TlvError::NotEnoughData`] — declared value length exceeds available data.
    pub fn decode(encoded_tlv: &[u8]) -> Result<DecodedTv, TlvError> {
        let tl = Self::decode_tag_and_length(encoded_tlv)?;
        let end = tl.encoded_len + tl.length.value;
        if end > encoded_tlv.len() {
            return Err(TlvError::NotEnoughData);
        }
        let data = encoded_tlv[tl.encoded_len..end].to_vec();
        Ok(DecodedTv {
            tag: tl.tag,
            value: data,
            encoded_len: end,
        })
    }

    /// Decodes a BER-TLV tag and length from `encoded`.
    ///
    /// Returns both decoded fields and the combined number of bytes consumed.
    pub fn decode_tag_and_length(encoded: &[u8]) -> Result<DecodedTl, TlvError> {
        let tag = Self::decode_tag(encoded)?;
        let len = Self::decode_length(&encoded[tag.encoded_len..])?;
        let total = tag.encoded_len + len.encoded_len;
        Ok(DecodedTl {
            tag,
            length: len,
            encoded_len: total,
        })
    }

    // -----------------------------------------------------------------------
    // Tag encode / decode
    // -----------------------------------------------------------------------

    /// Returns the BER encoding of `tag` as big-endian bytes (minimum 1 byte).
    /// Writes `byteCount(tag)` big-endian bytes, falling back to a single
    /// `0x00` byte when `tag == 0`.
    pub fn encode_tag(tag: u32) -> Vec<u8> {
        let n = tag as u64;
        let bc = byte_count(n);
        let count = if bc == 0 { 1 } else { bc };
        let mut out = vec![0u8; count];
        for i in 0..bc {
            let pos = 8 * (bc - i - 1);
            out[i] = ((n >> pos) & 0xFF) as u8;
        }
        out
    }

    /// Decodes a BER-TLV tag from `encoded_tag`.
    ///
    /// - **Single-byte form**: used when `encoded_tag[0] & 0x1F != 0x1F`.
    /// - **Multi-byte form**: used when `encoded_tag[0] & 0x1F == 0x1F`;
    ///   subsequent bytes with MSB set are continuation bytes; the first byte
    ///   with MSB clear is the last tag byte.
    ///
    /// # Errors
    /// - [`TlvError::EmptyTag`] — `encoded_tag` is empty.
    /// - [`TlvError::InvalidTag`] — multi-byte tag is truncated.
    pub fn decode_tag(encoded_tag: &[u8]) -> Result<DecodedTag, TlvError> {
        if encoded_tag.is_empty() {
            return Err(TlvError::EmptyTag);
        }

        let first_byte = encoded_tag[0];
        let mut offset = 1usize;

        let tag_value: u32 = if (first_byte & 0x1F) == 0x1F {
            // Multi-byte BER tag.
            if offset >= encoded_tag.len() {
                return Err(TlvError::InvalidTag);
            }

            let mut tag = first_byte as u32; // store first byte including class/constructed bits
            let mut b = encoded_tag[offset];
            offset += 1;

            // Continuation bytes have MSB set. Preserve the raw bytes
            // (including the MSB) so the tag round-trips through `encode_tag`.
            // Each appended byte shifts `tag` left by 8; reject tags that would
            // not fit in the u32 representation rather than truncating silently.
            while (b & 0x80) == 0x80 {
                if offset >= encoded_tag.len() {
                    return Err(TlvError::InvalidTag);
                }
                if tag > (u32::MAX >> 8) {
                    return Err(TlvError::InvalidTag);
                }
                tag = (tag << 8) | (b as u32);
                b = encoded_tag[offset];
                offset += 1;
            }

            // Last byte has MSB clear.
            if tag > (u32::MAX >> 8) {
                return Err(TlvError::InvalidTag);
            }
            tag = (tag << 8) | (b as u32);
            tag
        } else {
            // Single-byte tag.
            first_byte as u32
        };

        Ok(DecodedTag {
            value: tag_value,
            encoded_len: offset,
        })
    }

    // -----------------------------------------------------------------------
    // Length encode / decode
    // -----------------------------------------------------------------------

    /// Returns the BER encoding of `length`.
    ///
    /// - **Short form** (`length < 0x80`): one byte `[length]`.
    /// - **Long form** (`length >= 0x80`): `[0x80 | byteCount, ...big-endian bytes]`.
    ///
    /// # Errors
    /// - [`TlvError::LengthTooLarge`] — `length > 0xFFFFFF`.
    pub fn encode_length(length: usize) -> Result<Vec<u8>, TlvError> {
        if length > 0xFF_FFFF {
            return Err(TlvError::LengthTooLarge);
        }

        let bc = byte_count(length as u64);
        // Allocate 1 byte for short form, or `bc + 1` bytes for long form.
        // Special case: length == 0 → bc == 0, but we still need 1 byte.
        let size = bc + if bc == 0 || length >= 0x80 { 1 } else { 0 };
        let mut out = vec![0u8; size];

        if length < 0x80 {
            // Short form
            out[0] = length as u8;
        } else {
            // Long form
            out[0] = (bc as u8) | 0x80;
            for i in 0..bc {
                let pos = 8 * (bc - i - 1);
                out[i + 1] = ((length >> pos) & 0xFF) as u8;
            }
        }

        Ok(out)
    }

    /// Decodes a BER-encoded length from `encoded_length`.
    ///
    /// - **Short form**: MSB of first byte is 0 → `(first_byte, 1 byte consumed)`.
    /// - **Long form**: MSB of first byte is 1 → next `first_byte & 0x7F` bytes
    ///   are the big-endian length value (max 3 such bytes).
    ///
    /// # Errors
    /// - [`TlvError::EmptyLength`] — `encoded_length` is empty.
    /// - [`TlvError::IndefiniteLength`] — the BER indefinite-length marker
    ///   `0x80` (forbidden in DER) was encountered.
    /// - [`TlvError::LengthTooBig`] — declared byte-count of length > 3.
    /// - [`TlvError::InvalidLength`] — `encoded_length` is truncated.
    pub fn decode_length(encoded_length: &[u8]) -> Result<DecodedLen, TlvError> {
        if encoded_length.is_empty() {
            return Err(TlvError::EmptyLength);
        }

        let first = encoded_length[0];

        if (first & 0x80) == 0x80 {
            // Long form: lower 7 bits = number of subsequent length bytes.
            let num_len_bytes = (first & 0x7F) as usize;
            if num_len_bytes == 0 {
                // 0x80 on its own is the BER indefinite-length marker, which is
                // forbidden in DER — reject rather than treating it as length 0.
                return Err(TlvError::IndefiniteLength);
            }
            if num_len_bytes > 3 {
                return Err(TlvError::LengthTooBig);
            }

            let total_bytes = 1 + num_len_bytes;
            if total_bytes > encoded_length.len() {
                return Err(TlvError::InvalidLength);
            }

            let mut length = 0usize;
            for i in 1..total_bytes {
                length = length * 0x100 + (encoded_length[i] as usize);
            }

            Ok(DecodedLen {
                value: length,
                encoded_len: total_bytes,
            })
        } else {
            // Short form
            Ok(DecodedLen {
                value: first as usize,
                encoded_len: 1,
            })
        }
    }
}

// `byte_count` and `int_to_bin` are shared with the rest of the crate; see
// [`crate::utils`]. They were previously duplicated here.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // encode_length
    // -----------------------------------------------------------------------

    #[test]
    fn encode_length_zero() {
        assert_eq!(Tlv::encode_length(0).unwrap(), vec![0x00]);
    }

    #[test]
    fn encode_length_short_form_0x7f() {
        assert_eq!(Tlv::encode_length(0x7F).unwrap(), vec![0x7F]);
    }

    #[test]
    fn encode_length_long_form_0x80() {
        assert_eq!(Tlv::encode_length(0x80).unwrap(), vec![0x81, 0x80]);
    }

    #[test]
    fn encode_length_long_form_1999() {
        // 1999 = 0x07CF
        assert_eq!(Tlv::encode_length(1999).unwrap(), vec![0x82, 0x07, 0xCF]);
    }

    #[test]
    fn encode_length_long_form_0x8000() {
        assert_eq!(Tlv::encode_length(0x8000).unwrap(), vec![0x82, 0x80, 0x00]);
    }

    #[test]
    fn encode_length_long_form_0x800000() {
        assert_eq!(
            Tlv::encode_length(0x80_0000).unwrap(),
            vec![0x83, 0x80, 0x00, 0x00]
        );
    }

    #[test]
    fn encode_length_too_large_errors() {
        assert_eq!(
            Tlv::encode_length(0x1000_0000).unwrap_err(),
            TlvError::LengthTooLarge
        );
    }

    // -----------------------------------------------------------------------
    // decode_length
    // -----------------------------------------------------------------------

    #[test]
    fn decode_length_short_form_zero() {
        let dl = Tlv::decode_length(&[0x00]).unwrap();
        assert_eq!(dl.value, 0x00);
        assert_eq!(dl.encoded_len, 1);
    }

    #[test]
    fn decode_length_short_form_0x0f() {
        let dl = Tlv::decode_length(&[0x0F]).unwrap();
        assert_eq!(dl.value, 0x0F);
        assert_eq!(dl.encoded_len, 1);
    }

    #[test]
    fn decode_length_short_form_0x10() {
        let dl = Tlv::decode_length(&[0x10]).unwrap();
        assert_eq!(dl.value, 0x10);
        assert_eq!(dl.encoded_len, 1);
    }

    #[test]
    fn decode_length_short_form_0x7f() {
        let dl = Tlv::decode_length(&[0x7F]).unwrap();
        assert_eq!(dl.value, 0x7F);
        assert_eq!(dl.encoded_len, 1);
    }

    #[test]
    fn decode_length_long_form_0x80() {
        let dl = Tlv::decode_length(&[0x81, 0x80]).unwrap();
        assert_eq!(dl.value, 0x80);
        assert_eq!(dl.encoded_len, 2);
    }

    #[test]
    fn decode_length_long_form_0x8000() {
        let dl = Tlv::decode_length(&[0x82, 0x80, 0x00]).unwrap();
        assert_eq!(dl.value, 0x8000);
        assert_eq!(dl.encoded_len, 3);
    }

    #[test]
    fn decode_length_long_form_0x800000() {
        let dl = Tlv::decode_length(&[0x83, 0x80, 0x00, 0x00]).unwrap();
        assert_eq!(dl.value, 0x80_0000);
        assert_eq!(dl.encoded_len, 4);
    }

    #[test]
    fn decode_length_empty_errors() {
        assert_eq!(Tlv::decode_length(&[]).unwrap_err(), TlvError::EmptyLength);
    }

    #[test]
    fn decode_length_indefinite_0x80_is_rejected() {
        // 0x80 is the BER indefinite-length marker — must be rejected, not
        // decoded as a zero length.
        assert_eq!(
            Tlv::decode_length(&[0x80]).unwrap_err(),
            TlvError::IndefiniteLength
        );
        // Also when followed by content bytes.
        assert_eq!(
            Tlv::decode_length(&[0x80, 0x01, 0x02]).unwrap_err(),
            TlvError::IndefiniteLength
        );
    }

    #[test]
    fn decode_length_truncated_long_form_errors() {
        // 0x82 says 2 more bytes, but only 0 available → InvalidLength
        assert_eq!(
            Tlv::decode_length(&[0x82]).unwrap_err(),
            TlvError::InvalidLength
        );
    }

    #[test]
    fn decode_length_too_many_bytes_errors() {
        // 0x84 says 4 more bytes → LengthTooBig (max is 3)
        assert_eq!(
            Tlv::decode_length(&[0x84, 0x10, 0x00, 0x00, 0x00]).unwrap_err(),
            TlvError::LengthTooBig
        );
    }

    // -----------------------------------------------------------------------
    // encode_tag / decode_tag
    // -----------------------------------------------------------------------

    #[test]
    fn encode_tag_zero() {
        assert_eq!(Tlv::encode_tag(0), vec![0x00]);
    }

    #[test]
    fn encode_tag_single_byte() {
        assert_eq!(Tlv::encode_tag(0x87), vec![0x87]);
        assert_eq!(Tlv::encode_tag(0x8E), vec![0x8E]);
        assert_eq!(Tlv::encode_tag(0x99), vec![0x99]);
    }

    #[test]
    fn decode_tag_single_byte() {
        let dt = Tlv::decode_tag(&[0x00]).unwrap();
        assert_eq!(dt.value, 0x00);
        assert_eq!(dt.encoded_len, 1);

        let dt = Tlv::decode_tag(&[0x87]).unwrap();
        assert_eq!(dt.value, 0x87);
        assert_eq!(dt.encoded_len, 1);
    }

    #[test]
    fn decode_tag_empty_errors() {
        assert_eq!(Tlv::decode_tag(&[]).unwrap_err(), TlvError::EmptyTag);
    }

    #[test]
    fn decode_tag_truncated_multibyte_errors() {
        // 0x1F alone — needs at least one more byte
        assert_eq!(Tlv::decode_tag(&[0x1F]).unwrap_err(), TlvError::InvalidTag);
        // 0x1F 0x80 — continuation byte but no more bytes follow
        assert_eq!(
            Tlv::decode_tag(&[0x1F, 0x80]).unwrap_err(),
            TlvError::InvalidTag
        );
    }

    #[test]
    fn decode_tag_multibyte_roundtrips() {
        // Multi-byte tag with a continuation byte whose MSB is set (0x81).
        // decode_tag must preserve the raw bytes so encode_tag can rebuild them.
        for raw in [
            vec![0x5F, 0x81, 0x7F],
            vec![0x7F, 0x81, 0x01],
            vec![0x1F, 0x82, 0x00],
        ] {
            let dt = Tlv::decode_tag(&raw).unwrap();
            assert_eq!(dt.encoded_len, raw.len());
            assert_eq!(
                Tlv::encode_tag(dt.value),
                raw,
                "round-trip failed for {raw:02X?}"
            );
        }
    }

    #[test]
    fn decode_tag_overflow_errors() {
        // A 5-byte tag cannot fit in the u32 tag representation; it must be
        // rejected rather than silently truncated.
        assert_eq!(
            Tlv::decode_tag(&[0x1F, 0x81, 0x82, 0x83, 0x04]).unwrap_err(),
            TlvError::InvalidTag
        );
    }

    // -----------------------------------------------------------------------
    // encode_int_value
    // -----------------------------------------------------------------------

    #[test]
    fn encode_int_value_icao_9303_p10() {
        // Test vectors from ICAO 9303 Part 10 Section 3.9.6
        assert_eq!(
            Tlv::encode_int_value(0x54, 0x0001),
            hex::decode("540101").unwrap()
        );
        assert_eq!(
            Tlv::encode_int_value(0x54, 0xFFFF),
            hex::decode("5402FFFF").unwrap()
        );
    }

    #[test]
    fn encode_int_value_icao_9303_p11() {
        assert_eq!(
            Tlv::encode_int_value(0x97, 0x04),
            hex::decode("970104").unwrap()
        );
        assert_eq!(
            Tlv::encode_int_value(0x97, 0x12),
            hex::decode("970112").unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // encode
    // -----------------------------------------------------------------------

    #[test]
    fn encode_icao_9303_p11_d4() {
        // Test vectors from ICAO 9303 Part 11 Appendix D.4
        assert_eq!(
            Tlv::encode(0x87, &hex::decode("016375432908C044F6").unwrap()),
            hex::decode("8709016375432908C044F6").unwrap()
        );
        assert_eq!(
            Tlv::encode(0x8E, &hex::decode("BF8B92D635FF24F8").unwrap()),
            hex::decode("8E08BF8B92D635FF24F8").unwrap()
        );
        assert_eq!(
            Tlv::encode(0x8E, &hex::decode("ED6705417E96BA55").unwrap()),
            hex::decode("8E08ED6705417E96BA55").unwrap()
        );
        assert_eq!(
            Tlv::encode(0x8E, &hex::decode("2EA28A70F3C7B535").unwrap()),
            hex::decode("8E082EA28A70F3C7B535").unwrap()
        );
    }

    #[test]
    fn encode_empty_value() {
        assert_eq!(Tlv::encode(0x00, &[]), vec![0x00, 0x00]);
    }

    // -----------------------------------------------------------------------
    // decode
    // -----------------------------------------------------------------------

    #[test]
    fn decode_tag_0_len_0() {
        let tv = Tlv::decode(&[0x00, 0x00]).unwrap();
        assert_eq!(tv.tag.value, 0);
        assert_eq!(tv.tag.encoded_len, 1);
        assert_eq!(tv.encoded_len, 2);
        assert!(tv.value.is_empty());
    }

    #[test]
    fn decode_tag_1_len_0() {
        let tv = Tlv::decode(&[0x01, 0x00]).unwrap();
        assert_eq!(tv.tag.value, 1);
        assert_eq!(tv.tag.encoded_len, 1);
        assert_eq!(tv.encoded_len, 2);
        assert!(tv.value.is_empty());
    }

    #[test]
    fn decode_tag_0x10_len_0() {
        let tv = Tlv::decode(&[0x10, 0x00]).unwrap();
        assert_eq!(tv.tag.value, 0x10);
        assert_eq!(tv.tag.encoded_len, 1);
        assert_eq!(tv.encoded_len, 2);
        assert!(tv.value.is_empty());
    }

    #[test]
    fn decode_tag_0x11_len_0() {
        let tv = Tlv::decode(&[0x11, 0x00]).unwrap();
        assert_eq!(tv.tag.value, 0x11);
        assert_eq!(tv.tag.encoded_len, 1);
        assert_eq!(tv.encoded_len, 2);
        assert!(tv.value.is_empty());
    }

    #[test]
    fn decode_tag_0x11_value_0x00() {
        let tv = Tlv::decode(&[0x11, 0x01, 0x00]).unwrap();
        assert_eq!(tv.tag.value, 0x11);
        assert_eq!(tv.tag.encoded_len, 1);
        assert_eq!(tv.encoded_len, 3);
        assert_eq!(tv.value, vec![0x00]);
    }

    #[test]
    fn decode_tag_0x11_value_0x01() {
        let tv = Tlv::decode(&[0x11, 0x01, 0x01]).unwrap();
        assert_eq!(tv.tag.value, 0x11);
        assert_eq!(tv.encoded_len, 3);
        assert_eq!(tv.value, vec![0x01]);
    }

    #[test]
    fn decode_tag_0x11_value_0x0f() {
        let tv = Tlv::decode(&[0x11, 0x01, 0x0F]).unwrap();
        assert_eq!(tv.tag.value, 0x11);
        assert_eq!(tv.encoded_len, 3);
        assert_eq!(tv.value, vec![0x0F]);
    }

    #[test]
    fn decode_tag_0x11_value_0xff() {
        let tv = Tlv::decode(&[0x11, 0x01, 0xFF]).unwrap();
        assert_eq!(tv.tag.value, 0x11);
        assert_eq!(tv.tag.encoded_len, 1);
        assert_eq!(tv.encoded_len, 3);
        assert_eq!(tv.value, vec![0xFF]);
    }

    /// ICAO 9303 Part 11 Appendix D.4 — Case 1 Select COM
    #[test]
    fn decode_icao_p11_d4_case1() {
        // "990290008E08FA855A5D4C50A8ED" (data from R-APDU)
        let data = hex::decode("990290008E08FA855A5D4C50A8ED").unwrap();

        let do99 = Tlv::decode(&data).unwrap();
        let do8e = Tlv::decode(&data[do99.encoded_len..]).unwrap();

        assert_eq!(do99.encoded_len + do8e.encoded_len, data.len());
        assert_eq!(do99.tag.value, 0x99);
        assert_eq!(do99.value, hex::decode("9000").unwrap());
        assert_eq!(do8e.tag.value, 0x8E);
        assert_eq!(do8e.value, hex::decode("FA855A5D4C50A8ED").unwrap());
    }

    /// ICAO 9303 Part 11 Appendix D.4 — Case 2 Read Binary first 4 bytes
    #[test]
    fn decode_icao_p11_d4_case2() {
        let data = hex::decode("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED").unwrap();

        let do87 = Tlv::decode(&data).unwrap();
        let do99 = Tlv::decode(&data[do87.encoded_len..]).unwrap();
        let do8e = Tlv::decode(&data[do87.encoded_len + do99.encoded_len..]).unwrap();

        assert_eq!(
            do87.encoded_len + do99.encoded_len + do8e.encoded_len,
            data.len()
        );
        assert_eq!(do87.tag.value, 0x87);
        assert_eq!(do87.value, hex::decode("019FF0EC34F9922651").unwrap());

        let dec_do87_tl = Tlv::decode_tag_and_length(&hex::decode("60145F01").unwrap()).unwrap();
        assert_eq!(dec_do87_tl.tag.value, 0x60);
        assert_eq!(dec_do87_tl.length.value, 0x14);

        assert_eq!(do99.tag.value, 0x99);
        assert_eq!(do99.value, hex::decode("9000").unwrap());
        assert_eq!(do8e.tag.value, 0x8E);
        assert_eq!(do8e.value, hex::decode("AD55CC17140B2DED").unwrap());
    }

    /// ICAO 9303 Part 11 Appendix D.4 — Case 3 Read Binary rest
    #[test]
    fn decode_icao_p11_d4_case3() {
        let data = hex::decode(
            "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D74",
        )
        .unwrap();

        let do87 = Tlv::decode(&data).unwrap();
        let do99 = Tlv::decode(&data[do87.encoded_len..]).unwrap();
        let do8e = Tlv::decode(&data[do87.encoded_len + do99.encoded_len..]).unwrap();

        assert_eq!(
            do87.encoded_len + do99.encoded_len + do8e.encoded_len,
            data.len()
        );
        assert_eq!(do87.tag.value, 0x87);
        assert_eq!(
            do87.value,
            hex::decode("01FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A").unwrap()
        );
        assert_eq!(do99.tag.value, 0x99);
        assert_eq!(do99.value, hex::decode("9000").unwrap());
        assert_eq!(do8e.tag.value, 0x8E);
        assert_eq!(do8e.value, hex::decode("C8B2787EAEA07D74").unwrap());
    }

    // -----------------------------------------------------------------------
    // decode — error cases (fuzz / edge cases from tlv_test.dart)
    // -----------------------------------------------------------------------

    #[test]
    fn decode_empty_errors_empty_tag() {
        assert_eq!(Tlv::decode(&[]).unwrap_err(), TlvError::EmptyTag);
    }

    #[test]
    fn decode_single_byte_tag_no_length_errors() {
        // "00" alone → tag decoded OK but no bytes left for length
        assert_eq!(Tlv::decode(&[0x00]).unwrap_err(), TlvError::EmptyLength);
    }

    #[test]
    fn decode_multibyte_tag_truncated_errors() {
        assert_eq!(Tlv::decode(&[0x1F]).unwrap_err(), TlvError::InvalidTag);
        assert_eq!(
            Tlv::decode(&[0x1F, 0x80]).unwrap_err(),
            TlvError::InvalidTag
        );
    }

    #[test]
    fn decode_truncated_long_length_errors() {
        // "0082" → tag=0x00, length claims 2 more bytes but only "82" present
        assert_eq!(
            Tlv::decode(&[0x00, 0x82]).unwrap_err(),
            TlvError::InvalidLength
        );
    }

    #[test]
    fn decode_length_too_big_errors() {
        // "008410000000" → tag=0x00, length byte-count = 4 > 3
        assert_eq!(
            Tlv::decode(&[0x00, 0x84, 0x10, 0x00, 0x00, 0x00]).unwrap_err(),
            TlvError::LengthTooBig
        );
    }

    #[test]
    fn decode_value_out_of_bounds_errors() {
        // "0001" → tag=0x00, declared length=1, but no value bytes present
        assert_eq!(
            Tlv::decode(&[0x00, 0x01]).unwrap_err(),
            TlvError::NotEnoughData
        );
    }

    // -----------------------------------------------------------------------
    // Round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn encode_decode_roundtrip() {
        let original = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = Tlv::encode(0x87, &original);
        let tv = Tlv::decode(&encoded).unwrap();
        assert_eq!(tv.tag.value, 0x87);
        assert_eq!(tv.value, original);
        assert_eq!(tv.encoded_len, encoded.len());
    }

    // -----------------------------------------------------------------------
    // TlvEmpty
    // -----------------------------------------------------------------------

    #[test]
    fn tlv_empty_to_bytes() {
        let empty = TlvEmpty::new(0x87);
        assert_eq!(empty.to_bytes(), vec![0x87, 0x00]);
    }

    // -----------------------------------------------------------------------
    // Internal helper: byte_count
    // -----------------------------------------------------------------------

    #[test]
    fn byte_count_values() {
        assert_eq!(byte_count(0), 0);
        assert_eq!(byte_count(1), 1);
        assert_eq!(byte_count(0xFF), 1);
        assert_eq!(byte_count(0x100), 2);
        assert_eq!(byte_count(0xFFFF), 2);
        assert_eq!(byte_count(0x10000), 3);
    }

    // -----------------------------------------------------------------------
    // Internal helper: int_to_bin
    // -----------------------------------------------------------------------

    #[test]
    fn int_to_bin_min_len_1() {
        assert_eq!(int_to_bin(0, 1), vec![0x00]);
        assert_eq!(int_to_bin(1, 1), vec![0x01]);
        assert_eq!(int_to_bin(0xFF, 1), vec![0xFF]);
        assert_eq!(int_to_bin(0x100, 1), vec![0x01, 0x00]);
        assert_eq!(int_to_bin(0xFFFF, 1), vec![0xFF, 0xFF]);
    }

    #[test]
    fn int_to_bin_min_len_0_zero_is_empty() {
        assert_eq!(int_to_bin(0, 0), Vec::<u8>::new());
        assert_eq!(int_to_bin(1, 0), vec![0x01]);
    }
}
