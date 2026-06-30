//! Manual big-endian parsers for the PAN Secure-QR `construct` definitions.
//!
//! A 1:1 port of `constants/structs.py`. The Python uses the `construct`
//! library; here each definition is parsed by hand with a [`Cursor`] over a
//! byte slice, returning [`PanQrError`] on malformed input rather than
//! panicking.

use crate::error::PanQrError;

/// A forward-only cursor over a byte slice with big-endian readers.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], PanQrError> {
        if self.remaining() < n {
            return Err(PanQrError::UnexpectedEof(field));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, PanQrError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, PanQrError> {
        let b = self.take(2, field)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, PanQrError> {
        let b = self.take(4, field)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn skip(&mut self, n: usize, field: &'static str) -> Result<(), PanQrError> {
        self.take(n, field)?;
        Ok(())
    }

    fn expect(&mut self, magic: &[u8], field: &'static str) -> Result<(), PanQrError> {
        let found = self.take(magic.len(), field)?;
        if found != magic {
            return Err(PanQrError::BadMagic {
                field,
                expected: magic.to_vec(),
                found: found.to_vec(),
            });
        }
        Ok(())
    }

    /// Remaining bytes (`GreedyBytes`).
    fn greedy(&mut self) -> &'a [u8] {
        let slice = &self.data[self.pos..];
        self.pos = self.data.len();
        slice
    }
}

/// Parsed `ECC_KEY_STRUCT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccKey {
    /// Curve OID string bytes (e.g. `1.3.132.0.34`).
    pub curve_oid: Vec<u8>,
    /// Raw key bytes; the SEC1 public point starts at `key[2..]`.
    pub key: Vec<u8>,
}

impl EccKey {
    /// Parses an `ECC_KEY_STRUCT`:
    /// const `\x03\x01`, 2 padding, const `ECC`, 5 padding, `u16` OID length,
    /// OID bytes, `u16` key length, key bytes.
    pub fn parse(data: &[u8]) -> Result<Self, PanQrError> {
        let mut c = Cursor::new(data);
        c.expect(b"\x03\x01", "ECC_KEY_STRUCT.reserved")?;
        c.skip(2, "ECC_KEY_STRUCT.pad0")?;
        c.expect(b"ECC", "ECC_KEY_STRUCT.magic")?;
        c.skip(5, "ECC_KEY_STRUCT.pad1")?;
        let curve_oid_length = c.u16("ECC_KEY_STRUCT.curve_oid_length")? as usize;
        let curve_oid = c
            .take(curve_oid_length, "ECC_KEY_STRUCT.curve_oid")?
            .to_vec();
        let key_length = c.u16("ECC_KEY_STRUCT.key_length")? as usize;
        let key = c.take(key_length, "ECC_KEY_STRUCT.key")?.to_vec();
        Ok(Self { curve_oid, key })
    }
}

/// Parsed `METADATA_UPPER_STRUCT` (a single byte, bit-swapped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    /// The original metadata byte (kept so the struct can be re-serialised).
    pub raw: u8,
    /// 3-bit control type ([`crate::enums::SecureCodeType`]).
    pub control_type: u8,
    /// If set, the parent block's length is 2 bytes (exceeds 256).
    pub exceed_length_flag: bool,
    /// 4-bit character set ([`crate::enums::CharacterSets`]).
    pub character_set: u8,
}

impl Metadata {
    /// Parses the `BitsSwapped(BitStruct(...))` over a single byte.
    ///
    /// `construct`'s `BitsSwapped` reverses the bit order within the byte, i.e.
    /// the bit stream is read LSB-first. With bits `b0..b7` (`b0` = LSB):
    /// `control_type = b0 b1 b2`, `exceed_length_flag = b3`,
    /// `character_set = b4 b5 b6 b7` (each field big-endian within itself).
    pub fn from_byte(byte: u8) -> Self {
        let bit = |n: u8| (byte >> n) & 1;
        let control_type = (bit(0) << 2) | (bit(1) << 1) | bit(2);
        let exceed_length_flag = bit(3) != 0;
        let character_set = (bit(4) << 3) | (bit(5) << 2) | (bit(6) << 1) | bit(7);
        Self {
            raw: byte,
            control_type,
            exceed_length_flag,
            character_set,
        }
    }
}

/// Parsed `PAN_INNER_BLOCK_STRUCT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanInnerBlock {
    /// Block metadata byte.
    pub metadata: Metadata,
    /// Payload length (`u16` if `exceed_length_flag`, else `u8`).
    pub length: u16,
    /// Payload bytes.
    pub data: Vec<u8>,
}

impl PanInnerBlock {
    fn parse(c: &mut Cursor<'_>) -> Result<Self, PanQrError> {
        let metadata = Metadata::from_byte(c.u8("PAN_INNER_BLOCK_STRUCT.metadata")?);
        let length = if metadata.exceed_length_flag {
            c.u16("PAN_INNER_BLOCK_STRUCT.length")?
        } else {
            c.u8("PAN_INNER_BLOCK_STRUCT.length")? as u16
        };
        let data = c
            .take(length as usize, "PAN_INNER_BLOCK_STRUCT.data")?
            .to_vec();
        Ok(Self {
            metadata,
            length,
            data,
        })
    }

    /// Re-serialises the block (the inverse of [`PanInnerBlock::parse`]).
    fn build(&self, out: &mut Vec<u8>) {
        out.push(self.metadata.raw);
        if self.metadata.exceed_length_flag {
            out.extend_from_slice(&self.length.to_be_bytes());
        } else {
            out.push(self.length as u8);
        }
        out.extend_from_slice(&self.data);
    }
}

/// Parsed `SCBLOB_STRUCT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScBlob {
    /// 16-bit blob identifier ([`crate::enums::SCBlobIdentifier`]).
    pub identifier: u16,
    /// Remaining (greedy) blob bytes.
    pub data: Vec<u8>,
}

impl ScBlob {
    /// Parses `u16 identifier` followed by greedy remaining bytes.
    pub fn parse(data: &[u8]) -> Result<Self, PanQrError> {
        let mut c = Cursor::new(data);
        let identifier = c.u16("SCBLOB_STRUCT.identifier")?;
        let data = c.greedy().to_vec();
        Ok(Self { identifier, data })
    }
}

/// Parsed `PII_STRUCT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pii {
    /// Number of PII elements declared.
    pub num_blocks: u16,
    /// Remaining (greedy) PII bytes.
    pub data: Vec<u8>,
}

impl Pii {
    /// Parses `u16 num_blocks` followed by greedy remaining bytes.
    pub fn parse(data: &[u8]) -> Result<Self, PanQrError> {
        let mut c = Cursor::new(data);
        let num_blocks = c.u16("PII_STRUCT.num_blocks")?;
        let data = c.greedy().to_vec();
        Ok(Self { num_blocks, data })
    }
}

/// Parsed `PAN_OUTER_BLOCK_STRUCT_MESSAGE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanOuterBlockMessage {
    /// `code_type` ([`crate::enums::CodeType`]).
    pub code_type: u8,
    /// Unused.
    pub reserved_0: u8,
    /// Version code (drives validation and key selection).
    pub reserved_1: u32,
    /// Unused.
    pub reserved_2: u8,
    /// Validated to be `<= 6`.
    pub reserved_3: u16,
    /// Number of blocks in part 1.
    pub num_blocks_1: u8,
    /// Part-1 blocks.
    pub blocks_1: Vec<PanInnerBlock>,
    /// Number of blocks in part 2.
    pub num_blocks_2: u8,
    /// Part-2 blocks.
    pub blocks_2: Vec<PanInnerBlock>,
}

impl PanOuterBlockMessage {
    fn parse(c: &mut Cursor<'_>) -> Result<Self, PanQrError> {
        let code_type = c.u8("MESSAGE.code_type")?;
        let reserved_0 = c.u8("MESSAGE.reserved_0")?;
        let reserved_1 = c.u32("MESSAGE.reserved_1")?;
        let reserved_2 = c.u8("MESSAGE.reserved_2")?;
        let reserved_3 = c.u16("MESSAGE.reserved_3")?;
        let num_blocks_1 = c.u8("MESSAGE.num_blocks_1")?;
        let mut blocks_1 = Vec::with_capacity(num_blocks_1 as usize);
        for _ in 0..num_blocks_1 {
            blocks_1.push(PanInnerBlock::parse(c)?);
        }
        let num_blocks_2 = c.u8("MESSAGE.num_blocks_2")?;
        let mut blocks_2 = Vec::with_capacity(num_blocks_2 as usize);
        for _ in 0..num_blocks_2 {
            blocks_2.push(PanInnerBlock::parse(c)?);
        }
        Ok(Self {
            code_type,
            reserved_0,
            reserved_1,
            reserved_2,
            reserved_3,
            num_blocks_1,
            blocks_1,
            num_blocks_2,
            blocks_2,
        })
    }

    /// Re-serialises the message bytes (`construct`'s `.build`).
    ///
    /// The signature is computed over exactly these bytes, so this is the
    /// inverse of parsing and reproduces the original message byte-for-byte.
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.code_type);
        out.push(self.reserved_0);
        out.extend_from_slice(&self.reserved_1.to_be_bytes());
        out.push(self.reserved_2);
        out.extend_from_slice(&self.reserved_3.to_be_bytes());
        out.push(self.num_blocks_1);
        for block in &self.blocks_1 {
            block.build(&mut out);
        }
        out.push(self.num_blocks_2);
        for block in &self.blocks_2 {
            block.build(&mut out);
        }
        out
    }
}

/// Parsed `PAN_OUTER_BLOCK_STRUCT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanOuterBlock {
    /// The signed message.
    pub message: PanOuterBlockMessage,
    /// `signature_scheme` ([`crate::enums::SignatureScheme`]).
    pub signature_scheme: u8,
    /// Length of `signature_data`.
    pub signature_length: u16,
    /// Raw signature bytes (`r || s` for ECDSA).
    pub signature_data: Vec<u8>,
}

impl PanOuterBlock {
    /// Parses the full outer block:
    /// message, const `\x01`, `u8` signature scheme, 2 padding, `u16` signature
    /// length, then `signature_length` signature bytes.
    pub fn parse(data: &[u8]) -> Result<Self, PanQrError> {
        let mut c = Cursor::new(data);
        let message = PanOuterBlockMessage::parse(&mut c)?;
        c.expect(b"\x01", "PAN_OUTER_BLOCK_STRUCT.reserved_4")?;
        let signature_scheme = c.u8("PAN_OUTER_BLOCK_STRUCT.signature_scheme")?;
        c.skip(2, "PAN_OUTER_BLOCK_STRUCT.pad")?;
        let signature_length = c.u16("PAN_OUTER_BLOCK_STRUCT.signature_length")?;
        let signature_data = c
            .take(
                signature_length as usize,
                "PAN_OUTER_BLOCK_STRUCT.signature_data",
            )?
            .to_vec();
        Ok(Self {
            message,
            signature_scheme,
            signature_length,
            signature_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_bit_ordering() {
        // 0xC5 = 0b1100_0101. With LSB-first bit reading:
        //   control_type = b0 b1 b2 = 1 0 1 = 5 (SCBlob)
        //   exceed_length_flag = b3 = 0
        //   character_set = b4 b5 b6 b7 = 0 0 1 1 = 3 (AlphaNumericUpperCase)
        let m = Metadata::from_byte(0xC5);
        assert_eq!(m.raw, 0xC5);
        assert_eq!(m.control_type, 5);
        assert!(!m.exceed_length_flag);
        assert_eq!(m.character_set, 3);
    }

    #[test]
    fn metadata_flag_set() {
        // Set b3 to flip the exceed_length_flag: 0xC5 | 0x08 = 0xCD.
        let m = Metadata::from_byte(0xCD);
        assert_eq!(m.control_type, 5);
        assert!(m.exceed_length_flag);
        assert_eq!(m.character_set, 3);
    }

    #[test]
    fn inner_block_roundtrip_u8_length() {
        // metadata 0xC5 (flag clear -> u8 length), length 3, data "PAN".
        let bytes = [0xC5u8, 0x03, b'P', b'A', b'N'];
        let mut c = Cursor::new(&bytes);
        let block = PanInnerBlock::parse(&mut c).unwrap();
        assert_eq!(block.length, 3);
        assert_eq!(block.data, b"PAN");
        let mut rebuilt = Vec::new();
        block.build(&mut rebuilt);
        assert_eq!(rebuilt, bytes);
    }

    #[test]
    fn inner_block_u16_length() {
        // metadata with flag set -> u16 length.
        let bytes = [0xCDu8, 0x00, 0x02, b'h', b'i'];
        let mut c = Cursor::new(&bytes);
        let block = PanInnerBlock::parse(&mut c).unwrap();
        assert!(block.metadata.exceed_length_flag);
        assert_eq!(block.length, 2);
        assert_eq!(block.data, b"hi");
    }

    #[test]
    fn scblob_parse() {
        let bytes = [0x01u8, 0x02, 0xAA, 0xBB];
        let blob = ScBlob::parse(&bytes).unwrap();
        assert_eq!(blob.identifier, 0x0102);
        assert_eq!(blob.data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn pii_parse() {
        let bytes = [0x00u8, 0x04, 0xDE, 0xAD];
        let pii = Pii::parse(&bytes).unwrap();
        assert_eq!(pii.num_blocks, 4);
        assert_eq!(pii.data, vec![0xDE, 0xAD]);
    }

    fn sample_outer_message() -> Vec<u8> {
        let mut m = Vec::new();
        m.push(0x03); // code_type SingleCode
        m.push(0x00); // reserved_0
        m.extend_from_slice(&0x1Eu32.to_be_bytes()); // reserved_1 (WHITELISTED_VERSION_2)
        m.push(0x00); // reserved_2
        m.extend_from_slice(&0x0001u16.to_be_bytes()); // reserved_3 <= 6
        m.push(0x01); // num_blocks_1
        m.extend_from_slice(&[0xC5, 0x03, b'P', b'A', b'N']); // one block
        m.push(0x00); // num_blocks_2
        m
    }

    #[test]
    fn outer_message_parse_and_build_roundtrip() {
        let msg_bytes = sample_outer_message();
        let mut c = Cursor::new(&msg_bytes);
        let msg = PanOuterBlockMessage::parse(&mut c).unwrap();
        assert_eq!(msg.code_type, 3);
        assert_eq!(msg.reserved_1, 0x1E);
        assert_eq!(msg.reserved_3, 1);
        assert_eq!(msg.num_blocks_1, 1);
        assert_eq!(msg.blocks_1.len(), 1);
        assert_eq!(msg.num_blocks_2, 0);
        assert_eq!(msg.build(), msg_bytes);
    }

    #[test]
    fn outer_block_parse() {
        let mut data = sample_outer_message();
        data.push(0x01); // reserved_4 const
        data.push(0x00); // signature_scheme ECC
        data.extend_from_slice(&[0x00, 0x00]); // padding
        data.extend_from_slice(&0x0002u16.to_be_bytes()); // signature_length
        data.extend_from_slice(&[0xAB, 0xCD]); // signature_data
        let outer = PanOuterBlock::parse(&data).unwrap();
        assert_eq!(outer.signature_scheme, 0);
        assert_eq!(outer.signature_length, 2);
        assert_eq!(outer.signature_data, vec![0xAB, 0xCD]);
        assert_eq!(outer.message.build(), sample_outer_message());
    }

    #[test]
    fn malformed_returns_err_not_panic() {
        assert!(PanOuterBlock::parse(&[]).is_err());
        assert!(PanOuterBlock::parse(&[0x03, 0x00]).is_err());
        assert!(ScBlob::parse(&[0x01]).is_err());
        assert!(Pii::parse(&[0x00]).is_err());
        assert!(EccKey::parse(&[0x03]).is_err());
        // Bad magic.
        assert!(EccKey::parse(&[0xFF, 0xFF, 0, 0, b'X']).is_err());
    }
}
