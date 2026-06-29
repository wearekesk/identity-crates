//! ISO/IEC 7816-4 Command APDU.
//!
//! # Serialisation cases
//!
//! | Case | Data | Le  | Extended? | Wire format                          |
//! |------|------|-----|-----------|--------------------------------------|
//! | 1    | No   | No  | —         | `[CLA INS P1 P2]`                    |
//! | 2s   | No   | Yes | No        | `[CLA INS P1 P2 Le]`                 |
//! | 2e   | No   | Yes | Yes       | `[CLA INS P1 P2 00 LeHi LeLo]`      |
//! | 3s   | Yes  | No  | No        | `[CLA INS P1 P2 Lc data]`           |
//! | 3e   | Yes  | No  | Yes       | `[CLA INS P1 P2 00 00 LcHi LcLo data]` |
//! | 4s   | Yes  | Yes | No        | `[CLA INS P1 P2 Lc data Le]`        |
//! | 4e   | Yes  | Yes | Yes       | `[CLA INS P1 P2 00 00 LcHi LcLo data LeHi LeLo]` |
//!
//! **Extended form** is used when `data.len() > 255` OR `ne > 256`.
//!
//! Special Le values: in short form `ne == 256` → `0x00`. In extended form
//! `ne == 256` → `0x0100` (the literal value); only `ne == 65536` → `0x0000`.

use std::fmt;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur when constructing a [`CommandApdu`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommandApduError {
    /// The data field exceeds the ISO 7816-4 maximum of 65 535 bytes.
    #[error("Command APDU data length {0} exceeds maximum of 65535 bytes")]
    DataTooLong(usize),

    /// The `ne` (expected response length) value exceeds 65 536.
    #[error("Command APDU ne value {0} exceeds maximum of 65536")]
    InvalidNe(u32),
}

// ---------------------------------------------------------------------------
// CommandApdu
// ---------------------------------------------------------------------------

/// An ISO/IEC 7816-4 Command APDU.
///
/// # Fields
/// - `cla`, `ins`, `p1`, `p2` — the four mandatory header bytes.
/// - `data` — optional command data field (max 65 535 bytes).
/// - `ne` — expected response length (0 = none; max 65 536). In short form
///   `ne == 256` is the `0x00` "any length" sentinel; in extended form only
///   `ne == 65 536` is the `0x0000` sentinel, while `ne == 256` is the literal
///   `0x0100`.
#[derive(Debug, Clone)]
pub struct CommandApdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    /// Optional command data (max 65 535 bytes).
    pub data: Option<Vec<u8>>,
    /// Expected response length: 0 = not included; max = 65 536.
    pub ne: u32,
}

impl CommandApdu {
    /// Creates a new [`CommandApdu`], validating `data` length and `ne` range.
    ///
    /// # Errors
    /// - [`CommandApduError::DataTooLong`] — `data.len() > 65535`.
    /// - [`CommandApduError::InvalidNe`] — `ne > 65536`.
    pub fn new(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: Option<Vec<u8>>,
        ne: u32,
    ) -> Result<Self, CommandApduError> {
        if let Some(ref d) = data {
            if d.len() > 0xFFFF {
                return Err(CommandApduError::DataTooLong(d.len()));
            }
        }
        if ne > 65536 {
            return Err(CommandApduError::InvalidNe(ne));
        }
        Ok(Self {
            cla,
            ins,
            p1,
            p2,
            data,
            ne,
        })
    }

    /// Returns the four-byte command header `[CLA, INS, P1, P2]`.
    pub fn raw_header(&self) -> [u8; 4] {
        [self.cla, self.ins, self.p1, self.p2]
    }

    /// Serialises the command APDU according to ISO/IEC 7816-4.
    ///
    /// See the module-level documentation for the encoding rules.
    pub fn to_bytes(&self) -> Vec<u8> {
        let data_len = self.data.as_ref().map_or(0, |d| d.len());
        // Non-empty data present in the Lc/data fields?
        let has_data = self.data.as_ref().map_or(false, |d| !d.is_empty());

        // Extended form is required when data > 255 bytes OR ne > 256.
        let extended = data_len > 255 || self.ne > 256;

        let mut out = Vec::new();
        out.extend_from_slice(&self.raw_header());

        if has_data {
            // ---- Lc field ----
            if extended {
                // Extended Lc: 0x00 followed by two-byte big-endian length.
                out.push(0x00);
                out.extend_from_slice(&(data_len as u16).to_be_bytes());
            } else {
                // Short Lc: single byte.
                out.push(data_len as u8);
            }

            // ---- Data field ----
            out.extend_from_slice(self.data.as_ref().unwrap());

            // ---- Le field (if ne > 0) ----
            if self.ne > 0 {
                if extended {
                    // Extended Le: two-byte big-endian. Only 65536 maps to the
                    // 0x0000 "any length" sentinel; 256 is the literal 0x0100.
                    let le_val = if self.ne == 65536 { 0u16 } else { self.ne as u16 };
                    out.extend_from_slice(&le_val.to_be_bytes());
                } else {
                    // Short Le: single byte; 256 → 0x00.
                    let le_val = if self.ne == 256 { 0u8 } else { self.ne as u8 };
                    out.push(le_val);
                }
            }
        } else {
            // No data (Case 1 or Case 2).
            if self.ne > 0 {
                if extended {
                    // Extended Case 2: prefix 0x00 (addByte) then two-byte Le.
                    // Only 65536 maps to 0x0000; 256 is the literal 0x0100.
                    out.push(0x00);
                    let le_val = if self.ne == 65536 { 0u16 } else { self.ne as u16 };
                    out.extend_from_slice(&le_val.to_be_bytes());
                } else {
                    // Short Case 2: single Le byte; 256 → 0x00.
                    let le_val = if self.ne == 256 { 0u8 } else { self.ne as u8 };
                    out.push(le_val);
                }
            }
            // Case 1: ne == 0, no data → only the 4-byte header.
        }

        out
    }
}

impl fmt::Display for CommandApdu {
    /// Formats as `"C-APDU(CLA:XX INS:XX P1:XX P2:XX Le:N Lc:M Data:...)"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lc = self.data.as_ref().map_or(0, |d| d.len());
        let data_str = match &self.data {
            Some(d) if !d.is_empty() => hex::encode(d),
            _ => "None".to_string(),
        };
        write!(
            f,
            "C-APDU(CLA:{:02X} INS:{:02X} P1:{:02X} P2:{:02X} Le:{} Lc:{} Data:{})",
            self.cla, self.ins, self.p1, self.p2, self.ne, lc, data_str
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: Option<&[u8]>, ne: u32) -> Vec<u8> {
        CommandApdu::new(cla, ins, p1, p2, data.map(|d| d.to_vec()), ne)
            .unwrap()
            .to_bytes()
    }

    // -----------------------------------------------------------------------
    // Case 1 — no data, no Le
    // -----------------------------------------------------------------------

    #[test]
    fn case1_no_data_no_le() {
        assert_eq!(
            apdu(0x00, 0x10, 0x20, 0x30, None, 0),
            hex::decode("00102030").unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Case 2s — no data, short Le
    // -----------------------------------------------------------------------

    #[test]
    fn case2s_ne_0xa0() {
        assert_eq!(
            apdu(0x00, 0x10, 0x20, 0x30, None, 0xA0),
            hex::decode("00102030A0").unwrap()
        );
    }

    #[test]
    fn case2s_ne_0x80() {
        assert_eq!(
            apdu(0x00, 0x10, 0x20, 0x30, None, 0x80),
            hex::decode("0010203080").unwrap()
        );
    }

    #[test]
    fn case2s_ne_256_encoded_as_0x00() {
        // ne = 256 → short form 0x00 (means "accept any length")
        assert_eq!(
            apdu(0x00, 0x10, 0x20, 0x30, None, 256),
            hex::decode("0010203000").unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Case 2e — no data, extended Le
    // -----------------------------------------------------------------------

    #[test]
    fn case2e_ne_0xaabb() {
        assert_eq!(
            apdu(0x00, 0x10, 0x20, 0x30, None, 0xAABB),
            hex::decode("0010203000AABB").unwrap()
        );
    }

    #[test]
    fn case2e_ne_0x180() {
        assert_eq!(
            apdu(0x00, 0x10, 0x20, 0x30, None, 0x180),
            hex::decode("00102030000180").unwrap()
        );
    }

    #[test]
    fn case2e_ne_65536_encoded_as_0x0000() {
        // ne = 65536 → extended 0x0000
        assert_eq!(
            apdu(0x00, 0x10, 0x20, 0x30, None, 65536),
            hex::decode("00102030000000").unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Case 3s — data, no Le, short
    // -----------------------------------------------------------------------

    #[test]
    fn case3s_data_no_le() {
        assert_eq!(
            apdu(
                0x00,
                0x10,
                0x20,
                0x30,
                Some(&hex::decode("0102030405060708").unwrap()),
                0
            ),
            hex::decode("00102030080102030405060708").unwrap()
        );
    }

    #[test]
    fn case3s_4_byte_data_no_le() {
        assert_eq!(
            apdu(
                0x00,
                0x10,
                0x20,
                0x30,
                Some(&hex::decode("41424344").unwrap()),
                0
            ),
            hex::decode("001020300441424344").unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Case 4s — data + short Le
    // -----------------------------------------------------------------------

    #[test]
    fn case4s_data_ne_0xa0() {
        assert_eq!(
            apdu(
                0x00,
                0x10,
                0x20,
                0x30,
                Some(&hex::decode("0102030405060708").unwrap()),
                0xA0
            ),
            hex::decode("00102030080102030405060708A0").unwrap()
        );
    }

    #[test]
    fn case4s_data_ne_256_encoded_as_0x00() {
        // ne = 256, data fits in short form (8 bytes)
        assert_eq!(
            apdu(
                0x00,
                0x10,
                0x20,
                0x30,
                Some(&hex::decode("0102030405060708").unwrap()),
                256
            ),
            hex::decode("0010203008010203040506070800").unwrap()
        );
    }

    #[test]
    fn case4s_4_byte_data_ne_0x80() {
        assert_eq!(
            apdu(
                0x00,
                0x10,
                0x20,
                0x30,
                Some(&hex::decode("41424344").unwrap()),
                0x80
            ),
            hex::decode("00102030044142434480").unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Case 4e — data + extended Le  (ne > 256 forces extended)
    // -----------------------------------------------------------------------

    #[test]
    fn case4e_data_ne_0x0180() {
        assert_eq!(
            apdu(
                0x00,
                0x10,
                0x20,
                0x30,
                Some(&hex::decode("0102030405060708").unwrap()),
                0x0180
            ),
            hex::decode("0010203000000801020304050607080180").unwrap()
        );
    }

    #[test]
    fn case4e_data_ne_65536_encoded_as_0x0000() {
        assert_eq!(
            apdu(
                0x00,
                0x10,
                0x20,
                0x30,
                Some(&hex::decode("0102030405060708").unwrap()),
                65536
            ),
            hex::decode("0010203000000801020304050607080000").unwrap()
        );
    }

    #[test]
    fn case4e_4_byte_data_ne_0x180() {
        // ne > 256 forces extended even with short data
        assert_eq!(
            apdu(
                0x00,
                0x10,
                0x20,
                0x30,
                Some(&hex::decode("41424344").unwrap()),
                0x180
            ),
            hex::decode("00102030000004414243440180").unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Case 3e / 4e — data > 255 bytes forces extended Lc
    // -----------------------------------------------------------------------

    #[test]
    fn case3e_256_byte_data_no_le() {
        let data = vec![0xAAu8; 256];
        let mut expected = hex::decode("00102030000100").unwrap(); // header + extended Lc (256)
        expected.extend_from_slice(&data);
        assert_eq!(apdu(0x00, 0x10, 0x20, 0x30, Some(&data), 0), expected);
    }

    #[test]
    fn case4e_256_byte_data_ne_0xa0() {
        let data = vec![0xAAu8; 256];
        let mut expected = hex::decode("00102030000100").unwrap();
        expected.extend_from_slice(&data);
        expected.extend_from_slice(&hex::decode("00A0").unwrap()); // extended Le
        assert_eq!(apdu(0x00, 0x10, 0x20, 0x30, Some(&data), 0xA0), expected);
    }

    #[test]
    fn case4e_256_byte_data_ne_256() {
        let data = vec![0xAAu8; 256];
        let mut expected = hex::decode("00102030000100").unwrap();
        expected.extend_from_slice(&data);
        // In extended form 256 is the literal 0x0100 (0x0000 would mean 65536).
        expected.extend_from_slice(&[0x01, 0x00]);
        assert_eq!(apdu(0x00, 0x10, 0x20, 0x30, Some(&data), 256), expected);
    }

    #[test]
    fn case4e_256_byte_data_ne_0x0180() {
        let data = vec![0xAAu8; 256];
        let mut expected = hex::decode("00102030000100").unwrap();
        expected.extend_from_slice(&data);
        expected.extend_from_slice(&[0x01, 0x80]);
        assert_eq!(apdu(0x00, 0x10, 0x20, 0x30, Some(&data), 0x0180), expected);
    }

    #[test]
    fn case4e_256_byte_data_ne_65536() {
        let data = vec![0xAAu8; 256];
        let mut expected = hex::decode("00102030000100").unwrap();
        expected.extend_from_slice(&data);
        expected.extend_from_slice(&[0x00, 0x00]); // 65536 → 0x0000
        assert_eq!(apdu(0x00, 0x10, 0x20, 0x30, Some(&data), 65536), expected);
    }

    // -----------------------------------------------------------------------
    // None vs empty slice (both treated as no-data)
    // -----------------------------------------------------------------------

    #[test]
    fn none_and_empty_data_equivalent() {
        // Both None and Some([]) should produce Case 1 output
        let v1 = CommandApdu::new(0x00, 0x10, 0x20, 0x30, None, 0)
            .unwrap()
            .to_bytes();
        let v2 = CommandApdu::new(0x00, 0x10, 0x20, 0x30, Some(vec![]), 0)
            .unwrap()
            .to_bytes();
        assert_eq!(v1, v2);
        assert_eq!(v1, hex::decode("00102030").unwrap());
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    #[test]
    fn ne_too_large_errors() {
        assert_eq!(
            CommandApdu::new(0x00, 0x00, 0x00, 0x00, None, 65537).unwrap_err(),
            CommandApduError::InvalidNe(65537)
        );
    }

    #[test]
    fn data_too_long_errors() {
        let big_data = vec![0u8; 0x10000]; // 65536 bytes
        assert!(matches!(
            CommandApdu::new(0x00, 0x00, 0x00, 0x00, Some(big_data), 0).unwrap_err(),
            CommandApduError::DataTooLong(_)
        ));
    }

    // -----------------------------------------------------------------------
    // raw_header
    // -----------------------------------------------------------------------

    #[test]
    fn raw_header() {
        let apdu = CommandApdu::new(0x00, 0x10, 0x20, 0x30, None, 0).unwrap();
        assert_eq!(apdu.raw_header(), [0x00, 0x10, 0x20, 0x30]);
    }

    // -----------------------------------------------------------------------
    // Display
    // -----------------------------------------------------------------------

    #[test]
    fn display_no_data() {
        let apdu = CommandApdu::new(0x00, 0xA4, 0x04, 0x00, None, 0).unwrap();
        let s = apdu.to_string();
        assert!(s.starts_with("C-APDU("));
        assert!(s.contains("CLA:00"));
        assert!(s.contains("INS:A4"));
    }
}
