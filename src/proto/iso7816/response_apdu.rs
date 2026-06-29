//! ISO/IEC 7816-4 Response APDU and Status Word types.
//!
//! # Overview
//! - [`StatusWord`] — the two trailer bytes (SW1, SW2) of a response APDU, with
//!   all named constants defined in ISO/IEC 7816-4 Figure 7.
//! - [`ResponseApdu`] — a complete response APDU (optional data body + status word).

use std::fmt;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur while parsing a [`ResponseApdu`] or [`StatusWord`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResponseApduError {
    /// The raw APDU byte slice is shorter than 2 bytes.
    #[error("Invalid raw response APDU length")]
    InvalidLength,

    /// The `data` slice passed to `StatusWord::from_bytes` has fewer than 2 bytes.
    #[error("Argument length too small")]
    DataTooSmall,

    /// The `offset` argument places the read beyond the end of the data slice.
    #[error("Argument out of bounds")]
    OffsetOutOfBounds,
}

// ---------------------------------------------------------------------------
// StatusWord
// ---------------------------------------------------------------------------

/// The two status bytes (SW1, SW2) that trail every ISO/IEC 7816-4 Response APDU.
///
/// Named constants mirror the `StatusWord` class static fields.
/// Equality is based on the `(sw1, sw2)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusWord {
    pub sw1: u8,
    pub sw2: u8,
}

impl StatusWord {
    // -----------------------------------------------------------------------
    // Named status-word constants
    // -----------------------------------------------------------------------

    // -- Warnings (SW1 = 0x62) -----------------------------------------------

    /// No information given (0x6200).
    pub const NO_INFORMATION_GIVEN: StatusWord = StatusWord {
        sw1: 0x62,
        sw2: 0x00,
    };
    /// Part of returned data may be corrupted (0x6281).
    pub const POSSIBLE_CORRUPTED_DATA: StatusWord = StatusWord {
        sw1: 0x62,
        sw2: 0x81,
    };
    /// End of file reached before reading Le bytes (0x6282).
    pub const UNEXPECTED_EOF: StatusWord = StatusWord {
        sw1: 0x62,
        sw2: 0x82,
    };
    /// Selected file invalidated (0x6283).
    pub const SELECTED_FILE_INVALIDATED: StatusWord = StatusWord {
        sw1: 0x62,
        sw2: 0x83,
    };
    /// FCI not formatted according to 5.1.5 (0x6284).
    pub const WRONG_FCI_FORMAT: StatusWord = StatusWord {
        sw1: 0x62,
        sw2: 0x84,
    };

    // -- Warnings (SW1 = 0x63) -----------------------------------------------

    /// Authentication failed / protocol step failed (0x6300).
    pub const AUTHENTICATION_FAILED: StatusWord = StatusWord {
        sw1: 0x63,
        sw2: 0x00,
    };

    // -- Errors (SW1 = 0x67–0x6F) --------------------------------------------

    /// Wrong length, e.g. wrong Le field (0x6700).
    pub const WRONG_LENGTH: StatusWord = StatusWord {
        sw1: 0x67,
        sw2: 0x00,
    };
    /// Functions in CLA not supported (0x6800).
    pub const CLA_FUNCTION_NOT_SUPPORTED: StatusWord = StatusWord {
        sw1: 0x68,
        sw2: 0x00,
    };
    /// Logical channel not supported (0x6881).
    pub const LOGICAL_CHANNEL_NOT_SUPPORTED: StatusWord = StatusWord {
        sw1: 0x68,
        sw2: 0x81,
    };
    /// Secure messaging not supported (0x6882).
    pub const SECURE_MESSAGING_NOT_SUPPORTED: StatusWord = StatusWord {
        sw1: 0x68,
        sw2: 0x82,
    };
    /// Command not allowed (0x6900).
    pub const COMMAND_NOT_ALLOWED: StatusWord = StatusWord {
        sw1: 0x69,
        sw2: 0x00,
    };
    /// Command incompatible with file structure (0x6981).
    pub const INCOMPATIBLE_FILE_STRUCTURE_COMMAND: StatusWord = StatusWord {
        sw1: 0x69,
        sw2: 0x81,
    };
    /// Security status not satisfied (0x6982).
    pub const SECURITY_STATUS_NOT_SATISFIED: StatusWord = StatusWord {
        sw1: 0x69,
        sw2: 0x82,
    };
    /// Authentication method blocked (0x6983).
    pub const AUTHENTICATION_METHOD_BLOCKED: StatusWord = StatusWord {
        sw1: 0x69,
        sw2: 0x83,
    };
    /// Referenced data invalidated (0x6984).
    pub const REFERENCED_DATA_INVALIDATED: StatusWord = StatusWord {
        sw1: 0x69,
        sw2: 0x84,
    };
    /// Conditions of use not satisfied (0x6985).
    pub const CONDITIONS_NOT_SATISFIED: StatusWord = StatusWord {
        sw1: 0x69,
        sw2: 0x85,
    };
    /// Command not allowed — no current EF (0x6986).
    pub const COMMAND_NOT_ALLOWED_NO_EF: StatusWord = StatusWord {
        sw1: 0x69,
        sw2: 0x86,
    };
    /// Expected secure messaging data objects missing (0x6987).
    pub const SM_DATA_MISSING: StatusWord = StatusWord {
        sw1: 0x69,
        sw2: 0x87,
    };
    /// Secure messaging data objects incorrect (0x6988).
    pub const SM_DATA_INVALID: StatusWord = StatusWord {
        sw1: 0x69,
        sw2: 0x88,
    };
    /// Wrong parameter(s) P1-P2 (0x6A00).
    pub const WRONG_PARAMETERS: StatusWord = StatusWord {
        sw1: 0x6A,
        sw2: 0x00,
    };
    /// Incorrect parameters in the data field (0x6A80).
    pub const INVALID_DATA_FIELD_PARAMETERS: StatusWord = StatusWord {
        sw1: 0x6A,
        sw2: 0x80,
    };
    /// Function not supported (0x6A81).
    pub const NOT_SUPPORTED: StatusWord = StatusWord {
        sw1: 0x6A,
        sw2: 0x81,
    };
    /// File not found (0x6A82).
    pub const FILE_NOT_FOUND: StatusWord = StatusWord {
        sw1: 0x6A,
        sw2: 0x82,
    };
    /// Record not found (0x6A83).
    pub const RECORD_NOT_FOUND: StatusWord = StatusWord {
        sw1: 0x6A,
        sw2: 0x83,
    };
    /// Not enough memory space in the file (0x6A84).
    pub const NOT_ENOUGH_SPACE_IN_FILE: StatusWord = StatusWord {
        sw1: 0x6A,
        sw2: 0x84,
    };
    /// Lc inconsistent with TLV structure (0x6A85).
    pub const LC_INCONSISTENT_WITH_TLV: StatusWord = StatusWord {
        sw1: 0x6A,
        sw2: 0x85,
    };
    /// Incorrect parameters P1-P2 (0x6A86).
    pub const INCORRECT_PARAMETERS: StatusWord = StatusWord {
        sw1: 0x6A,
        sw2: 0x86,
    };
    /// Lc inconsistent with P1-P2 (0x6A87).
    pub const LC_INCONSISTENT_WITH_PARAMETERS: StatusWord = StatusWord {
        sw1: 0x6A,
        sw2: 0x87,
    };
    /// Referenced data not found (0x6A88).
    pub const REFERENCED_DATA_NOT_FOUND: StatusWord = StatusWord {
        sw1: 0x6A,
        sw2: 0x88,
    };
    /// Wrong parameter(s) P1-P2 — second variant (0x6B00).
    pub const WRONG_PARAMETERS2: StatusWord = StatusWord {
        sw1: 0x6B,
        sw2: 0x00,
    };
    /// Instruction code not supported or invalid (0x6D00).
    pub const INVALID_INSTRUCTION_CODE: StatusWord = StatusWord {
        sw1: 0x6D,
        sw2: 0x00,
    };
    /// Class not supported (0x6E00).
    pub const CLASS_NOT_SUPPORTED: StatusWord = StatusWord {
        sw1: 0x6E,
        sw2: 0x00,
    };
    /// No precise diagnosis (0x6F00).
    pub const NO_PRECISE_DIAGNOSTICS: StatusWord = StatusWord {
        sw1: 0x6F,
        sw2: 0x00,
    };

    // -- Normal processing ---------------------------------------------------

    /// Success (0x9000).
    pub const SUCCESS: StatusWord = StatusWord {
        sw1: 0x90,
        sw2: 0x00,
    };

    // -- Special SW1 constants (not full status words) -----------------------

    /// SW1 = 0x6C: wrong Le field; SW2 indicates the exact length.
    pub const SW1_WRONG_LENGTH_WITH_EXACT_LENGTH: u8 = 0x6C;

    /// SW1 = 0x61: success with remaining bytes; SW2 = number of remaining bytes.
    /// Can be returned by the GET RESPONSE command (ISO 7816-4 §7).
    pub const SW1_SUCCESS_WITH_REMAINING_BYTES: u8 = 0x61;

    // -----------------------------------------------------------------------
    // Factory helpers for the two special SW1 codes
    // -----------------------------------------------------------------------

    /// Creates a status word indicating that `num_bytes` response bytes are
    /// still available (`SW1 = 0x61`, `SW2 = num_bytes`).
    pub fn remaining_available_response_bytes(num_bytes: u8) -> Self {
        Self {
            sw1: Self::SW1_SUCCESS_WITH_REMAINING_BYTES,
            sw2: num_bytes,
        }
    }

    /// Creates a status word indicating that the Le field was wrong and
    /// `exact_length` is the correct value (`SW1 = 0x6C`, `SW2 = exact_length`).
    pub fn le_wrong_length(exact_length: u8) -> Self {
        Self {
            sw1: Self::SW1_WRONG_LENGTH_WITH_EXACT_LENGTH,
            sw2: exact_length,
        }
    }

    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Creates a new [`StatusWord`] from `sw1` and `sw2`.
    pub fn new(sw1: u8, sw2: u8) -> Self {
        Self { sw1, sw2 }
    }

    /// Parses a [`StatusWord`] from `data` starting at `offset`.
    ///
    /// Reads exactly two bytes: `data[offset]` = SW1, `data[offset+1]` = SW2.
    ///
    /// # Errors
    /// - [`ResponseApduError::DataTooSmall`] — `data.len() < 2`.
    /// - [`ResponseApduError::OffsetOutOfBounds`] — fewer than 2 bytes remain at `offset`.
    pub fn from_bytes(data: &[u8], offset: usize) -> Result<Self, ResponseApduError> {
        if data.len() < 2 {
            return Err(ResponseApduError::DataTooSmall);
        }
        if data.len().saturating_sub(offset) < 2 {
            return Err(ResponseApduError::OffsetOutOfBounds);
        }
        Ok(Self {
            sw1: data[offset],
            sw2: data[offset + 1],
        })
    }

    // -----------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------

    /// Returns the combined 16-bit status word value `(SW1 << 8) | SW2`.
    #[inline]
    pub fn value(self) -> u32 {
        ((self.sw1 as u32) << 8) | (self.sw2 as u32)
    }

    /// Returns `true` if this status word represents successful processing.
    pub fn is_success(self) -> bool {
        self == Self::SUCCESS || self.sw1 == Self::SW1_SUCCESS_WITH_REMAINING_BYTES
    }

    /// Returns `true` if this status word represents a warning condition.
    pub fn is_warning(self) -> bool {
        self.sw1 >= 0x62 && self.sw1 <= 0x63
    }

    /// Returns `true` if this status word represents an error condition.
    pub fn is_error(self) -> bool {
        self.sw1 >= 0x64 && self.sw1 != 0x90
    }

    /// Returns the serialised form `[SW1, SW2]`.
    pub fn to_bytes(self) -> [u8; 2] {
        [self.sw1, self.sw2]
    }

    /// Returns a human-readable description of this status word.
    ///
    /// Matches the description strings from the `StatusWord.description()` method.
    /// For unrecognised status words, falls back to `self.to_string()`.
    pub fn description(self) -> String {
        match (self.sw1, self.sw2) {
            (0x62, 0x00) => "No information given".into(),
            (0x62, 0x81) => "Part of returned data my be corrupted".into(),
            (0x62, 0x82) => "End of file reached before reading Le bytes".into(),
            (0x62, 0x83) => "Selected file invalidated".into(),
            (0x62, 0x84) => "FCI not formatted according to 5.1.5".into(),
            (0x63, 0x00) => "The protocol (step) failed.".into(),
            (0x67, 0x00) => "Wrong length (e.g. wrong Le field)".into(),
            (0x68, 0x00) => "Functions in CLA not support".into(),
            (0x68, 0x81) => "Logical channel not supported".into(),
            (0x68, 0x82) => "Secure messaging not supported".into(),
            (0x69, 0x00) => "Command not allowed".into(),
            (0x69, 0x81) => "Command incompatible with file structure".into(),
            (0x69, 0x82) => "Security status not satisfied".into(),
            (0x69, 0x83) => "Authentication method blocked".into(),
            (0x69, 0x84) => "Referenced data invalidated".into(),
            (0x69, 0x85) => "Conditions of use not satisfied".into(),
            (0x69, 0x86) => "Command not allowed (no current EF)".into(),
            (0x69, 0x87) => "Expected SM data objects missing".into(),
            (0x69, 0x88) => "SM data objects incorrect".into(),
            (0x6A, 0x00) => "Wrong parameter(s) P1-P2".into(),
            (0x6A, 0x80) => "Incorrect parameters in the data field".into(),
            (0x6A, 0x81) => "Function not supported".into(),
            (0x6A, 0x82) => "File not found".into(),
            (0x6A, 0x83) => "Record not found".into(),
            (0x6A, 0x84) => "Not enough memory space in the file".into(),
            (0x6A, 0x85) => "Lc inconsistent with TLV structure".into(),
            (0x6A, 0x86) => "Incorrect parameters P1-P2".into(),
            (0x6A, 0x87) => "Lc inconsistent with P1-P2".into(),
            (0x6A, 0x88) => "Referenced data not found".into(),
            (0x6B, 0x00) => "Wrong parameter(s) P1-P2".into(),
            (0x6D, 0x00) => "Instruction code not supported or invalid".into(),
            (0x6E, 0x00) => "Class not supported".into(),
            (0x6F, 0x00) => "No precise diagnosis".into(),
            (0x90, 0x00) => "Success".into(),
            _ => {
                if self.sw1 == Self::SW1_WRONG_LENGTH_WITH_EXACT_LENGTH {
                    format!("Wrong length (exact length: {})", self.sw2)
                } else if self.sw1 == Self::SW1_SUCCESS_WITH_REMAINING_BYTES {
                    format!("{} byte(s) are still available", self.sw2)
                } else {
                    self.to_string()
                }
            }
        }
    }
}

impl fmt::Display for StatusWord {
    /// Formats the status word as `"sw=XXXX"` where XXXX is the 4-digit
    /// uppercase hexadecimal value of `(SW1 << 8) | SW2`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sw={:04X}", self.value())
    }
}

// ---------------------------------------------------------------------------
// ResponseApdu
// ---------------------------------------------------------------------------

/// An ISO/IEC 7816-4 Response APDU.
///
/// Consists of an optional data body followed by a two-byte [`StatusWord`].
#[derive(Debug, Clone)]
pub struct ResponseApdu {
    /// The trailing status bytes.
    pub status: StatusWord,
    /// Optional response data body (everything before the status bytes).
    pub data: Option<Vec<u8>>,
}

impl ResponseApdu {
    /// Creates a new [`ResponseApdu`] from a status word and optional data.
    pub fn new(status: StatusWord, data: Option<Vec<u8>>) -> Self {
        Self { status, data }
    }

    /// Parses a [`ResponseApdu`] from a raw byte slice.
    ///
    /// The last two bytes are the status word; all preceding bytes (if any)
    /// form the data body.
    ///
    /// # Errors
    /// Returns [`ResponseApduError::InvalidLength`] if `apdu_bytes.len() < 2`.
    pub fn from_bytes(apdu_bytes: &[u8]) -> Result<Self, ResponseApduError> {
        if apdu_bytes.len() < 2 {
            return Err(ResponseApduError::InvalidLength);
        }
        let status = StatusWord::from_bytes(apdu_bytes, apdu_bytes.len() - 2)?;
        let data = if apdu_bytes.len() > 2 {
            Some(apdu_bytes[..apdu_bytes.len() - 2].to_vec())
        } else {
            None
        };
        Ok(Self { status, data })
    }

    /// Serialises this APDU as `data_bytes || [SW1, SW2]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = self.data.as_ref().map(|d| d.clone()).unwrap_or_default();
        out.extend_from_slice(&self.status.to_bytes());
        out
    }
}

impl fmt::Display for ResponseApdu {
    /// Formats as `"<status> data=<hex>"` where hex is lowercase, or
    /// `"<status> data=None"` when there is no data body.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.data {
            Some(d) => write!(f, "{} data={}", self.status, hex::encode(d)),
            None => write!(f, "{} data=None", self.status),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helper that mirrors the _testStatusWord
    // -----------------------------------------------------------------------

    fn check_sw(
        sw: StatusWord,
        sw1: u8,
        sw2: u8,
        is_success: bool,
        is_warning: bool,
        is_error: bool,
        description: &str,
    ) {
        assert_eq!(sw.sw1, sw1, "sw1 mismatch for sw={:04X}", sw.value());
        assert_eq!(sw.sw2, sw2, "sw2 mismatch for sw={:04X}", sw.value());
        assert_eq!(
            sw.value(),
            ((sw1 as u32) << 8) | sw2 as u32,
            "value mismatch"
        );
        assert_eq!(sw.is_success(), is_success, "is_success mismatch");
        assert_eq!(sw.is_warning(), is_warning, "is_warning mismatch");
        assert_eq!(sw.is_error(), is_error, "is_error mismatch");
        assert_eq!(
            sw.to_string(),
            format!("sw={:04X}", sw.value()),
            "Display mismatch"
        );
        assert_eq!(sw.description(), description, "description mismatch");
        assert_eq!(sw.to_bytes(), [sw1, sw2]);
        assert_eq!(sw, StatusWord::new(sw1, sw2));

        // from_bytes at offset 0
        let raw = sw.to_bytes();
        assert_eq!(StatusWord::from_bytes(&raw, 0).unwrap(), sw);

        // from_bytes at offset 1 with a leading padding byte
        let mut padded = vec![0xFFu8];
        padded.extend_from_slice(&raw);
        assert_eq!(StatusWord::from_bytes(&padded, 1).unwrap(), sw);
    }

    // -----------------------------------------------------------------------
    // Success
    // -----------------------------------------------------------------------

    #[test]
    fn sw_success() {
        check_sw(
            StatusWord::SUCCESS,
            0x90,
            0x00,
            true,
            false,
            false,
            "Success",
        );
    }

    #[test]
    fn sw_remaining_available_response_bytes() {
        let sw = StatusWord::remaining_available_response_bytes(32);
        check_sw(
            sw,
            StatusWord::SW1_SUCCESS_WITH_REMAINING_BYTES,
            0x20,
            true,
            false,
            false,
            "32 byte(s) are still available",
        );
    }

    // -----------------------------------------------------------------------
    // Warnings (SW1 = 0x62–0x63)
    // -----------------------------------------------------------------------

    #[test]
    fn sw_no_information_given() {
        check_sw(
            StatusWord::NO_INFORMATION_GIVEN,
            0x62,
            0x00,
            false,
            true,
            false,
            "No information given",
        );
    }

    #[test]
    fn sw_possible_corrupted_data() {
        check_sw(
            StatusWord::POSSIBLE_CORRUPTED_DATA,
            0x62,
            0x81,
            false,
            true,
            false,
            "Part of returned data my be corrupted",
        );
    }

    #[test]
    fn sw_unexpected_eof() {
        check_sw(
            StatusWord::UNEXPECTED_EOF,
            0x62,
            0x82,
            false,
            true,
            false,
            "End of file reached before reading Le bytes",
        );
    }

    #[test]
    fn sw_selected_file_invalidated() {
        check_sw(
            StatusWord::SELECTED_FILE_INVALIDATED,
            0x62,
            0x83,
            false,
            true,
            false,
            "Selected file invalidated",
        );
    }

    #[test]
    fn sw_wrong_fci_format() {
        check_sw(
            StatusWord::WRONG_FCI_FORMAT,
            0x62,
            0x84,
            false,
            true,
            false,
            "FCI not formatted according to 5.1.5",
        );
    }

    // -----------------------------------------------------------------------
    // Errors (SW1 = 0x64–0x6F)
    // -----------------------------------------------------------------------

    #[test]
    fn sw_wrong_length() {
        check_sw(
            StatusWord::WRONG_LENGTH,
            0x67,
            0x00,
            false,
            false,
            true,
            "Wrong length (e.g. wrong Le field)",
        );
    }

    #[test]
    fn sw_cla_function_not_supported() {
        check_sw(
            StatusWord::CLA_FUNCTION_NOT_SUPPORTED,
            0x68,
            0x00,
            false,
            false,
            true,
            "Functions in CLA not support",
        );
    }

    #[test]
    fn sw_logical_channel_not_supported() {
        check_sw(
            StatusWord::LOGICAL_CHANNEL_NOT_SUPPORTED,
            0x68,
            0x81,
            false,
            false,
            true,
            "Logical channel not supported",
        );
    }

    #[test]
    fn sw_secure_messaging_not_supported() {
        check_sw(
            StatusWord::SECURE_MESSAGING_NOT_SUPPORTED,
            0x68,
            0x82,
            false,
            false,
            true,
            "Secure messaging not supported",
        );
    }

    #[test]
    fn sw_command_not_allowed() {
        check_sw(
            StatusWord::COMMAND_NOT_ALLOWED,
            0x69,
            0x00,
            false,
            false,
            true,
            "Command not allowed",
        );
    }

    #[test]
    fn sw_incompatible_file_structure_command() {
        check_sw(
            StatusWord::INCOMPATIBLE_FILE_STRUCTURE_COMMAND,
            0x69,
            0x81,
            false,
            false,
            true,
            "Command incompatible with file structure",
        );
    }

    #[test]
    fn sw_security_status_not_satisfied() {
        check_sw(
            StatusWord::SECURITY_STATUS_NOT_SATISFIED,
            0x69,
            0x82,
            false,
            false,
            true,
            "Security status not satisfied",
        );
    }

    #[test]
    fn sw_authentication_method_blocked() {
        check_sw(
            StatusWord::AUTHENTICATION_METHOD_BLOCKED,
            0x69,
            0x83,
            false,
            false,
            true,
            "Authentication method blocked",
        );
    }

    #[test]
    fn sw_referenced_data_invalidated() {
        check_sw(
            StatusWord::REFERENCED_DATA_INVALIDATED,
            0x69,
            0x84,
            false,
            false,
            true,
            "Referenced data invalidated",
        );
    }

    #[test]
    fn sw_conditions_not_satisfied() {
        check_sw(
            StatusWord::CONDITIONS_NOT_SATISFIED,
            0x69,
            0x85,
            false,
            false,
            true,
            "Conditions of use not satisfied",
        );
    }

    #[test]
    fn sw_command_not_allowed_no_ef() {
        check_sw(
            StatusWord::COMMAND_NOT_ALLOWED_NO_EF,
            0x69,
            0x86,
            false,
            false,
            true,
            "Command not allowed (no current EF)",
        );
    }

    #[test]
    fn sw_sm_data_missing() {
        check_sw(
            StatusWord::SM_DATA_MISSING,
            0x69,
            0x87,
            false,
            false,
            true,
            "Expected SM data objects missing",
        );
    }

    #[test]
    fn sw_sm_data_invalid() {
        check_sw(
            StatusWord::SM_DATA_INVALID,
            0x69,
            0x88,
            false,
            false,
            true,
            "SM data objects incorrect",
        );
    }

    #[test]
    fn sw_wrong_parameters() {
        check_sw(
            StatusWord::WRONG_PARAMETERS,
            0x6A,
            0x00,
            false,
            false,
            true,
            "Wrong parameter(s) P1-P2",
        );
    }

    #[test]
    fn sw_invalid_data_field_parameters() {
        check_sw(
            StatusWord::INVALID_DATA_FIELD_PARAMETERS,
            0x6A,
            0x80,
            false,
            false,
            true,
            "Incorrect parameters in the data field",
        );
    }

    #[test]
    fn sw_not_supported() {
        check_sw(
            StatusWord::NOT_SUPPORTED,
            0x6A,
            0x81,
            false,
            false,
            true,
            "Function not supported",
        );
    }

    #[test]
    fn sw_file_not_found() {
        check_sw(
            StatusWord::FILE_NOT_FOUND,
            0x6A,
            0x82,
            false,
            false,
            true,
            "File not found",
        );
    }

    #[test]
    fn sw_record_not_found() {
        check_sw(
            StatusWord::RECORD_NOT_FOUND,
            0x6A,
            0x83,
            false,
            false,
            true,
            "Record not found",
        );
    }

    #[test]
    fn sw_not_enough_space_in_file() {
        check_sw(
            StatusWord::NOT_ENOUGH_SPACE_IN_FILE,
            0x6A,
            0x84,
            false,
            false,
            true,
            "Not enough memory space in the file",
        );
    }

    #[test]
    fn sw_lc_inconsistent_with_tlv() {
        check_sw(
            StatusWord::LC_INCONSISTENT_WITH_TLV,
            0x6A,
            0x85,
            false,
            false,
            true,
            "Lc inconsistent with TLV structure",
        );
    }

    #[test]
    fn sw_incorrect_parameters() {
        check_sw(
            StatusWord::INCORRECT_PARAMETERS,
            0x6A,
            0x86,
            false,
            false,
            true,
            "Incorrect parameters P1-P2",
        );
    }

    #[test]
    fn sw_lc_inconsistent_with_parameters() {
        check_sw(
            StatusWord::LC_INCONSISTENT_WITH_PARAMETERS,
            0x6A,
            0x87,
            false,
            false,
            true,
            "Lc inconsistent with P1-P2",
        );
    }

    #[test]
    fn sw_referenced_data_not_found() {
        check_sw(
            StatusWord::REFERENCED_DATA_NOT_FOUND,
            0x6A,
            0x88,
            false,
            false,
            true,
            "Referenced data not found",
        );
    }

    #[test]
    fn sw_wrong_parameters2() {
        check_sw(
            StatusWord::WRONG_PARAMETERS2,
            0x6B,
            0x00,
            false,
            false,
            true,
            "Wrong parameter(s) P1-P2",
        );
    }

    #[test]
    fn sw_invalid_instruction_code() {
        check_sw(
            StatusWord::INVALID_INSTRUCTION_CODE,
            0x6D,
            0x00,
            false,
            false,
            true,
            "Instruction code not supported or invalid",
        );
    }

    #[test]
    fn sw_class_not_supported() {
        check_sw(
            StatusWord::CLASS_NOT_SUPPORTED,
            0x6E,
            0x00,
            false,
            false,
            true,
            "Class not supported",
        );
    }

    #[test]
    fn sw_no_precise_diagnostics() {
        check_sw(
            StatusWord::NO_PRECISE_DIAGNOSTICS,
            0x6F,
            0x00,
            false,
            false,
            true,
            "No precise diagnosis",
        );
    }

    #[test]
    fn sw_le_wrong_length() {
        let sw = StatusWord::le_wrong_length(32);
        check_sw(
            sw,
            StatusWord::SW1_WRONG_LENGTH_WITH_EXACT_LENGTH,
            0x20,
            false,
            false,
            true,
            "Wrong length (exact length: 32)",
        );
    }

    // -----------------------------------------------------------------------
    // StatusWord::from_bytes error cases
    // -----------------------------------------------------------------------

    #[test]
    fn sw_from_bytes_empty_errors() {
        assert_eq!(
            StatusWord::from_bytes(&[], 0).unwrap_err(),
            ResponseApduError::DataTooSmall
        );
    }

    #[test]
    fn sw_from_bytes_one_byte_errors() {
        assert_eq!(
            StatusWord::from_bytes(&[0x00], 0).unwrap_err(),
            ResponseApduError::DataTooSmall
        );
    }

    #[test]
    fn sw_from_bytes_offset_out_of_bounds_errors() {
        // "0000" with offset=1 → only 1 byte remains, need 2
        assert_eq!(
            StatusWord::from_bytes(&[0x00, 0x00], 1).unwrap_err(),
            ResponseApduError::OffsetOutOfBounds
        );
    }

    #[test]
    fn sw_from_bytes_various_offsets() {
        // Verify reading at various offsets produces the correct SW
        let sw = StatusWord::SUCCESS;
        let raw = [sw.sw1, sw.sw2];
        assert_eq!(StatusWord::from_bytes(&raw, 0).unwrap(), sw);

        let mut buf = vec![0x00u8; 3];
        buf.extend_from_slice(&raw);
        assert_eq!(StatusWord::from_bytes(&buf, 3).unwrap(), sw);
    }

    // -----------------------------------------------------------------------
    // ResponseApdu
    // -----------------------------------------------------------------------

    #[test]
    fn response_apdu_from_bytes_only_status() {
        // "9000" → status=0x9000, data=None
        let apdu = ResponseApdu::from_bytes(&hex::decode("9000").unwrap()).unwrap();
        assert_eq!(apdu.status.sw1, 0x90);
        assert_eq!(apdu.status.sw2, 0x00);
        assert!(apdu.data.is_none());
    }

    #[test]
    fn response_apdu_from_bytes_with_data() {
        // ICAO 9303 p11 Appendix D.4 — Test 1
        let raw = hex::decode("990290008E08FA855A5D4C50A8ED9000").unwrap();
        let apdu = ResponseApdu::from_bytes(&raw).unwrap();
        assert_eq!(apdu.status.sw1, 0x90);
        assert_eq!(apdu.status.sw2, 0x00);
        assert_eq!(
            apdu.data.as_deref().unwrap(),
            hex::decode("990290008E08FA855A5D4C50A8ED")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn response_apdu_from_bytes_icao_test2() {
        let raw = hex::decode("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000").unwrap();
        let apdu = ResponseApdu::from_bytes(&raw).unwrap();
        assert_eq!(apdu.status.sw1, 0x90);
        assert_eq!(apdu.status.sw2, 0x00);
        assert_eq!(
            apdu.data.as_deref().unwrap(),
            hex::decode("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn response_apdu_from_bytes_icao_test3() {
        let raw = hex::decode(
            "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000",
        )
        .unwrap();
        let apdu = ResponseApdu::from_bytes(&raw).unwrap();
        assert_eq!(apdu.status.sw1, 0x90);
        assert_eq!(apdu.status.sw2, 0x00);
        assert_eq!(
            apdu.data.as_deref().unwrap(),
            hex::decode(
                "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D74"
            )
            .unwrap()
            .as_slice()
        );
    }

    #[test]
    fn response_apdu_various_status_words() {
        let cases: &[(&str, u8, u8)] = &[
            ("6A80", 0x6A, 0x80),
            ("6A88", 0x6A, 0x88),
            ("6300", 0x63, 0x00),
            ("0000", 0x00, 0x00),
            ("FFFF", 0xFF, 0xFF),
        ];
        for (hex, sw1, sw2) in cases {
            let raw = hex::decode(hex).unwrap();
            let apdu = ResponseApdu::from_bytes(&raw).unwrap();
            assert_eq!(apdu.status.sw1, *sw1);
            assert_eq!(apdu.status.sw2, *sw2);
            assert!(apdu.data.is_none());
        }
    }

    #[test]
    fn response_apdu_from_bytes_too_short_errors() {
        assert!(ResponseApdu::from_bytes(&[]).is_err());
    }

    #[test]
    fn response_apdu_to_bytes_roundtrip() {
        let raw = hex::decode("990290008E08FA855A5D4C50A8ED9000").unwrap();
        let apdu = ResponseApdu::from_bytes(&raw).unwrap();
        assert_eq!(apdu.to_bytes(), raw);
    }

    #[test]
    fn response_apdu_to_bytes_status_only() {
        let apdu = ResponseApdu::new(StatusWord::SUCCESS, None);
        assert_eq!(apdu.to_bytes(), vec![0x90, 0x00]);
    }

    #[test]
    fn response_apdu_display_no_data() {
        let apdu = ResponseApdu::new(StatusWord::SUCCESS, None);
        assert_eq!(apdu.to_string(), "sw=9000 data=None");
    }

    #[test]
    fn response_apdu_display_with_data() {
        let apdu = ResponseApdu::new(StatusWord::SUCCESS, Some(vec![0xDE, 0xAD]));
        assert_eq!(apdu.to_string(), "sw=9000 data=dead");
    }
}
