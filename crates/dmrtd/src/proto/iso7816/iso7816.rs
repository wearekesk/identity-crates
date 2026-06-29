//! ISO/IEC 7816-4 Basic InterIndustry Command (BIC) constants.
//!
//! The constants are grouped in modules (`cla`, `ins`, `select_file_p1`,
//! `select_file_p2`) rather than in uninhabited classes — this is the idiomatic
//! Rust equivalent of the reference "class with only `static const` members" idiom.

// ---------------------------------------------------------------------------
// CLA — Command class byte (secure messaging / command chaining bits).
// ---------------------------------------------------------------------------

/// ISO/IEC 7816-4 CLA byte values.
pub mod cla {
    /// No secure messaging.
    pub const NO_SM: u8 = 0x00;
    /// Proprietary secure messaging.
    pub const PROPRIETARY_SM: u8 = 0x04;
    /// SM, no header authentication.
    pub const SM_NO_HEADER_AUTHN: u8 = 0x08;
    /// SM, header authenticated.
    pub const SM_HEADER_AUTHN: u8 = 0x0C;
    /// Command chaining.
    pub const COMMAND_CHAINING: u8 = 0x10;
}

// ---------------------------------------------------------------------------
// INS — Instruction byte.
// ---------------------------------------------------------------------------

/// ISO/IEC 7816-4 INS byte values used by DMRTD.
pub mod ins {
    pub const MANAGE_SECURITY_ENVIRONMENT: u8 = 0x22;
    pub const GET_CHALLENGE: u8 = 0x84;
    pub const GENERAL_AUTHENTICATE: u8 = 0x86;
    pub const EXTERNAL_AUTHENTICATE: u8 = 0x82;
    pub const INTERNAL_AUTHENTICATE: u8 = 0x88;
    pub const READ_BINARY: u8 = 0xB0;
    /// READ BINARY with odd INS, for offsets beyond 32 767 bytes.
    pub const READ_BINARY_EXT: u8 = 0xB1;
    pub const SELECT_FILE: u8 = 0xA4;
}

// ---------------------------------------------------------------------------
// SELECT FILE P1 values.
// ---------------------------------------------------------------------------

/// P1 values for the SELECT FILE command (ISO 7816-4 §6, table 58).
pub mod select_file_p1 {
    /// Select MF, DF or EF (data field = identifier or empty).
    pub const BY_ID: u8 = 0x00;
    /// Select child DF (data field = DF identifier).
    pub const BY_CHILD_DF_ID: u8 = 0x01;
    /// Select EF under current DF (data field = EF identifier).
    pub const BY_EF_ID: u8 = 0x02;
    /// Select parent DF of the current DF.
    pub const PARENT_DF: u8 = 0x03;
    /// Direct selection by DF name.
    pub const BY_DF_NAME: u8 = 0x04;
    /// Select from MF by path (data field = path without MF identifier).
    pub const BY_PATH_FROM_MF: u8 = 0x08;
    /// Select from current DF by path.
    pub const BY_PATH: u8 = 0x09;
}

// ---------------------------------------------------------------------------
// SELECT FILE P2 values.
// ---------------------------------------------------------------------------

/// P2 values for the SELECT FILE command (ISO 7816-4 §6, table 59).
pub mod select_file_p2 {
    pub const FIRST_RECORD: u8 = 0x00;
    pub const LAST_RECORD: u8 = 0x01;
    pub const NEXT_RECORD: u8 = 0x02;
    pub const PREVIOUS_RECORD: u8 = 0x03;

    /// Return FCI (optional template).
    pub const RETURN_FCI: u8 = 0x00;
    /// Return FCP template.
    pub const RETURN_FCP: u8 = 0x04;
    /// Return FMD template.
    pub const RETURN_FMD: u8 = 0x08;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cla_values() {
        assert_eq!(cla::NO_SM, 0x00);
        assert_eq!(cla::SM_HEADER_AUTHN, 0x0C);
        assert_eq!(cla::COMMAND_CHAINING, 0x10);
    }

    #[test]
    fn ins_values() {
        assert_eq!(ins::GET_CHALLENGE, 0x84);
        assert_eq!(ins::SELECT_FILE, 0xA4);
        assert_eq!(ins::READ_BINARY, 0xB0);
        assert_eq!(ins::READ_BINARY_EXT, 0xB1);
    }

    #[test]
    fn select_file_p1_values() {
        assert_eq!(select_file_p1::BY_ID, 0x00);
        assert_eq!(select_file_p1::BY_DF_NAME, 0x04);
    }

    #[test]
    fn select_file_p2_fci_fcp_fmd_differ() {
        assert_eq!(select_file_p2::RETURN_FCI, 0x00);
        assert_eq!(select_file_p2::RETURN_FCP, 0x04);
        assert_eq!(select_file_p2::RETURN_FMD, 0x08);
    }
}
