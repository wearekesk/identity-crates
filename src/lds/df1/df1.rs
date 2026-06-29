//! DF1 (eMRTD Application) constants.
//!
//! The eMRTD application is identified on chip by the AID defined in
//! ICAO 9303 p10 §3.1.

use once_cell::sync::Lazy;

/// eMRTD Application AID (`A0 00 00 02 47 10 01`).
pub static AID: Lazy<Vec<u8>> =
    Lazy::new(|| vec![0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]);

/// Human-readable application name.
pub const NAME: &str = "eMRTD Application";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aid_is_expected_bytes() {
        assert_eq!(
            AID.as_slice(),
            &[0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]
        );
    }
}
