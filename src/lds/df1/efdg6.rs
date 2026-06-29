//! EF.DG6 — reserved for future use per ICAO 9303 p10.

use crate::dg_stub;

dg_stub!(EfDG6, 0x0106, 0x06, 0x66);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::tlv::Tlv;

    #[test]
    fn parses_valid_wrapper() {
        let bytes = Tlv::encode(0x66, &[0x00]);
        assert!(EfDG6::from_bytes(bytes).is_ok());
    }
}
