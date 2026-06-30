//! EF.DG4 (encoded iris) — stub data group.

use crate::dg_stub;

dg_stub!(EfDG4, 0x0104, 0x04, 0x76);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::tlv::Tlv;

    #[test]
    fn parses_valid_wrapper() {
        let bytes = Tlv::encode(0x76, &[0xAA]);
        assert!(EfDG4::from_bytes(bytes).is_ok());
    }

    #[test]
    fn constants() {
        assert_eq!(EfDG4::FID, 0x0104);
        assert_eq!(EfDG4::TAG.value(), 0x76);
    }
}
