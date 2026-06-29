//! EF.DG5 (displayed portrait) — stub data group.

use crate::dg_stub;

dg_stub!(EfDG5, 0x0105, 0x05, 0x65);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::tlv::Tlv;

    #[test]
    fn parses_valid_wrapper() {
        let bytes = Tlv::encode(0x65, &[0xAA]);
        assert!(EfDG5::from_bytes(bytes).is_ok());
    }

    #[test]
    fn constants() {
        assert_eq!(EfDG5::FID, 0x0105);
        assert_eq!(EfDG5::TAG.value(), 0x65);
    }
}
