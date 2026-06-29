//! EF.DG16 (persons to notify) — stub data group.

use crate::dg_stub;

dg_stub!(EfDG16, 0x0110, 0x10, 0x70);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::tlv::Tlv;

    #[test]
    fn parses_valid_wrapper() {
        assert!(EfDG16::from_bytes(Tlv::encode(0x70, &[])).is_ok());
    }
}
