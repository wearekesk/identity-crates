//! EF.DG7 (displayed signature / usual mark) — stub data group.

use crate::dg_stub;

dg_stub!(EfDG7, 0x0107, 0x07, 0x67);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::tlv::Tlv;

    #[test]
    fn parses_valid_wrapper() {
        assert!(EfDG7::from_bytes(Tlv::encode(0x67, &[])).is_ok());
    }
}
