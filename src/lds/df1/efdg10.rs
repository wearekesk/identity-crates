//! EF.DG10 (substance features) — stub data group.

use crate::dg_stub;

dg_stub!(EfDG10, 0x010A, 0x0A, 0x6A);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::tlv::Tlv;

    #[test]
    fn parses_valid_wrapper() {
        assert!(EfDG10::from_bytes(Tlv::encode(0x6A, &[])).is_ok());
    }
}
