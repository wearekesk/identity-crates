//! EF.DG8 (data features) — stub data group.

use crate::dg_stub;

dg_stub!(EfDG8, 0x0108, 0x08, 0x68);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::tlv::Tlv;

    #[test]
    fn parses_valid_wrapper() {
        assert!(EfDG8::from_bytes(Tlv::encode(0x68, &[])).is_ok());
    }
}
