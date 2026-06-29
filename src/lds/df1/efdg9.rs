//! EF.DG9 (structure features) — stub data group.

use crate::dg_stub;

dg_stub!(EfDG9, 0x0109, 0x09, 0x69);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::tlv::Tlv;

    #[test]
    fn parses_valid_wrapper() {
        assert!(EfDG9::from_bytes(Tlv::encode(0x69, &[])).is_ok());
    }
}
