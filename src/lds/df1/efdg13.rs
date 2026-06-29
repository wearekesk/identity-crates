//! EF.DG13 (optional details) — stub data group.

use crate::dg_stub;

dg_stub!(EfDG13, 0x010D, 0x0D, 0x6D);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::tlv::Tlv;

    #[test]
    fn parses_valid_wrapper() {
        assert!(EfDG13::from_bytes(Tlv::encode(0x6D, &[])).is_ok());
    }
}
