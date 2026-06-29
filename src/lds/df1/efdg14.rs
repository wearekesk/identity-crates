//! EF.DG14 (security options) — stub data group.
//!
//! The reference does not parse the SecurityInfos SET — it only checks
//! the outer tag. This port matches that behaviour.

use crate::dg_stub;

dg_stub!(EfDG14, 0x010E, 0x0E, 0x6E);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::tlv::Tlv;

    #[test]
    fn parses_valid_wrapper() {
        assert!(EfDG14::from_bytes(Tlv::encode(0x6E, &[])).is_ok());
    }
}
