//! EF.DG3 (encoded fingerprints) — stub data group.

use crate::dg_stub;

dg_stub!(
    /// EF.DG3 — encoded fingerprint biometric template.
    /// The port only validates the outer tag (0x63); this Rust port does
    /// the same.
    EfDG3, 0x0103, 0x03, 0x63
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lds::ef::ElementaryFile;
    use crate::lds::tlv::Tlv;

    #[test]
    fn parses_valid_wrapper() {
        let bytes = Tlv::encode(0x63, &[0x01, 0x02, 0x03]);
        let ef = EfDG3::from_bytes(bytes.clone()).unwrap();
        assert_eq!(ef.to_bytes(), bytes.as_slice());
    }

    #[test]
    fn rejects_wrong_tag() {
        let bytes = Tlv::encode(0x61, &[0x01]);
        assert!(EfDG3::from_bytes(bytes).is_err());
    }

    #[test]
    fn constants() {
        assert_eq!(EfDG3::FID, 0x0103);
        assert_eq!(EfDG3::SFI, 0x03);
        assert_eq!(EfDG3::TAG.value(), 0x63);
    }
}
