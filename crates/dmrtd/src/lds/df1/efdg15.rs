//! EF.DG15 — Active Authentication public key.
//!
//! DG15 wraps a DER-encoded `SubjectPublicKeyInfo` structure under outer tag
//! `0x6F`. The parser strips the wrapper and delegates to
//! [`AAPublicKey::from_bytes`].

use crate::crypto::aa_pubkey::AAPublicKey;
use crate::lds::df1::dg::{parse_dg_content, DgTag};
use crate::lds::ef::{EfParseError, ElementaryFile};

/// EF.DG15 file ID.
pub const EF_DG15_FID: u16 = 0x010F;
/// EF.DG15 short file ID.
pub const EF_DG15_SFI: u8 = 0x0F;
/// EF.DG15 outer tag.
pub const EF_DG15_TAG: DgTag = DgTag(0x6F);

/// EF.DG15 — Active Authentication public key.
#[derive(Debug, Clone)]
pub struct EfDG15 {
    encoded: Vec<u8>,
    pub_key: AAPublicKey,
}

impl EfDG15 {
    /// Parses EF.DG15 bytes.
    pub fn from_bytes(data: impl Into<Vec<u8>>) -> Result<Self, EfParseError> {
        let encoded = data.into();
        let inner = parse_dg_content(&encoded, EF_DG15_TAG.value())?;
        let pub_key = AAPublicKey::from_bytes(inner).map_err(|e| {
            EfParseError::new(format!("Failed to parse AAPublicKey from EF.DG15: {e}"))
        })?;
        Ok(Self { encoded, pub_key })
    }

    /// Returns the parsed Active Authentication public key.
    pub fn aa_public_key(&self) -> &AAPublicKey {
        &self.pub_key
    }
}

impl ElementaryFile for EfDG15 {
    const FID: u16 = EF_DG15_FID;
    const SFI: u8 = EF_DG15_SFI;

    fn to_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aa_pubkey::AAPublicKeyType;
    use crate::lds::tlv::Tlv;

    // RSA OID encoded in DER.
    const RSA_OID_BYTES: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

    fn build_spki(oid_bytes: &[u8], pubkey_bitstring_value: &[u8]) -> Vec<u8> {
        let oid = Tlv::encode(0x06, oid_bytes);
        let alg = Tlv::encode(0x30, &oid);
        let bit_string = Tlv::encode(0x03, pubkey_bitstring_value);
        let mut inner = Vec::new();
        inner.extend_from_slice(&alg);
        inner.extend_from_slice(&bit_string);
        Tlv::encode(0x30, &inner)
    }

    #[test]
    fn parses_rsa_pubkey_wrapped_in_dg15() {
        let spki = build_spki(RSA_OID_BYTES, &[0x00, 0xAB, 0xCD]);
        let dg15_bytes = Tlv::encode(EF_DG15_TAG.value(), &spki);
        let dg15 = EfDG15::from_bytes(dg15_bytes.clone()).unwrap();
        assert_eq!(dg15.aa_public_key().key_type(), AAPublicKeyType::Rsa);
        assert_eq!(dg15.to_bytes(), dg15_bytes.as_slice());
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        let spki = build_spki(RSA_OID_BYTES, &[0x00, 0xAB]);
        let wrapped = Tlv::encode(0x6A, &spki);
        assert!(EfDG15::from_bytes(wrapped).is_err());
    }

    #[test]
    fn rejects_invalid_pubkey_payload() {
        // Outer wrapper OK, inner bytes are not a valid SPKI.
        let wrapped = Tlv::encode(EF_DG15_TAG.value(), &[0x00, 0x01]);
        let err = EfDG15::from_bytes(wrapped).unwrap_err();
        assert!(err.0.contains("Failed to parse AAPublicKey"));
    }

    #[test]
    fn constants() {
        assert_eq!(EfDG15::FID, 0x010F);
        assert_eq!(EfDG15::SFI, 0x0F);
        assert_eq!(EF_DG15_TAG.value(), 0x6F);
    }
}
