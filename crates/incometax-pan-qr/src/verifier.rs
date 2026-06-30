//! ECDSA signature verification over NIST P-384 with SHA-384.
//!
//! Verification uses the RustCrypto [`p384`] crate.
//!
//! The chosen base64 ECC key is parsed via `ECC_KEY_STRUCT`; `key[2..]` is the
//! SEC1 public point. For the two embedded keys this slice is 97 bytes and
//! already begins with the `0x04` uncompressed-point tag, so it is passed to
//! `VerifyingKey::from_sec1_bytes` verbatim (no `0x04` needs to be prepended).
//! The QR signature is raw `r || s` (96 bytes for P-384), parsed with
//! `Signature::from_slice`.
//!
//! NOTE: end-to-end signature verification is not exercised by the unit tests
//! because no real QR sample is bundled with the crate. The tests only confirm
//! that both embedded keys parse and load into a P-384 key.

use crate::error::PanQrError;
use crate::structs::EccKey;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p384::ecdsa::signature::Verifier as _;
use p384::ecdsa::{Signature, VerifyingKey};

/// Holds a loaded P-384 verifying key.
pub struct Verifier {
    verifying_key: VerifyingKey,
}

impl Verifier {
    /// Builds a verifier from a base64-encoded `ECC_KEY_STRUCT`.
    pub fn new(key_b64: &str) -> Result<Self, PanQrError> {
        let decoded = STANDARD
            .decode(key_b64)
            .map_err(|e| PanQrError::KeyDecode(e.to_string()))?;
        let key = EccKey::parse(&decoded)?;
        // The SEC1 public point begins at offset 2 of the key field.
        let point = key.key.get(2..).ok_or(PanQrError::InvalidKey)?;
        let verifying_key =
            VerifyingKey::from_sec1_bytes(point).map_err(|_| PanQrError::InvalidKey)?;
        Ok(Self { verifying_key })
    }

    /// Verifies a raw `r || s` signature over `message` (hashed with SHA-384).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, PanQrError> {
        let signature =
            Signature::from_slice(signature).map_err(|_| PanQrError::InvalidSignature)?;
        Ok(self.verifying_key.verify(message, &signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::values::{ECC_KEY_1, ECC_KEY_2};

    #[test]
    fn both_embedded_keys_parse_and_load() {
        // This validates the ECC_KEY_STRUCT byte layout end-to-end: a successful
        // `from_sec1_bytes` means `key[2..]` is a valid P-384 public point.
        for key in [ECC_KEY_1, ECC_KEY_2] {
            let verifier = Verifier::new(key);
            assert!(verifier.is_ok(), "embedded ECC key failed to load");
        }
    }

    #[test]
    fn key_point_is_97_bytes_uncompressed() {
        let decoded = STANDARD.decode(ECC_KEY_1).unwrap();
        let key = EccKey::parse(&decoded).unwrap();
        let point = &key.key[2..];
        assert_eq!(point.len(), 97);
        assert_eq!(point[0], 0x04, "expected SEC1 uncompressed-point tag");
    }

    #[test]
    fn bad_signature_length_is_err() {
        let verifier = Verifier::new(ECC_KEY_1).unwrap();
        assert!(verifier.verify(b"msg", &[0u8; 10]).is_err());
    }
}
