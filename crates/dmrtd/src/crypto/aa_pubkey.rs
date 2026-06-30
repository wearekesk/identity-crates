//! Active Authentication public key info.
//!
//! Parses a DER-encoded ASN.1 `SubjectPublicKeyInfo`, detects whether it
//! describes an RSA or ECC key (based on the algorithm OID), and exposes the
//! raw `SubjectPublicKey` bit-string bytes.

use thiserror::Error;

use crate::lds::tlv::{Tlv, TlvError};

/// RSA encryption OID — 1.2.840.113549.1.1.1 — encoded as DER OID bytes
/// (without the 0x06 tag or the length prefix).
const RSA_OID_BYTES: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

const TAG_SEQUENCE: u32 = 0x30;
const TAG_OID: u32 = 0x06;
const TAG_BIT_STRING: u8 = 0x03;

/// Active Authentication public key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AAPublicKeyType {
    /// RSA key (algorithm OID `1.2.840.113549.1.1.1`).
    Rsa,
    /// Any non-RSA key (default).
    Ecc,
}

/// Error type for [`AAPublicKey`] parsing.
#[derive(Debug, Error)]
pub enum AAPublicKeyError {
    #[error("Invalid SubjectPublicKeyInfo tag={0:02X}, expected tag=30")]
    InvalidSubjectPublicKeyInfoTag(u32),

    #[error("Invalid AlgorithmIdentifier tag={0:02X}, expected tag=30")]
    InvalidAlgorithmIdentifierTag(u32),

    #[error("Invalid Algorithm OID object tag={0:02X}, expected tag=06")]
    InvalidAlgorithmOidTag(u32),

    #[error("Invalid SubjectPublicKey object tag={0:02X}, expected tag=03")]
    InvalidSubjectPublicKeyTag(u8),

    #[error("SubjectPublicKey bytes missing from SubjectPublicKeyInfo")]
    MissingSubjectPublicKey,

    #[error("TLV decode error: {0}")]
    Tlv(#[from] TlvError),
}

/// Active Authentication public key info.
#[derive(Debug, Clone)]
pub struct AAPublicKey {
    /// Full DER-encoded `SubjectPublicKeyInfo` bytes.
    enc_pub_key: Vec<u8>,
    /// Inferred key type (RSA when the algorithm OID matches, otherwise ECC).
    key_type: AAPublicKeyType,
    /// The actual `SubjectPublicKey` octets: the BIT STRING content with the
    /// leading "number of unused bits" byte stripped (i.e. the bare public key,
    /// not the surrounding `0x03` TLV).
    sub_pub_key_bytes: Vec<u8>,
}

impl AAPublicKey {
    /// Parses an [`AAPublicKey`] from DER-encoded ASN.1 bytes.
    ///
    /// # Errors
    /// Returns [`AAPublicKeyError`] when the input does not match the expected
    /// `SubjectPublicKeyInfo` structure.
    pub fn from_bytes(enc_pub_key: impl Into<Vec<u8>>) -> Result<Self, AAPublicKeyError> {
        let enc_pub_key = enc_pub_key.into();

        // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
        let tv_pub_key_info = Tlv::decode(&enc_pub_key)?;
        if tv_pub_key_info.tag.value != TAG_SEQUENCE {
            return Err(AAPublicKeyError::InvalidSubjectPublicKeyInfoTag(
                tv_pub_key_info.tag.value,
            ));
        }

        // AlgorithmIdentifier ::= SEQUENCE { OID, parameters? }
        let tv_alg = Tlv::decode(&tv_pub_key_info.value)?;
        if tv_alg.tag.value != TAG_SEQUENCE {
            return Err(AAPublicKeyError::InvalidAlgorithmIdentifierTag(
                tv_alg.tag.value,
            ));
        }

        // First element of the algorithm identifier must be the algorithm OID.
        let tv_alg_oid = Tlv::decode(&tv_alg.value)?;
        if tv_alg_oid.tag.value != TAG_OID {
            return Err(AAPublicKeyError::InvalidAlgorithmOidTag(
                tv_alg_oid.tag.value,
            ));
        }

        let key_type = if tv_alg_oid.value == RSA_OID_BYTES {
            AAPublicKeyType::Rsa
        } else {
            AAPublicKeyType::Ecc
        };

        // The remainder of the outer SubjectPublicKeyInfo value, after the
        // AlgorithmIdentifier, is the SubjectPublicKey BIT STRING.
        if tv_alg.encoded_len > tv_pub_key_info.value.len() {
            return Err(AAPublicKeyError::MissingSubjectPublicKey);
        }
        let bit_string_tlv = &tv_pub_key_info.value[tv_alg.encoded_len..];

        let first = bit_string_tlv
            .first()
            .copied()
            .ok_or(AAPublicKeyError::MissingSubjectPublicKey)?;
        if first != TAG_BIT_STRING {
            return Err(AAPublicKeyError::InvalidSubjectPublicKeyTag(first));
        }

        // Decode the BIT STRING and drop the leading "unused bits" octet so the
        // accessor exposes the bare public-key bytes rather than the TLV.
        let bit_string = Tlv::decode(bit_string_tlv)?;
        let sub_pub_key_bytes = bit_string
            .value
            .split_first()
            .map(|(_unused_bits, key)| key.to_vec())
            .ok_or(AAPublicKeyError::MissingSubjectPublicKey)?;

        Ok(Self {
            enc_pub_key,
            key_type,
            sub_pub_key_bytes,
        })
    }

    /// Returns the original DER-encoded `SubjectPublicKeyInfo` bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.enc_pub_key
    }

    /// Returns the bare `SubjectPublicKey` octets (the BIT STRING content with
    /// the leading unused-bits byte removed), ready to be parsed as the public
    /// key itself.
    pub fn raw_subject_public_key(&self) -> &[u8] {
        &self.sub_pub_key_bytes
    }

    /// Returns the inferred key type.
    pub fn key_type(&self) -> AAPublicKeyType {
        self.key_type
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a SubjectPublicKeyInfo DER blob for tests:
    ///   SEQUENCE {
    ///     SEQUENCE { OID <oid_bytes>, NULL or params? },
    ///     BIT STRING <pubkey bytes>
    ///   }
    fn build_spki(oid_bytes: &[u8], pubkey_bitstring_value: &[u8]) -> Vec<u8> {
        let oid = Tlv::encode(TAG_OID, oid_bytes);
        let alg = Tlv::encode(TAG_SEQUENCE, &oid);
        let bit_string = Tlv::encode(TAG_BIT_STRING as u32, pubkey_bitstring_value);
        let mut inner = Vec::new();
        inner.extend_from_slice(&alg);
        inner.extend_from_slice(&bit_string);
        Tlv::encode(TAG_SEQUENCE, &inner)
    }

    #[test]
    fn parses_rsa_spki() {
        let pubkey = vec![0x00, 0xAB, 0xCD, 0xEF];
        let spki = build_spki(RSA_OID_BYTES, &pubkey);
        let aa = AAPublicKey::from_bytes(spki.clone()).unwrap();
        assert_eq!(aa.key_type(), AAPublicKeyType::Rsa);
        assert_eq!(aa.to_bytes(), spki.as_slice());
        // The accessor strips the BIT STRING tag/length and the unused-bits
        // byte (0x00), exposing only the key octets.
        assert_eq!(aa.raw_subject_public_key(), &[0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn parses_ecc_spki() {
        // EC public key OID: 1.2.840.10045.2.1
        let ec_oid: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        let pubkey = vec![0x00, 0x04, 0xAA, 0xBB];
        let spki = build_spki(ec_oid, &pubkey);
        let aa = AAPublicKey::from_bytes(spki).unwrap();
        assert_eq!(aa.key_type(), AAPublicKeyType::Ecc);
    }

    #[test]
    fn rejects_non_sequence_outer_tag() {
        // Build an OCTET STRING instead of a SEQUENCE at the outer level.
        let bogus = Tlv::encode(0x04, &[0x00]);
        let err = AAPublicKey::from_bytes(bogus).unwrap_err();
        assert!(matches!(
            err,
            AAPublicKeyError::InvalidSubjectPublicKeyInfoTag(_)
        ));
    }

    #[test]
    fn rejects_non_sequence_algorithm_identifier() {
        // Outer SEQUENCE containing a non-SEQUENCE (OCTET STRING) as first element.
        let inner = Tlv::encode(0x04, &[0x00]);
        let outer = Tlv::encode(TAG_SEQUENCE, &inner);
        let err = AAPublicKey::from_bytes(outer).unwrap_err();
        assert!(matches!(
            err,
            AAPublicKeyError::InvalidAlgorithmIdentifierTag(_)
        ));
    }

    #[test]
    fn rejects_non_oid_algorithm_first_element() {
        // AlgorithmIdentifier whose first element is an OCTET STRING, not an OID.
        let bad_oid = Tlv::encode(0x04, &[0x2A]);
        let alg = Tlv::encode(TAG_SEQUENCE, &bad_oid);
        let bit_string = Tlv::encode(TAG_BIT_STRING as u32, &[0x00]);
        let mut inner = Vec::new();
        inner.extend_from_slice(&alg);
        inner.extend_from_slice(&bit_string);
        let outer = Tlv::encode(TAG_SEQUENCE, &inner);
        let err = AAPublicKey::from_bytes(outer).unwrap_err();
        assert!(matches!(err, AAPublicKeyError::InvalidAlgorithmOidTag(_)));
    }

    #[test]
    fn rejects_non_bitstring_public_key() {
        // SubjectPublicKey encoded as OCTET STRING instead of BIT STRING.
        let oid = Tlv::encode(TAG_OID, RSA_OID_BYTES);
        let alg = Tlv::encode(TAG_SEQUENCE, &oid);
        let bad_pk = Tlv::encode(0x04, &[0x00]);
        let mut inner = Vec::new();
        inner.extend_from_slice(&alg);
        inner.extend_from_slice(&bad_pk);
        let outer = Tlv::encode(TAG_SEQUENCE, &inner);
        let err = AAPublicKey::from_bytes(outer).unwrap_err();
        assert!(matches!(
            err,
            AAPublicKeyError::InvalidSubjectPublicKeyTag(_)
        ));
    }

    #[test]
    fn rejects_missing_public_key() {
        // AlgorithmIdentifier present but no SubjectPublicKey after it.
        let oid = Tlv::encode(TAG_OID, RSA_OID_BYTES);
        let alg = Tlv::encode(TAG_SEQUENCE, &oid);
        let outer = Tlv::encode(TAG_SEQUENCE, &alg);
        let err = AAPublicKey::from_bytes(outer).unwrap_err();
        assert!(matches!(err, AAPublicKeyError::MissingSubjectPublicKey));
    }
}
