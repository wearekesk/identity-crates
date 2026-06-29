//! PACE protocol — pure helpers + response parsers.
//!
//! This port covers the **stateless** PACE surface — data/response parsers,
//! key derivation, authentication-token computation, nonce decryption. The
//! async state machine (`ecdh`, `dh`, `initSession`) drives ICC I/O and is
//! deferred until the ICC transport layer is ported.

use thiserror::Error;

use crate::crypto::aes::{AES_BLOCK_SIZE, AesCipher, BlockCipherMode};
use crate::crypto::des::DesedeCipher;
use crate::crypto::iso9797;
use crate::crypto::kdf::DeriveKey;
use crate::lds::asn1_object_identifiers::{
    CipherAlgorithm, KeyLength, Oie, OiePaceProtocol, TokenAgreementAlgo,
};
use crate::lds::tlv::{Tlv, TlvEmpty};
use crate::lds::tlv_set::TlvSet;
use crate::proto::access_key::AccessKey;
use crate::proto::public_key_pace::PublicKeyPace;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Tags for PACE command / response data objects — ICAO 9303 p11 §4.4.5 table 4.
pub mod exchanged_data {
    /// Step 1 — encrypted nonce (response).
    pub const ENCRYPTED_NONCE_RESPONSE: u32 = 0x80;
    /// Step 2 — map nonce (response).
    pub const MAPPING_DATA_RESPONSE: u32 = 0x82;
    /// Step 3 — key agreement (response).
    pub const EPHEMERAL_PUBLIC_KEY_RESPONSE: u32 = 0x84;
    /// Step 4 — mutual authentication (response).
    pub const AUTHENTICATION_TOKEN_RESPONSE: u32 = 0x86;
}

/// Outer tag used in PACE response APDUs.
pub const TAG_DYNAMIC_AUTHENTICATION_DATA: u32 = 0x7C;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// General PACE protocol error.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("PACEError: {0}")]
pub struct PaceError(pub String);

/// Response parse error for PACE Step 1.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("ResponseAPDUStep1PaceError: {0}")]
pub struct Step1Error(pub String);

/// Response parse error for PACE Step 2 / 3.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("ResponseAPDUStep2or3PaceError: {0}")]
pub struct Step2Or3Error(pub String);

/// Response parse error for PACE Step 4.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("ResponseAPDUStep4PaceError: {0}")]
pub struct Step4Error(pub String);

// ---------------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------------

/// Parses a PACE Step 1 response payload (encrypted nonce).
///
/// Returns the raw encrypted-nonce bytes.
pub fn parse_step1_response(data: &[u8]) -> Result<Vec<u8>, Step1Error> {
    let dyn_data = Tlv::from_bytes(data)
        .map_err(|e| Step1Error(format!("Invalid TLV: {e}")))?;
    if dyn_data.tag != TAG_DYNAMIC_AUTHENTICATION_DATA {
        return Err(Step1Error(
            "Response data does not contain dynamic authentication data".into(),
        ));
    }
    let nonce_tlv = Tlv::from_bytes(&dyn_data.value)
        .map_err(|e| Step1Error(format!("Invalid inner TLV: {e}")))?;
    if nonce_tlv.tag != exchanged_data::ENCRYPTED_NONCE_RESPONSE {
        return Err(Step1Error(
            "Dynamic authentication data does not contain encrypted nonce".into(),
        ));
    }
    Ok(nonce_tlv.value)
}

/// Parses a PACE Step 2 or Step 3 response payload (mapping / ephemeral
/// public key).
///
/// Returns the parsed public key.
pub fn parse_step2_or_3_response(
    data: &[u8],
    algo: TokenAgreementAlgo,
) -> Result<PublicKeyPace, Step2Or3Error> {
    let dyn_data = Tlv::from_bytes(data)
        .map_err(|e| Step2Or3Error(format!("Invalid TLV: {e}")))?;
    if dyn_data.tag != TAG_DYNAMIC_AUTHENTICATION_DATA {
        return Err(Step2Or3Error(
            "Response data does not contain dynamic authentication data".into(),
        ));
    }

    let mapping = Tlv::from_bytes(&dyn_data.value)
        .map_err(|e| Step2Or3Error(format!("Invalid inner TLV: {e}")))?;
    if mapping.tag != exchanged_data::MAPPING_DATA_RESPONSE
        && mapping.tag != exchanged_data::EPHEMERAL_PUBLIC_KEY_RESPONSE
    {
        return Err(Step2Or3Error(
            "Dynamic authentication data does not contain mapping data".into(),
        ));
    }
    if mapping.value.is_empty() {
        return Err(Step2Or3Error("Mapping data is empty".into()));
    }

    match algo {
        TokenAgreementAlgo::Ecdh => {
            if mapping.value[0] != 0x04 {
                return Err(Step2Or3Error(
                    "Token agreement is ECDH, but first byte is not 0x04".into(),
                ));
            }
            let xy = &mapping.value[1..];
            PublicKeyPace::ecdh_from_hex(xy).ok_or_else(|| {
                Step2Or3Error(
                    "Mapping data contains EC public key with odd length (no X/Y split)".into(),
                )
            })
        }
        TokenAgreementAlgo::Dh => Ok(PublicKeyPace::new_dh(mapping.value)),
    }
}

/// Parses a PACE Step 4 response payload (authentication token).
///
/// Returns the ICC-computed `T_IC` token.
pub fn parse_step4_response(data: &[u8]) -> Result<Vec<u8>, Step4Error> {
    let dyn_data = Tlv::from_bytes(data)
        .map_err(|e| Step4Error(format!("Invalid TLV: {e}")))?;
    if dyn_data.tag != TAG_DYNAMIC_AUTHENTICATION_DATA {
        return Err(Step4Error(
            "Response data does not contain dynamic authentication data".into(),
        ));
    }
    let token_tlv = Tlv::from_bytes(&dyn_data.value)
        .map_err(|e| Step4Error(format!("Invalid inner TLV: {e}")))?;
    if token_tlv.tag != exchanged_data::AUTHENTICATION_TOKEN_RESPONSE {
        return Err(Step4Error(
            "Dynamic authentication data does not contain authentication token".into(),
        ));
    }
    if token_tlv.value.is_empty() {
        return Err(Step4Error("Authentication token is empty".into()));
    }
    Ok(token_tlv.value)
}

// ---------------------------------------------------------------------------
// Data generators
// ---------------------------------------------------------------------------

/// Generates the `ENCODING INPUT` TLV: `7F49 { 06 <oid-bytes> || (84|86) <pub> }`.
///
/// This mirrors the reference's pragmatic OID-body encoding: it takes
/// the arc values beginning at index 1 of the OIE identifier — a shortcut
/// that works because every arc in the PACE OIDs is `< 128` and the first two
/// arcs encode as a single byte under DER.
pub fn generate_encoding_input_data(
    mechanism: &OiePaceProtocol,
    ephemeral_public: &PublicKeyPace,
) -> Vec<u8> {
    const INPUT_DATA_TAG: u32 = 0x7F49;
    const OBJECT_IDENTIFIER_TAG: u32 = 0x06;
    const DH_POINT_TAG: u32 = 0x84;
    const EC_POINT_TAG: u32 = 0x86;

    let oid_body = oid_body_bytes(&mechanism.oie);
    let oid_tlv = Tlv::encode(OBJECT_IDENTIFIER_TAG, &oid_body);

    let pub_tlv = match ephemeral_public {
        PublicKeyPace::Ecdh { .. } => {
            let mut body = vec![0x04]; // uncompressed point tag
            body.extend_from_slice(&ephemeral_public.to_bytes());
            Tlv::encode(EC_POINT_TAG, &body)
        }
        PublicKeyPace::Dh { .. } => Tlv::encode(DH_POINT_TAG, &ephemeral_public.to_bytes()),
    };

    let mut body = oid_tlv;
    body.extend_from_slice(&pub_tlv);
    Tlv::encode(INPUT_DATA_TAG, &body)
}

/// Generates the MSE:Set AT data field — a SET of:
/// - `80` Cryptographic Mechanism Reference (OID body, arcs from index 1)
/// - `83` Password / Reference of Public Key (e.g. MRZ `0x01`, CAN `0x02`)
pub fn generate_mse_set_at_data(mechanism: &OiePaceProtocol, pace_ref_type: u8) -> Vec<u8> {
    const CRYPTOGRAPHIC_MECHANISM_REF_TAG: u32 = 0x80;
    const PASSWORD_REF_PUB_KEY_TAG: u32 = 0x83;
    let oid_body = oid_body_bytes(&mechanism.oie);
    let cm = Tlv::new(CRYPTOGRAPHIC_MECHANISM_REF_TAG, oid_body);
    let drp = Tlv::from_int_value(PASSWORD_REF_PUB_KEY_TAG, pace_ref_type as u64);
    let set = TlvSet::with_tlvs(vec![cm, drp]);
    set.to_bytes()
}

/// Data field for `GENERAL AUTHENTICATE` — step 1 (empty TLV `7C 00`).
pub fn generate_general_authenticate_data_step1() -> Vec<u8> {
    TlvEmpty::new(0x7C).to_bytes()
}

/// Data field for `GENERAL AUTHENTICATE` — step 2 (mapping) or step 3
/// (ephemeral). Set `is_ephemeral = true` for step 3.
pub fn generate_general_authenticate_data_step2_or_3(
    public: &PublicKeyPace,
    is_ephemeral: bool,
) -> Vec<u8> {
    const DYNAMIC_AUTH_DATA_TAG: u32 = 0x7C;
    const MAPPING_DATA_TAG: u32 = 0x81;
    const MAPPING_DATA_EPHEMERAL_TAG: u32 = 0x83;
    let public_key_tag = if is_ephemeral {
        MAPPING_DATA_EPHEMERAL_TAG
    } else {
        MAPPING_DATA_TAG
    };

    let mapping_value = match public {
        PublicKeyPace::Ecdh { .. } => {
            let mut body = vec![0x04];
            body.extend_from_slice(&public.to_bytes());
            body
        }
        PublicKeyPace::Dh { .. } => public.to_bytes(),
    };
    let mapping_tlv = Tlv::encode(public_key_tag, &mapping_value);
    Tlv::encode(DYNAMIC_AUTH_DATA_TAG, &mapping_tlv)
}

/// Data field for `GENERAL AUTHENTICATE` — step 4 (authentication token).
pub fn generate_general_authenticate_data_step4(auth_token: &[u8]) -> Vec<u8> {
    const DYNAMIC_AUTH_DATA_TAG: u32 = 0x7C;
    const AUTHENTICATION_TOKEN_TAG: u32 = 0x85;
    let auth_tlv = Tlv::encode(AUTHENTICATION_TOKEN_TAG, auth_token);
    Tlv::encode(DYNAMIC_AUTH_DATA_TAG, &auth_tlv)
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derives `K_Enc` for the given PACE protocol from the shared secret `seed`.
pub fn calculate_enc_key(protocol: &OiePaceProtocol, seed: &[u8]) -> Result<Vec<u8>, PaceError> {
    match (protocol.cipher_algorithm, protocol.key_length) {
        (CipherAlgorithm::Aes, KeyLength::S128) => Ok(DeriveKey::aes128(seed, false)),
        (CipherAlgorithm::Aes, KeyLength::S192) => Ok(DeriveKey::aes192(seed, false)),
        (CipherAlgorithm::Aes, KeyLength::S256) => Ok(DeriveKey::aes256(seed, false)),
        (CipherAlgorithm::DeSede, _) => Ok(DeriveKey::des_ede(seed, false)),
    }
}

/// Derives `K_Mac` for the given PACE protocol from the shared secret `seed`.
pub fn calculate_mac_key(protocol: &OiePaceProtocol, seed: &[u8]) -> Result<Vec<u8>, PaceError> {
    match (protocol.cipher_algorithm, protocol.key_length) {
        (CipherAlgorithm::Aes, KeyLength::S128) => Ok(DeriveKey::cmac128(seed)),
        (CipherAlgorithm::Aes, KeyLength::S192) => Ok(DeriveKey::cmac192(seed)),
        (CipherAlgorithm::Aes, KeyLength::S256) => Ok(DeriveKey::cmac256(seed)),
        // K_mac for 3DES uses the MAC-mode KDF (counter 2), NOT the ENC KDF.
        // ICAO 9303 Part 11 §9.7.1: K_enc = KDF(K,1), K_mac = KDF(K,2).
        (CipherAlgorithm::DeSede, _) => Ok(DeriveKey::iso9797_mac_alg3(seed)),
    }
}

// ---------------------------------------------------------------------------
// Authentication token
// ---------------------------------------------------------------------------

/// Computes the PACE authentication token `T = MAC(K_Mac, input_data)`.
///
/// For AES this is AES-CMAC (truncated to 8 bytes); for 3DES this is
/// ISO 9797-1 MAC algorithm 3 with padding.
pub fn calculate_auth_token(
    protocol: &OiePaceProtocol,
    input_data: &[u8],
    mac_key: &[u8],
) -> Result<Vec<u8>, PaceError> {
    match protocol.cipher_algorithm {
        CipherAlgorithm::Aes => {
            let cipher = AesCipher::new(protocol.key_length);
            cipher
                .calculate_cmac(input_data, mac_key)
                .map_err(|e| PaceError(format!("AES-CMAC failed: {e}")))
        }
        CipherAlgorithm::DeSede => iso9797::mac_alg3(mac_key, input_data, true)
            .map_err(|e| PaceError(format!("ISO 9797-1 MAC alg 3 failed: {e}"))),
    }
}

// ---------------------------------------------------------------------------
// Nonce decryption
// ---------------------------------------------------------------------------

/// Decrypts the encrypted nonce received in Step 1 using the access-key
/// derived `K_π`.
pub fn decrypt_nonce(
    protocol: &OiePaceProtocol,
    nonce: &[u8],
    access_key: &dyn AccessKey,
) -> Result<Vec<u8>, PaceError> {
    let k_pi = access_key
        .kpi(protocol.cipher_algorithm, protocol.key_length)
        .map_err(PaceError)?;
    match protocol.cipher_algorithm {
        CipherAlgorithm::Aes => {
            let cipher = AesCipher::new(protocol.key_length);
            // PACE decrypts the encrypted nonce with an all-zero IV (ICAO 9303
            // p11 §4.4.1); the IV must now be passed explicitly.
            let iv = [0u8; AES_BLOCK_SIZE];
            cipher
                .decrypt(nonce, &k_pi, Some(&iv), BlockCipherMode::Cbc)
                .map_err(|e| PaceError(format!("AES decrypt failed: {e}")))
        }
        CipherAlgorithm::DeSede => {
            let iv = [0u8; DesedeCipher::BLOCK_SIZE];
            let cipher = DesedeCipher::new(&k_pi, &iv)
                .map_err(|e| PaceError(format!("3DES init failed: {e}")))?;
            cipher
                .decrypt(nonce, false)
                .map_err(|e| PaceError(format!("3DES decrypt failed: {e}")))
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the OID body bytes used by PACE — the OIE arc values from index 1
/// onwards, each cast to a single byte. See [`generate_encoding_input_data`]
/// for why this shortcut is safe for every defined PACE OID.
fn oid_body_bytes(oie: &Oie) -> Vec<u8> {
    // An empty identifier has no arcs to skip; `[1..]` would panic on it.
    if oie.identifier.is_empty() {
        return Vec::new();
    }
    oie.identifier[1..].iter().map(|&a| a as u8).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::can_key::CanKey;

    fn oie_aes128_ecdh_gm() -> OiePaceProtocol {
        OiePaceProtocol::new(
            "0.4.0.127.0.7.2.2.4.2.2",
            "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
            vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 2],
        )
        .unwrap()
    }

    fn oie_desede_dh_gm() -> OiePaceProtocol {
        OiePaceProtocol::new(
            "0.4.0.127.0.7.2.2.4.1.1",
            "id-PACE-DH-GM-3DES-CBC-CBC",
            vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 1],
        )
        .unwrap()
    }

    // ---------------- Response parsers ----------------

    #[test]
    fn step1_parses_encrypted_nonce() {
        let inner = Tlv::encode(exchanged_data::ENCRYPTED_NONCE_RESPONSE, &[0xAAu8; 16]);
        let outer = Tlv::encode(TAG_DYNAMIC_AUTHENTICATION_DATA, &inner);
        let nonce = parse_step1_response(&outer).unwrap();
        assert_eq!(nonce, vec![0xAAu8; 16]);
    }

    #[test]
    fn step1_rejects_wrong_outer_tag() {
        let inner = Tlv::encode(exchanged_data::ENCRYPTED_NONCE_RESPONSE, &[0; 16]);
        let outer = Tlv::encode(0x7D, &inner);
        assert!(parse_step1_response(&outer).is_err());
    }

    #[test]
    fn step1_rejects_wrong_inner_tag() {
        let inner = Tlv::encode(0x81, &[0; 16]);
        let outer = Tlv::encode(TAG_DYNAMIC_AUTHENTICATION_DATA, &inner);
        assert!(parse_step1_response(&outer).is_err());
    }

    #[test]
    fn step2_parses_ecdh_public() {
        // Build: 7C { 82 { 04 || XY } }
        let mut mapping_val = vec![0x04];
        mapping_val.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let inner = Tlv::encode(exchanged_data::MAPPING_DATA_RESPONSE, &mapping_val);
        let outer = Tlv::encode(TAG_DYNAMIC_AUTHENTICATION_DATA, &inner);
        let pk = parse_step2_or_3_response(&outer, TokenAgreementAlgo::Ecdh).unwrap();
        assert_eq!(pk.to_relevant_bytes(), vec![0x01, 0x02]);
        assert_eq!(pk.to_bytes(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn step2_parses_dh_public() {
        let inner = Tlv::encode(exchanged_data::MAPPING_DATA_RESPONSE, &[0xDE, 0xAD]);
        let outer = Tlv::encode(TAG_DYNAMIC_AUTHENTICATION_DATA, &inner);
        let pk = parse_step2_or_3_response(&outer, TokenAgreementAlgo::Dh).unwrap();
        assert_eq!(pk.to_bytes(), vec![0xDE, 0xAD]);
    }

    #[test]
    fn step3_accepts_ephemeral_tag() {
        let inner = Tlv::encode(exchanged_data::EPHEMERAL_PUBLIC_KEY_RESPONSE, &[0xAA]);
        let outer = Tlv::encode(TAG_DYNAMIC_AUTHENTICATION_DATA, &inner);
        assert!(parse_step2_or_3_response(&outer, TokenAgreementAlgo::Dh).is_ok());
    }

    #[test]
    fn step2_ecdh_rejects_missing_0x04_prefix() {
        let inner = Tlv::encode(exchanged_data::MAPPING_DATA_RESPONSE, &[0x02, 0x11, 0x22]);
        let outer = Tlv::encode(TAG_DYNAMIC_AUTHENTICATION_DATA, &inner);
        assert!(parse_step2_or_3_response(&outer, TokenAgreementAlgo::Ecdh).is_err());
    }

    #[test]
    fn step4_parses_auth_token() {
        let inner = Tlv::encode(exchanged_data::AUTHENTICATION_TOKEN_RESPONSE, &[0u8; 8]);
        let outer = Tlv::encode(TAG_DYNAMIC_AUTHENTICATION_DATA, &inner);
        let t = parse_step4_response(&outer).unwrap();
        assert_eq!(t.len(), 8);
    }

    #[test]
    fn step4_empty_token_errors_about_authentication_token() {
        let inner = Tlv::encode(exchanged_data::AUTHENTICATION_TOKEN_RESPONSE, &[]);
        let outer = Tlv::encode(TAG_DYNAMIC_AUTHENTICATION_DATA, &inner);
        let err = parse_step4_response(&outer).unwrap_err();
        assert!(err.0.contains("Authentication token"));
    }

    // ---------------- Data generators ----------------

    #[test]
    fn encoding_input_data_has_expected_outer_tag() {
        let proto = oie_aes128_ecdh_gm();
        let pk = PublicKeyPace::new_ecdh_fixed(
            num_bigint::BigUint::from(0xAABBCCDDu32),
            num_bigint::BigUint::from(0x11223344u32),
            4,
        )
        .unwrap();
        let out = generate_encoding_input_data(&proto, &pk);
        // Outer tag 0x7F49 is a two-byte BER tag: 0x7F 0x49
        assert_eq!(out[0], 0x7F);
        assert_eq!(out[1], 0x49);
    }

    #[test]
    fn mse_set_at_data_encodes_oid_and_ref_tag() {
        let proto = oie_aes128_ecdh_gm();
        let out = generate_mse_set_at_data(&proto, 0x01);
        // First element: tag 0x80, length N, OID body; second element: 0x83, 0x01, 0x01.
        assert_eq!(out[0], 0x80);
        let oid_len = out[1] as usize;
        assert_eq!(&out[2..2 + oid_len], &oid_body_bytes(&proto.oie)[..]);
        let pos = 2 + oid_len;
        assert_eq!(out[pos], 0x83);
        assert_eq!(out[pos + 1], 0x01);
        assert_eq!(out[pos + 2], 0x01);
    }

    #[test]
    fn step1_data_is_empty_tlv() {
        let out = generate_general_authenticate_data_step1();
        assert_eq!(out, vec![0x7C, 0x00]);
    }

    #[test]
    fn step2_data_wraps_mapping() {
        let pk = PublicKeyPace::new_dh(vec![0x01, 0x02, 0x03]);
        let out = generate_general_authenticate_data_step2_or_3(&pk, false);
        // 7C <len> 81 <len> 01 02 03
        assert_eq!(out[0], 0x7C);
        assert_eq!(out[2], 0x81);
    }

    #[test]
    fn step3_data_uses_ephemeral_tag() {
        let pk = PublicKeyPace::new_dh(vec![0x01]);
        let out = generate_general_authenticate_data_step2_or_3(&pk, true);
        assert_eq!(out[2], 0x83); // ephemeral public key tag
    }

    #[test]
    fn step4_data_wraps_auth_token() {
        let out = generate_general_authenticate_data_step4(&[0xAB, 0xCD]);
        // 7C <len> 85 <len> AB CD
        assert_eq!(out[0], 0x7C);
        assert_eq!(out[2], 0x85);
        assert_eq!(&out[4..], &[0xAB, 0xCD]);
    }

    // ---------------- Key derivation ----------------

    #[test]
    fn enc_and_mac_keys_aes128_are_16_bytes() {
        let proto = oie_aes128_ecdh_gm();
        let seed = [0x11u8; 32];
        assert_eq!(calculate_enc_key(&proto, &seed).unwrap().len(), 16);
        assert_eq!(calculate_mac_key(&proto, &seed).unwrap().len(), 16);
    }

    #[test]
    fn enc_and_mac_keys_desede_are_16_bytes() {
        let proto = oie_desede_dh_gm();
        let seed = [0x22u8; 32];
        assert_eq!(calculate_enc_key(&proto, &seed).unwrap().len(), 16);
        assert_eq!(calculate_mac_key(&proto, &seed).unwrap().len(), 16);
    }

    /// K_mac for 3DES must be derived with the MAC-mode KDF (counter 2), not
    /// the ENC KDF (counter 1) — so it must differ from K_enc and must equal
    /// the ISO 9797-1 MAC alg 3 derivation. ICAO 9303 Part 11 §9.7.1.
    #[test]
    fn desede_mac_key_uses_mac_kdf_not_enc_kdf() {
        let proto = oie_desede_dh_gm();
        let seed = [0x22u8; 32];
        let enc = calculate_enc_key(&proto, &seed).unwrap();
        let mac = calculate_mac_key(&proto, &seed).unwrap();
        assert_ne!(enc, mac, "3DES K_enc and K_mac must differ");
        assert_eq!(mac, DeriveKey::iso9797_mac_alg3(&seed));
        assert_eq!(enc, DeriveKey::des_ede(&seed, false));
    }

    #[test]
    fn oid_body_bytes_handles_empty_identifier() {
        let oie = Oie::new("", "", Vec::new());
        assert!(oid_body_bytes(&oie).is_empty());
    }

    // ---------------- Auth token ----------------

    #[test]
    fn auth_token_aes128_is_8_bytes() {
        let proto = oie_aes128_ecdh_gm();
        let mac_key = [0x33u8; 16];
        let t = calculate_auth_token(&proto, &[0u8; 16], &mac_key).unwrap();
        assert_eq!(t.len(), 8);
    }

    #[test]
    fn auth_token_desede_is_8_bytes() {
        let proto = oie_desede_dh_gm();
        let mac_key = [0x44u8; 16];
        let t = calculate_auth_token(&proto, &[0u8; 16], &mac_key).unwrap();
        assert_eq!(t.len(), 8);
    }

    // ---------------- Nonce decryption ----------------

    #[test]
    fn decrypt_nonce_with_can_key_aes128_roundtrip() {
        let proto = oie_aes128_ecdh_gm();
        let can = CanKey::new("123456").unwrap();
        let k_pi = can.kpi(proto.cipher_algorithm, proto.key_length).unwrap();
        // Encrypt a 16-byte nonce under k_pi / zero IV.
        let cipher = AesCipher::new(proto.key_length);
        let iv = [0u8; AES_BLOCK_SIZE];
        let pt = [0xA1u8; 16];
        let ct = cipher
            .encrypt(&pt, &k_pi, Some(&iv), BlockCipherMode::Cbc, false)
            .unwrap();
        let decrypted = decrypt_nonce(&proto, &ct, &can).unwrap();
        assert_eq!(decrypted, pt);
    }

    /// `decrypt_nonce` accepts an AES key longer than one block — exercises
    /// the AES-256 + PACE-ECDH path with a dummy access key whose `K_π` is a
    /// fixed 32-byte key.
    #[test]
    fn decrypt_nonce_aes256_with_dummy_access_key() {
        use crate::lds::asn1_object_identifiers::{KeyLength, TokenAgreementAlgo};

        struct DummyKey {
            kpi: Vec<u8>,
        }
        impl crate::proto::access_key::AccessKey for DummyKey {
            fn pace_ref_key_tag(&self) -> u8 {
                0
            }
            fn kpi(
                &self,
                _: CipherAlgorithm,
                _: KeyLength,
            ) -> Result<Vec<u8>, String> {
                Ok(self.kpi.clone())
            }
        }

        let proto = OiePaceProtocol::new(
            "0.4.0.127.0.7.2.2.4.2.4",
            "id-PACE-ECDH-GM-AES-CBC-CMAC-256",
            vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 4],
        )
        .unwrap();
        assert_eq!(proto.token_agreement_algorithm, TokenAgreementAlgo::Ecdh);
        assert_eq!(proto.key_length, KeyLength::S256);

        let kpi =
            hex::decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
                .unwrap();
        let nonce = hex::decode("A1A2A3A4A5A6A7A8A9AAABACADAEAFB0").unwrap();

        let cipher = AesCipher::new(KeyLength::S256);
        let iv = [0u8; AES_BLOCK_SIZE];
        let encrypted = cipher
            .encrypt(&nonce, &kpi, Some(&iv), BlockCipherMode::Cbc, false)
            .unwrap();

        let dummy = DummyKey { kpi: kpi.clone() };
        let decrypted = decrypt_nonce(&proto, &encrypted, &dummy).unwrap();
        assert_eq!(decrypted, nonce);
    }
}
