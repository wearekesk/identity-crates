//! Basic Access Control (BAC) protocol primitives.
//!
//! This module implements the **pure** BAC primitives (nonce handling, session
//! key derivation, MAC / encryption helpers, SSC construction). They are
//! transport-agnostic: callers drive the actual APDU exchange themselves and
//! build the secure-messaging session with the [`establish_sm`] constructor.
//!
//! For a ready-made synchronous handshake driver that sequences the APDUs
//! around these helpers, see [`BacSession`](crate::proto::bac_session::BacSession).

use thiserror::Error;

use crate::crypto::crypto_utils::constant_time_eq;
use crate::crypto::des::DesedeCipher;
use crate::crypto::iso9797;
use crate::crypto::kdf::DeriveKey;
use crate::proto::des_smcipher::DesSmCipher;
use crate::proto::mrtd_sm::MrtdSM;
use crate::proto::ssc::DesedeSSC;
use crate::types::pair::Pair;

/// BAC nonce length (`RND.IC`, `RND.IFD`) — 8 bytes.
pub const NONCE_LEN: usize = 8;
/// BAC key length (`K.IC`, `K.IFD`) — 16 bytes.
pub const K_LEN: usize = 16;
/// Payload length for `S` and `R` — 32 bytes.
pub const S_LEN: usize = 2 * NONCE_LEN + K_LEN;
/// Encrypted payload length (same as `S`).
pub const E_LEN: usize = S_LEN;
/// ISO 9797-1 Alg 3 MAC length — 8 bytes.
pub const MAC_LEN: usize = 8;

/// BAC protocol error.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("BACError: {0}")]
pub struct BacError(pub String);

// ---------------------------------------------------------------------------
// Pure helpers (visible for testing)
// ---------------------------------------------------------------------------

/// Generates `S = RND.IFD || RND.IC || K.IFD` (32 bytes).
pub fn generate_s(rnd_ifd: &[u8], rnd_icc: &[u8], kifd: &[u8]) -> Result<Vec<u8>, BacError> {
    check_len(rnd_ifd, NONCE_LEN, "RND.IFD")?;
    check_len(rnd_icc, NONCE_LEN, "RND.IC")?;
    check_len(kifd, K_LEN, "K.IFD")?;
    let mut out = Vec::with_capacity(S_LEN);
    out.extend_from_slice(rnd_ifd);
    out.extend_from_slice(rnd_icc);
    out.extend_from_slice(kifd);
    Ok(out)
}

/// Concatenates the encrypted cryptogram `E_ifd` and its MAC `M_ifd` for the
/// EXTERNAL AUTHENTICATE data field.
pub fn generate_ea_data(e_ifd: &[u8], m_ifd: &[u8]) -> Result<Vec<u8>, BacError> {
    check_len(e_ifd, E_LEN, "E.IFD")?;
    check_len(m_ifd, MAC_LEN, "M.IFD")?;
    let mut out = Vec::with_capacity(E_LEN + MAC_LEN);
    out.extend_from_slice(e_ifd);
    out.extend_from_slice(m_ifd);
    Ok(out)
}

/// 3DES-CBC encrypt `S` with `K_enc` (zero IV, no padding).
pub fn encrypt_s(k_enc: &[u8], s: &[u8]) -> Result<Vec<u8>, BacError> {
    check_len(k_enc, K_LEN, "K_enc")?;
    check_len(s, S_LEN, "S")?;
    let iv = [0u8; DesedeCipher::BLOCK_SIZE];
    let cipher = DesedeCipher::new(k_enc, &iv).map_err(|e| BacError(e.to_string()))?;
    cipher
        .encrypt(s, false)
        .map_err(|e| BacError(e.to_string()))
}

/// 3DES-CBC decrypt `E_icc` with `K_dec` (zero IV, no padding).
pub fn decrypt_e_icc(k_dec: &[u8], e_icc: &[u8]) -> Result<Vec<u8>, BacError> {
    check_len(k_dec, K_LEN, "K_dec")?;
    check_len(e_icc, E_LEN, "E_icc")?;
    let iv = [0u8; DesedeCipher::BLOCK_SIZE];
    let cipher = DesedeCipher::new(k_dec, &iv).map_err(|e| BacError(e.to_string()))?;
    cipher
        .decrypt(e_icc, false)
        .map_err(|e| BacError(e.to_string()))
}

/// ISO 9797-1 MAC algorithm 3 over `E_ifd` (message is padded).
pub fn mac_e(k_mac: &[u8], e_ifd: &[u8]) -> Result<Vec<u8>, BacError> {
    check_len(k_mac, K_LEN, "K_mac")?;
    check_len(e_ifd, E_LEN, "E.IFD")?;
    iso9797::mac_alg3(k_mac, e_ifd, true).map_err(|e| BacError(e.to_string()))
}

/// Splits the ICC EXTERNAL AUTHENTICATE response into `(E_icc, M_icc)`.
pub fn extract_eicc_and_micc(icc_ea_data: &[u8]) -> Result<Pair<Vec<u8>, Vec<u8>>, BacError> {
    check_len(icc_ea_data, E_LEN + MAC_LEN, "ICCea_data")?;
    let eicc = icc_ea_data[..E_LEN].to_vec();
    let micc = icc_ea_data[E_LEN..].to_vec();
    Ok(Pair::new(eicc, micc))
}

/// Verifies `E_icc` against `M_icc` using the `K_mac` ISO 9797-1 MAC.
pub fn verify_eicc(eicc: &[u8], k_mac: &[u8], micc: &[u8]) -> Result<bool, BacError> {
    let expected = mac_e(k_mac, eicc)?;
    check_len(micc, MAC_LEN, "M_icc")?;
    Ok(constant_time_eq(&expected, micc))
}

/// Verifies that the `RND.IFD` slice in `R` matches the one we sent, and
/// returns `K.ICC` (the last 16 bytes of `R`).
pub fn verify_rnd_ifd_and_extract_kicc(rnd_ifd: &[u8], r: &[u8]) -> Result<Vec<u8>, BacError> {
    check_len(rnd_ifd, NONCE_LEN, "RND.IFD")?;
    check_len(r, S_LEN, "R")?;
    let extracted = &r[NONCE_LEN..2 * NONCE_LEN];
    if !constant_time_eq(extracted, rnd_ifd) {
        return Err(BacError(format!(
            "Extracted RND.IFD={} from R differs from generated RND.IFD={}",
            hex::encode(extracted),
            hex::encode(rnd_ifd)
        )));
    }
    Ok(r[2 * NONCE_LEN..].to_vec())
}

/// Derives the session keys `(KS_enc, KS_mac)` from `K.IFD` XOR `K.ICC`.
pub fn calculate_session_keys(
    kifd: &[u8],
    kicc: &[u8],
) -> Result<Pair<Vec<u8>, Vec<u8>>, BacError> {
    check_len(kifd, K_LEN, "K.IFD")?;
    check_len(kicc, K_LEN, "K.ICC")?;
    let mut key_seed = vec![0u8; K_LEN];
    for i in 0..K_LEN {
        key_seed[i] = kifd[i] ^ kicc[i];
    }
    let ks_enc = DeriveKey::des_ede(&key_seed, false);
    let ks_mac = DeriveKey::iso9797_mac_alg3(&key_seed);
    Ok(Pair::new(ks_enc, ks_mac))
}

/// Builds the 8-byte BAC SSC from the second halves of `RND.IC` and
/// `RND.IFD`.
pub fn calculate_ssc(rnd_ifd: &[u8], rnd_icc: &[u8]) -> Result<DesedeSSC, BacError> {
    check_len(rnd_ifd, NONCE_LEN, "RND.IFD")?;
    check_len(rnd_icc, NONCE_LEN, "RND.IC")?;
    let suffix = NONCE_LEN / 2;
    let mut out = Vec::with_capacity(NONCE_LEN);
    out.extend_from_slice(&rnd_icc[suffix..]);
    out.extend_from_slice(&rnd_ifd[suffix..]);
    DesedeSSC::new(&out).map_err(|e| BacError(e.to_string()))
}

/// Builds the [`MrtdSM`] session from the derived session keys and SSC.
pub fn establish_sm(
    ks_enc: &[u8],
    ks_mac: &[u8],
    ssc: DesedeSSC,
) -> Result<MrtdSM<DesSmCipher>, BacError> {
    let cipher = DesSmCipher::new(ks_enc, ks_mac.to_vec()).map_err(|e| BacError(e.to_string()))?;
    Ok(MrtdSM::new(cipher, ssc.0))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn check_len(buf: &[u8], expected: usize, name: &str) -> Result<(), BacError> {
    if buf.len() != expected {
        return Err(BacError(format!(
            "{name} length {got} != expected {expected}",
            got = buf.len()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! ICAO 9303 p11 Appendix D.3 BAC worked example.
    //!
    //! All expected values are taken directly from the specification:
    //!   K_enc    = AB94FDECF2674FDFB9B391F85D7F76F2
    //!   K_mac    = 7962D9ECE03D1ACD4C76089DCE131543
    //!   RND.IC   = 4608F91988702212
    //!   RND.IFD  = 781723860C06C226
    //!   K.IFD    = 0B795240CB7049B01C19B33E32804F0B
    //!   S        = 781723860C06C2264608F91988702212 0B795240CB7049B01C19B33E32804F0B
    //!   K.ICC    = 0B4F80323EB3191CB04970CB4052790B
    //!   SSC      = 887022120C06C226
    //!   KSenc    = 979EC13B1CBFE9DCD01AB0FED307EAE5
    //!   KSmac    = F1CB1F1FB5ADF208806B89DC579DC1F8

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        ::hex::decode(s).unwrap()
    }

    #[test]
    fn generate_s_concatenates_fields() {
        let s = generate_s(
            &hex("781723860C06C226"),
            &hex("4608F91988702212"),
            &hex("0B795240CB7049B01C19B33E32804F0B"),
        )
        .unwrap();
        assert_eq!(s.len(), S_LEN);
        assert_eq!(&s[..NONCE_LEN], hex("781723860C06C226").as_slice());
        assert_eq!(
            &s[NONCE_LEN..2 * NONCE_LEN],
            hex("4608F91988702212").as_slice()
        );
    }

    #[test]
    fn calculate_ssc_matches_icao_d3_vector() {
        let ssc = calculate_ssc(&hex("781723860C06C226"), &hex("4608F91988702212")).unwrap();
        assert_eq!(ssc.0.to_bytes(), hex("887022120C06C226"));
    }

    #[test]
    fn calculate_session_keys_matches_icao_d3_vector() {
        let pair = calculate_session_keys(
            &hex("0B795240CB7049B01C19B33E32804F0B"),
            &hex("0B4F80323EB3191CB04970CB4052790B"),
        )
        .unwrap();
        assert_eq!(pair.first, hex("979EC13B1CBFE9DCD01AB0FED307EAE5"));
        assert_eq!(pair.second, hex("F1CB1F1FB5ADF208806B89DC579DC1F8"));
    }

    #[test]
    fn encrypt_s_roundtrips_with_decrypt() {
        let kenc = hex("AB94FDECF2674FDFB9B391F85D7F76F2");
        let s = generate_s(
            &hex("781723860C06C226"),
            &hex("4608F91988702212"),
            &hex("0B795240CB7049B01C19B33E32804F0B"),
        )
        .unwrap();
        let e = encrypt_s(&kenc, &s).unwrap();
        let back = decrypt_e_icc(&kenc, &e).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn mac_e_and_verify_eicc_agree() {
        let kmac = hex("7962D9ECE03D1ACD4C76089DCE131543");
        let eifd = vec![0xAAu8; E_LEN];
        let m = mac_e(&kmac, &eifd).unwrap();
        assert!(verify_eicc(&eifd, &kmac, &m).unwrap());

        // Tampered MAC must fail.
        let mut bad_mac = m.clone();
        bad_mac[0] ^= 0x01;
        assert!(!verify_eicc(&eifd, &kmac, &bad_mac).unwrap());
    }

    #[test]
    fn extract_eicc_and_micc_splits_at_32() {
        let payload: Vec<u8> = (0..(E_LEN + MAC_LEN) as u8).collect();
        let pair = extract_eicc_and_micc(&payload).unwrap();
        assert_eq!(pair.first.len(), E_LEN);
        assert_eq!(pair.second.len(), MAC_LEN);
        assert_eq!(pair.first[0], 0);
        assert_eq!(pair.second[0], E_LEN as u8);
    }

    #[test]
    fn verify_rnd_ifd_roundtrip() {
        let rnd_ifd = hex("781723860C06C226");
        let rnd_icc = hex("4608F91988702212");
        let kicc = hex("0B4F80323EB3191CB04970CB4052790B");
        let mut r = Vec::with_capacity(S_LEN);
        r.extend_from_slice(&rnd_icc);
        r.extend_from_slice(&rnd_ifd);
        r.extend_from_slice(&kicc);
        let extracted = verify_rnd_ifd_and_extract_kicc(&rnd_ifd, &r).unwrap();
        assert_eq!(extracted, kicc);
    }

    #[test]
    fn verify_rnd_ifd_rejects_mismatch() {
        let rnd_ifd = hex("781723860C06C226");
        let mut r = vec![0u8; S_LEN];
        // Place wrong RND.IFD in the middle.
        r[NONCE_LEN..2 * NONCE_LEN].copy_from_slice(&hex("FFFFFFFFFFFFFFFF"));
        let err = verify_rnd_ifd_and_extract_kicc(&rnd_ifd, &r).unwrap_err();
        assert!(err.0.contains("differs from generated"));
    }

    #[test]
    fn establish_sm_returns_working_session() {
        let kenc = hex("979EC13B1CBFE9DCD01AB0FED307EAE5");
        let kmac = hex("F1CB1F1FB5ADF208806B89DC579DC1F8");
        let ssc = calculate_ssc(&hex("781723860C06C226"), &hex("4608F91988702212")).unwrap();
        let _sm = establish_sm(&kenc, &kmac, ssc).unwrap();
    }

    #[test]
    fn length_checks_reject_bad_inputs() {
        assert!(generate_s(&[0; 7], &[0; 8], &[0; 16]).is_err());
        assert!(generate_s(&[0; 8], &[0; 7], &[0; 16]).is_err());
        assert!(generate_s(&[0; 8], &[0; 8], &[0; 15]).is_err());
        assert!(encrypt_s(&[0; 15], &[0; 32]).is_err());
        assert!(calculate_session_keys(&[0; 15], &[0; 16]).is_err());
    }

    // ICAO 9303 p11 Appendix D.3 full intermediate-value assertions.
    // Every byte string below is read directly from the specification.
    #[test]
    fn icao_d3_encrypt_s_matches_expected_eifd() {
        let kenc = hex("AB94FDECF2674FDFB9B391F85D7F76F2");
        let s = hex("781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B");
        assert_eq!(
            hex::encode_upper(encrypt_s(&kenc, &s).unwrap()),
            "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2"
        );
    }

    #[test]
    fn icao_d3_mac_eifd_matches_expected_mifd() {
        let kmac = hex("7962D9ECE03D1ACD4C76089DCE131543");
        let eifd = hex("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2");
        assert_eq!(
            hex::encode_upper(mac_e(&kmac, &eifd).unwrap()),
            "5F1448EEA8AD90A7"
        );
    }

    #[test]
    fn icao_d3_mac_eicc_matches_expected_micc() {
        let kmac = hex("7962D9ECE03D1ACD4C76089DCE131543");
        let eicc = hex("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F");
        assert_eq!(
            hex::encode_upper(mac_e(&kmac, &eicc).unwrap()),
            "2F2D235D074D7449"
        );
    }

    #[test]
    fn icao_d3_decrypt_eicc_matches_expected_r() {
        let kenc = hex("AB94FDECF2674FDFB9B391F85D7F76F2");
        let eicc = hex("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F");
        assert_eq!(
            hex::encode_upper(decrypt_e_icc(&kenc, &eicc).unwrap()),
            "4608F91988702212781723860C06C2260B4F80323EB3191CB04970CB4052790B"
        );
    }

    #[test]
    fn icao_d3_full_ea_response_roundtrip() {
        // Full end-to-end: given the response 80 bytes from the ICC and the
        // derived keys, extract Eicc/Micc, verify MAC, decrypt → R, extract
        // K.ICC, derive session keys, and compute SSC.
        let kenc = hex("AB94FDECF2674FDFB9B391F85D7F76F2");
        let kmac = hex("7962D9ECE03D1ACD4C76089DCE131543");
        let rnd_ifd = hex("781723860C06C226");
        let rnd_icc = hex("4608F91988702212");
        let kifd = hex("0B795240CB7049B01C19B33E32804F0B");
        let resp =
            hex("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449");

        let pair = extract_eicc_and_micc(&resp).unwrap();
        assert!(verify_eicc(&pair.first, &kmac, &pair.second).unwrap());

        let r = decrypt_e_icc(&kenc, &pair.first).unwrap();
        let kicc = verify_rnd_ifd_and_extract_kicc(&rnd_ifd, &r).unwrap();
        assert_eq!(hex::encode_upper(&kicc), "0B4F80323EB3191CB04970CB4052790B");

        let ks = calculate_session_keys(&kifd, &kicc).unwrap();
        assert_eq!(
            hex::encode_upper(&ks.first),
            "979EC13B1CBFE9DCD01AB0FED307EAE5"
        );
        assert_eq!(
            hex::encode_upper(&ks.second),
            "F1CB1F1FB5ADF208806B89DC579DC1F8"
        );

        let ssc = calculate_ssc(&rnd_ifd, &rnd_icc).unwrap();
        assert_eq!(hex::encode_upper(ssc.0.to_bytes()), "887022120C06C226");
    }
}
