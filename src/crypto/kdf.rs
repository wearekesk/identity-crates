//! ICAO 9303 Key Derivation Function (KDF).
//!
//! Implements key derivation as specified in ICAO 9303 Part 11, Sections 9.7.1.1–9.7.1.4.
//!
//! The general KDF is:
//! ```text
//! H(keySeed || counter)
//! ```
//! where `H` is SHA-1 (for DESede/AES-128) or SHA-256 (for AES-192/256),
//! and `counter` is a big-endian 32-bit integer.
//!
//! # Counter values
//! | Mode          | Counter |
//! |---------------|---------|
//! | ENC (default) | 1       |
//! | MAC           | 2       |
//! | PACE          | 3       |
//!
//! # Key types
//! | [`DeriveKeyType`]    | Hash   | Output length | Counter |
//! |----------------------|--------|---------------|---------|
//! | `DESede`             | SHA-1  | 16 bytes      | 1 (or 3 in PACE mode) |
//! | `ISO9797MacAlg3`     | SHA-1  | 16 bytes      | 2       |
//! | `AES128`             | SHA-1  | 16 bytes      | 1 (or 3 in PACE mode) |
//! | `CMAC128`            | SHA-1  | 16 bytes      | 2       |
//! | `AES192`             | SHA-256| 24 bytes      | 1 (or 3 in PACE mode) |
//! | `CMAC192`            | SHA-256| 24 bytes      | 2       |
//! | `AES256`             | SHA-256| 32 bytes      | 1 (or 3 in PACE mode) |
//! | `CMAC256`            | SHA-256| 32 bytes      | 2       |

use digest::Digest;
use sha1::Sha1;
use sha2::Sha256;

// ---------------------------------------------------------------------------
// KDF primitive
// ---------------------------------------------------------------------------

/// Low-level ICAO 9303 Key Derivation Function.
///
/// Computes `H(keySeed || counter_be32)` using the supplied digest `H`.
fn kdf_sha1(key_seed: &[u8], counter: u32) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(key_seed);
    hasher.update(counter.to_be_bytes());
    hasher.finalize().to_vec()
}

fn kdf_sha256(key_seed: &[u8], counter: u32) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key_seed);
    hasher.update(counter.to_be_bytes());
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// DeriveKeyType enum
// ---------------------------------------------------------------------------

/// Selects the key type to derive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveKeyType {
    // Encryption key types
    DESede,
    AES128,
    AES192,
    AES256,
    // MAC key types
    ISO9797MacAlg3,
    CMAC128,
    CMAC192,
    CMAC256,
}

// ---------------------------------------------------------------------------
// DeriveKey struct (static methods only)
// ---------------------------------------------------------------------------

/// ICAO 9303 key derivation helpers.
///
/// # Examples
/// ```
/// use dmrtd::crypto::kdf::DeriveKey;
///
/// // From ICAO 9303 p11 Appendix D
/// let seed = hex::decode("239AB9CB282DAF66231DC5A4DF6BFBAE").unwrap();
/// let kenc = DeriveKey::des_ede(&seed, false);
/// assert_eq!(kenc, hex::decode("AB94FDECF2674FDFB9B391F85D7F76F2").unwrap());
///
/// let kmac = DeriveKey::iso9797_mac_alg3(&seed);
/// assert_eq!(kmac, hex::decode("7962D9ECE03D1ACD4C76089DCE131543").unwrap());
/// ```
pub struct DeriveKey;

impl DeriveKey {
    /// Returns the key for ISO 9797-1 MAC Algorithm 3 derived from `key_seed`.
    ///
    /// Uses counter mode 2 (MAC mode) and SHA-1; returns 16 bytes.
    pub fn iso9797_mac_alg3(key_seed: &[u8]) -> Vec<u8> {
        Self::derive(DeriveKeyType::ISO9797MacAlg3, key_seed, false)
    }

    /// Returns the CMAC-128 key derived from `key_seed`.
    ///
    /// Uses counter mode 2 (MAC mode) and SHA-1; returns 16 bytes.
    pub fn cmac128(key_seed: &[u8]) -> Vec<u8> {
        Self::derive(DeriveKeyType::CMAC128, key_seed, false)
    }

    /// Returns the CMAC-192 key derived from `key_seed`.
    ///
    /// Uses counter mode 2 (MAC mode) and SHA-256; returns 24 bytes.
    pub fn cmac192(key_seed: &[u8]) -> Vec<u8> {
        Self::derive(DeriveKeyType::CMAC192, key_seed, false)
    }

    /// Returns the CMAC-256 key derived from `key_seed`.
    ///
    /// Uses counter mode 2 (MAC mode) and SHA-256; returns 32 bytes.
    pub fn cmac256(key_seed: &[u8]) -> Vec<u8> {
        Self::derive(DeriveKeyType::CMAC256, key_seed, false)
    }

    /// Returns the DESede (Triple-DES) key derived from `key_seed`.
    ///
    /// Uses counter mode 1 (ENC) normally, or 3 (PACE) when `pace_mode` is `true`.
    /// Uses SHA-1; returns 16 bytes with odd-parity bits adjusted.
    pub fn des_ede(key_seed: &[u8], pace_mode: bool) -> Vec<u8> {
        Self::derive(DeriveKeyType::DESede, key_seed, pace_mode)
    }

    /// Returns the AES-128 key derived from `key_seed`.
    ///
    /// Uses counter mode 1 (ENC) normally, or 3 (PACE) when `pace_mode` is `true`.
    /// Uses SHA-1; returns 16 bytes.
    pub fn aes128(key_seed: &[u8], pace_mode: bool) -> Vec<u8> {
        Self::derive(DeriveKeyType::AES128, key_seed, pace_mode)
    }

    /// Returns the AES-192 key derived from `key_seed`.
    ///
    /// Uses counter mode 1 (ENC) normally, or 3 (PACE) when `pace_mode` is `true`.
    /// Uses SHA-256; returns 24 bytes.
    pub fn aes192(key_seed: &[u8], pace_mode: bool) -> Vec<u8> {
        Self::derive(DeriveKeyType::AES192, key_seed, pace_mode)
    }

    /// Returns the AES-256 key derived from `key_seed`.
    ///
    /// Uses counter mode 1 (ENC) normally, or 3 (PACE) when `pace_mode` is `true`.
    /// Uses SHA-256; returns 32 bytes.
    pub fn aes256(key_seed: &[u8], pace_mode: bool) -> Vec<u8> {
        Self::derive(DeriveKeyType::AES256, key_seed, pace_mode)
    }

    /// General-purpose key derivation.
    ///
    /// Selects the correct hash, counter, and post-processing (parity adjustment
    /// for DESede) based on `key_type` and `pace_mode`.
    pub fn derive(key_type: DeriveKeyType, key_seed: &[u8], pace_mode: bool) -> Vec<u8> {
        // Determine counter: MAC types always use 2; ENC types use 1, or 3 in PACE mode.
        let counter: u32 = match key_type {
            DeriveKeyType::ISO9797MacAlg3
            | DeriveKeyType::CMAC128
            | DeriveKeyType::CMAC192
            | DeriveKeyType::CMAC256 => 2,
            _ => {
                if pace_mode {
                    3
                } else {
                    1
                }
            }
        };

        match key_type {
            // ----------------------------------------------------------------
            // SHA-1 based keys (DESede, AES-128, ISO9797 MAC, CMAC-128)
            // Use only first 16 bytes of the 20-byte SHA-1 digest.
            // ----------------------------------------------------------------
            DeriveKeyType::DESede | DeriveKeyType::ISO9797MacAlg3 => {
                let mut key = kdf_sha1(key_seed, counter)[..16].to_vec();
                // Adjust odd parity bits for DES keys
                adjust_des_parity(&mut key);
                key
            }
            DeriveKeyType::AES128 | DeriveKeyType::CMAC128 => {
                kdf_sha1(key_seed, counter)[..16].to_vec()
            }

            // ----------------------------------------------------------------
            // SHA-256 based keys (AES-192, AES-256, CMAC-192, CMAC-256)
            // Use first 24 bytes for 192-bit, full 32 bytes for 256-bit.
            // ----------------------------------------------------------------
            DeriveKeyType::AES192 | DeriveKeyType::CMAC192 => {
                kdf_sha256(key_seed, counter)[..24].to_vec()
            }
            DeriveKeyType::AES256 | DeriveKeyType::CMAC256 => kdf_sha256(key_seed, counter),
        }
    }
}

// ---------------------------------------------------------------------------
// DES parity-bit adjustment
// ---------------------------------------------------------------------------

/// Adjusts the least-significant bit of each byte of a DES key so that each
/// byte has an **odd** number of set bits (odd parity).
///
/// This mirrors the reference which ensures even total bit-count
/// per byte by XOR-ing bit 0 when the popcount is even:
///
/// ```text
/// if (popcount(byte) % 2 == 0) { byte ^= 0x01; }
/// ```
///
/// Note: "even popcount → XOR with 1" is equivalent to forcing **odd** parity.
fn adjust_des_parity(key: &mut [u8]) {
    for byte in key.iter_mut() {
        let count = byte.count_ones();
        if count % 2 == 0 {
            // Even number of set bits → flip LSB to make it odd
            *byte ^= 0x01;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test vectors from ICAO 9303 Part 11, Appendix D
    // (same vectors used kdf_test.dart)
    // -----------------------------------------------------------------------

    /// Appendix D – DESede and ISO/IEC 9797 MAC Algorithm 3 key derivation.
    #[test]
    fn des_ede_and_iso9797_mac_alg3_appendix_d_vector_1() {
        let kseed = hex::decode("239AB9CB282DAF66231DC5A4DF6BFBAE").unwrap();

        let kenc = DeriveKey::des_ede(&kseed, false);
        assert_eq!(
            kenc,
            hex::decode("AB94FDECF2674FDFB9B391F85D7F76F2").unwrap(),
            "Kenc mismatch"
        );

        let kmac = DeriveKey::iso9797_mac_alg3(&kseed);
        assert_eq!(
            kmac,
            hex::decode("7962D9ECE03D1ACD4C76089DCE131543").unwrap(),
            "Kmac mismatch"
        );
    }

    /// Appendix D – second set of DESede / ISO9797 MAC vectors.
    #[test]
    fn des_ede_and_iso9797_mac_alg3_appendix_d_vector_2() {
        let kseed = hex::decode("0036D272F5C350ACAC50C3F572D23600").unwrap();

        let kenc = DeriveKey::des_ede(&kseed, false);
        assert_eq!(
            kenc,
            hex::decode("979EC13B1CBFE9DCD01AB0FED307EAE5").unwrap(),
            "Kenc mismatch"
        );

        let kmac = DeriveKey::iso9797_mac_alg3(&kseed);
        assert_eq!(
            kmac,
            hex::decode("F1CB1F1FB5ADF208806B89DC579DC1F8").unwrap(),
            "Kmac mismatch"
        );
    }

    // -----------------------------------------------------------------------
    // Test vectors from ICAO 9303 Part 11, Appendix G (AES-128 / CMAC-128)
    // -----------------------------------------------------------------------

    #[test]
    fn aes128_and_cmac128_appendix_g_vector_1() {
        let shared_secret =
            hex::decode("28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925")
                .unwrap();

        let kenc = DeriveKey::aes128(&shared_secret, false);
        assert_eq!(
            kenc,
            hex::decode("F5F0E35C0D7161EE6724EE513A0D9A7F").unwrap(),
            "AES-128 Kenc mismatch"
        );

        let kmac = DeriveKey::cmac128(&shared_secret);
        assert_eq!(
            kmac,
            hex::decode("FE251C7858B356B24514B3BD5F4297D1").unwrap(),
            "CMAC-128 Kmac mismatch"
        );
    }

    #[test]
    fn aes128_and_cmac128_appendix_g_vector_2() {
        let shared_secret = hex::decode(
            "6BABC7B3A72BCD7EA385E4C62DB2625BD8613B24149E146A629311C4CA6698E3\
             8B834B6A9E9CD7184BA8834AFF5043D436950C4C1E7832367C10CB8C314D40E5\
             990B0DF7013E64B4549E2270923D06F08CFF6BD3E977DDE6ABE4C31D55C0FA2E\
             465E553E77BDF75E3193D3834FC26E8EB1EE2FA1E4FC97C18C3F6CFFFE2607FD",
        )
        .unwrap();

        let kenc = DeriveKey::aes128(&shared_secret, false);
        assert_eq!(
            kenc,
            hex::decode("2F7F46ADCC9E7E521B45D192FAFA9126").unwrap(),
        );

        let kmac = DeriveKey::cmac128(&shared_secret);
        assert_eq!(
            kmac,
            hex::decode("805A1D27D45A5116F73C54469462B7D8").unwrap(),
        );
    }

    #[test]
    fn aes128_and_cmac128_appendix_i_vector() {
        let shared_secret =
            hex::decode("67950559D0C06B4D4B86972D14460837461087F8419FDBC36AAF6CEAAC462832")
                .unwrap();

        let kenc = DeriveKey::aes128(&shared_secret, false);
        assert_eq!(
            kenc,
            hex::decode("0A9DA4DB03BDDE39FC5202BC44B2E89E").unwrap(),
        );

        let kmac = DeriveKey::cmac128(&shared_secret);
        assert_eq!(
            kmac,
            hex::decode("4B1C06491ED5140CA2B537D344C6C0B1").unwrap(),
        );
    }

    // -----------------------------------------------------------------------
    // General property tests
    // -----------------------------------------------------------------------

    #[test]
    fn des_parity_adjustment_makes_odd_parity() {
        let mut key = vec![0x00u8; 8]; // all zeros → even parity → should flip LSB
        adjust_des_parity(&mut key);
        for byte in &key {
            assert_eq!(
                byte.count_ones() % 2,
                1,
                "Byte 0x{:02X} does not have odd parity",
                byte
            );
        }
    }

    #[test]
    fn des_parity_idempotent_when_already_odd() {
        // A byte with 1 set bit (odd parity) should not change.
        let mut key = vec![0x01u8]; // 1 set bit → odd parity
        let before = key[0];
        adjust_des_parity(&mut key);
        assert_eq!(key[0], before, "Byte with already-odd parity was changed");
    }

    #[test]
    fn derive_enc_counter_differs_from_mac_counter() {
        let kseed = [0xAAu8; 16];
        let enc_key = DeriveKey::derive(DeriveKeyType::AES128, &kseed, false);
        let mac_key = DeriveKey::derive(DeriveKeyType::CMAC128, &kseed, false);
        assert_ne!(enc_key, mac_key, "ENC and MAC keys must differ");
    }

    #[test]
    fn pace_mode_uses_different_counter_than_enc_mode() {
        let kseed = [0xBBu8; 16];
        let enc_key = DeriveKey::aes128(&kseed, false);
        let pace_key = DeriveKey::aes128(&kseed, true);
        assert_ne!(enc_key, pace_key, "ENC and PACE keys must differ");
    }

    #[test]
    fn aes256_output_is_32_bytes() {
        let kseed = [0x01u8; 32];
        let key = DeriveKey::aes256(&kseed, false);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn aes192_output_is_24_bytes() {
        let kseed = [0x01u8; 32];
        let key = DeriveKey::aes192(&kseed, false);
        assert_eq!(key.len(), 24);
    }

    #[test]
    fn aes128_output_is_16_bytes() {
        let kseed = [0x01u8; 16];
        let key = DeriveKey::aes128(&kseed, false);
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn des_ede_output_is_16_bytes() {
        let kseed = [0x01u8; 16];
        let key = DeriveKey::des_ede(&kseed, false);
        assert_eq!(key.len(), 16);
    }
}
