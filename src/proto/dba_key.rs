//! Document Basic Access key (DBA / BAC).
//!
//! DBA keys are derived from the MRZ document number, date of birth, and
//! date of expiry per ICAO 9303 p11 §9.7.2. The SHA-1 hash of the
//! concatenated MRZ string yields the seed used by BAC (first 16 bytes) or
//! PACE (first 20 bytes).

use chrono::NaiveDate;
use sha1::{Digest, Sha1};

use crate::crypto::kdf::DeriveKey;
use crate::extension::datetime::DateTimeFormatExt;
use crate::lds::asn1_object_identifiers::{CipherAlgorithm, KeyLength};
use crate::lds::mrz::Mrz;
use crate::proto::access_key::{AccessKey, PACE_REF_KEY_TAG_MRZ};

/// Seed length for BAC (16 bytes).
pub const SEED_LEN_BAC: usize = 16;
/// Seed length for PACE (20 bytes — uncut SHA-1 digest).
pub const SEED_LEN_PACE: usize = 20;

/// Document Basic Access key.
#[derive(Debug, Clone)]
pub struct DBAKey {
    mrtd_number: String,
    /// Original date of birth, stored verbatim so the getter round-trips the
    /// input exactly (the MRZ `YYMMDD` form loses the century).
    dob: NaiveDate,
    /// Original date of expiry (see [`DBAKey::dob`]).
    doe: NaiveDate,
    seed_len: usize,
}

impl DBAKey {
    /// Constructs a [`DBAKey`] from the MRTD number and birth/expiry dates.
    ///
    /// If `pace_mode` is `true`, the seed length is set to 20 bytes (uncut
    /// SHA-1 digest); otherwise it is 16 bytes (BAC).
    pub fn new(
        mrtd_number: impl Into<String>,
        date_of_birth: NaiveDate,
        date_of_expiry: NaiveDate,
        pace_mode: bool,
    ) -> Self {
        Self {
            mrtd_number: mrtd_number.into(),
            dob: date_of_birth,
            doe: date_of_expiry,
            seed_len: if pace_mode { SEED_LEN_PACE } else { SEED_LEN_BAC },
        }
    }

    /// Constructs a [`DBAKey`] from a parsed [`Mrz`] (BAC mode).
    pub fn from_mrz(mrz: &Mrz) -> Self {
        Self::new(
            mrz.document_number(),
            mrz.date_of_birth,
            mrz.date_of_expiry,
            false,
        )
    }

    /// Returns `K_seed` (truncated to `seed_len` bytes) as specified in
    /// Appendix D.2 of ICAO 9303 Part 11.
    pub fn key_seed(&self) -> Vec<u8> {
        let padded_mrtd = pad_right(&self.mrtd_number, 9, '<');
        let dob = self.dob.format_yymmdd();
        let doe = self.doe.format_yymmdd();
        // The seed inputs (doc number, YYMMDD dates) are expected to use the MRZ
        // alphabet; an unsupported character only ever produces a wrong seed
        // (GIGO), so fall back to 0 rather than failing key derivation here.
        let cdn = Mrz::calculate_check_digit(&padded_mrtd).unwrap_or(0);
        let cdb = Mrz::calculate_check_digit(&dob).unwrap_or(0);
        let cde = Mrz::calculate_check_digit(&doe).unwrap_or(0);
        let kmrz = format!(
            "{padded_mrtd}{cdn}{dob}{cdb}{doe}{cde}",
            padded_mrtd = padded_mrtd,
            cdn = cdn,
            dob = dob,
            cdb = cdb,
            doe = doe,
            cde = cde,
        );
        let mut hasher = Sha1::new();
        hasher.update(kmrz.as_bytes());
        let digest = hasher.finalize();
        digest[..self.seed_len].to_vec()
    }

    /// Returns `K_enc` (3DES encryption key for BAC / PACE).
    pub fn enc_key(&self) -> Vec<u8> {
        DeriveKey::des_ede(&self.key_seed(), false)
    }

    /// Returns `K_mac` (ISO 9797 MAC algorithm 3 key).
    pub fn mac_key(&self) -> Vec<u8> {
        DeriveKey::iso9797_mac_alg3(&self.key_seed())
    }

    /// Returns the MRTD number used to build the seed.
    pub fn mrtd_number(&self) -> &str {
        &self.mrtd_number
    }

    /// Returns the date of birth exactly as supplied to [`DBAKey::new`].
    pub fn date_of_birth(&self) -> NaiveDate {
        self.dob
    }

    /// Returns the date of expiry exactly as supplied to [`DBAKey::new`].
    pub fn date_of_expiry(&self) -> NaiveDate {
        self.doe
    }

    /// Returns `true` when the key was constructed with the PACE seed length.
    pub fn is_pace_mode(&self) -> bool {
        self.seed_len == SEED_LEN_PACE
    }
}

impl AccessKey for DBAKey {
    fn pace_ref_key_tag(&self) -> u8 {
        PACE_REF_KEY_TAG_MRZ
    }

    fn kpi(
        &self,
        cipher_algorithm: CipherAlgorithm,
        key_length: KeyLength,
    ) -> Result<Vec<u8>, String> {
        let seed = self.key_seed();
        match (cipher_algorithm, key_length) {
            (CipherAlgorithm::DeSede, _) => Ok(DeriveKey::des_ede(&seed, true)),
            (CipherAlgorithm::Aes, KeyLength::S128) => Ok(DeriveKey::aes128(&seed, true)),
            (CipherAlgorithm::Aes, KeyLength::S192) => Ok(DeriveKey::aes192(&seed, true)),
            (CipherAlgorithm::Aes, KeyLength::S256) => Ok(DeriveKey::aes256(&seed, true)),
        }
    }
}

fn pad_right(s: &str, min_len: usize, fill: char) -> String {
    if s.len() >= min_len {
        s.to_string()
    } else {
        let mut out = s.to_string();
        out.extend(std::iter::repeat(fill).take(min_len - s.len()));
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// ICAO 9303 p11 Appendix D.2 worked example:
    ///   documentNumber = "L898902C<"      (padded to 9 chars with '<')
    ///   dateOfBirth    = "690806"         → 6 Aug 1969
    ///   dateOfExpiry   = "940623"         → 23 Jun 1994
    ///   K_seed (BAC, 16 bytes) = 239AB9CB282DAF66231DC5A4DF6BFBAE
    #[test]
    fn key_seed_matches_icao_worked_example() {
        let key = DBAKey::new(
            "L898902C",
            NaiveDate::from_ymd_opt(1969, 8, 6).unwrap(),
            NaiveDate::from_ymd_opt(1994, 6, 23).unwrap(),
            false,
        );
        let seed = key.key_seed();
        assert_eq!(
            hex::encode_upper(&seed),
            "239AB9CB282DAF66231DC5A4DF6BFBAE"
        );
    }

    #[test]
    fn pace_mode_seed_is_20_bytes() {
        let key = DBAKey::new(
            "L898902C",
            NaiveDate::from_ymd_opt(1969, 8, 6).unwrap(),
            NaiveDate::from_ymd_opt(1994, 6, 23).unwrap(),
            true,
        );
        assert_eq!(key.key_seed().len(), 20);
        assert!(key.is_pace_mode());
    }

    #[test]
    fn bac_mode_seed_is_16_bytes() {
        let key = DBAKey::new(
            "L898902C",
            NaiveDate::from_ymd_opt(1969, 8, 6).unwrap(),
            NaiveDate::from_ymd_opt(1994, 6, 23).unwrap(),
            false,
        );
        assert_eq!(key.key_seed().len(), 16);
        assert!(!key.is_pace_mode());
    }

    #[test]
    fn pace_ref_key_tag_is_mrz() {
        let key = DBAKey::new(
            "X",
            NaiveDate::from_ymd_opt(2000, 1, 1).unwrap(),
            NaiveDate::from_ymd_opt(2010, 1, 1).unwrap(),
            false,
        );
        assert_eq!(key.pace_ref_key_tag(), PACE_REF_KEY_TAG_MRZ);
    }

    #[test]
    fn kpi_desede_returns_16_bytes() {
        let key = DBAKey::new(
            "L898902C",
            NaiveDate::from_ymd_opt(1969, 8, 6).unwrap(),
            NaiveDate::from_ymd_opt(1994, 6, 23).unwrap(),
            true,
        );
        let kpi = key.kpi(CipherAlgorithm::DeSede, KeyLength::S128).unwrap();
        // DeriveKey::des_ede produces a 16-byte 3DES key.
        assert_eq!(kpi.len(), 16);
    }

    #[test]
    fn kpi_aes_key_lengths() {
        let key = DBAKey::new(
            "L898902C",
            NaiveDate::from_ymd_opt(1969, 8, 6).unwrap(),
            NaiveDate::from_ymd_opt(1994, 6, 23).unwrap(),
            true,
        );
        assert_eq!(
            key.kpi(CipherAlgorithm::Aes, KeyLength::S128).unwrap().len(),
            16
        );
        assert_eq!(
            key.kpi(CipherAlgorithm::Aes, KeyLength::S192).unwrap().len(),
            24
        );
        assert_eq!(
            key.kpi(CipherAlgorithm::Aes, KeyLength::S256).unwrap().len(),
            32
        );
    }

    #[test]
    fn enc_and_mac_key_lengths() {
        let key = DBAKey::new(
            "L898902C",
            NaiveDate::from_ymd_opt(1969, 8, 6).unwrap(),
            NaiveDate::from_ymd_opt(1994, 6, 23).unwrap(),
            false,
        );
        // 3DES key (K_enc) and MAC key are each 16 bytes per ICAO 9303.
        assert_eq!(key.enc_key().len(), 16);
        assert_eq!(key.mac_key().len(), 16);
    }

    #[test]
    fn date_getters_round_trip_input_century() {
        // Dates whose century the YYMMDD pivot heuristic could get wrong must
        // still be reported exactly as supplied to `new`.
        let dob = NaiveDate::from_ymd_opt(2005, 3, 9).unwrap();
        let doe = NaiveDate::from_ymd_opt(2045, 12, 31).unwrap();
        let key = DBAKey::new("D23145890", dob, doe, false);
        assert_eq!(key.date_of_birth(), dob);
        assert_eq!(key.date_of_expiry(), doe);
    }

    #[test]
    fn from_mrz_uses_td3_fields() {
        let mrz = Mrz::from_bytes(
            "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10".as_bytes().to_vec(),
        )
        .unwrap();
        let key = DBAKey::from_mrz(&mrz);
        assert_eq!(key.mrtd_number(), "L898902C3");
        assert_eq!(key.date_of_birth(), NaiveDate::from_ymd_opt(1974, 8, 12).unwrap());
        assert_eq!(key.date_of_expiry(), NaiveDate::from_ymd_opt(2012, 4, 15).unwrap());
        assert!(!key.is_pace_mode());
    }

    /// PACE worked example: doc number `T22000129`, DOB 1964-08-12, DOE
    /// 2010-10-31 — `K_seed`, `K_enc`, `K_mac`, and `K_π` for AES-128.
    #[test]
    fn pace_mode_worked_example_derives_expected_keys() {
        let key = DBAKey::new(
            "T22000129",
            NaiveDate::from_ymd_opt(1964, 8, 12).unwrap(),
            NaiveDate::from_ymd_opt(2010, 10, 31).unwrap(),
            true,
        );
        assert_eq!(
            hex::encode(key.key_seed()),
            "7e2d2a41c74ea0b38cd36f863939bfa8e9032aad"
        );
        assert_eq!(
            hex::encode(key.enc_key()),
            "3dc4f8862f8a1570b57fefdcfec43e46"
        );
        assert_eq!(
            hex::encode(key.mac_key()),
            "bc641c6b2fa8b5704552322007761f85"
        );
        assert_eq!(
            hex::encode(key.kpi(CipherAlgorithm::Aes, KeyLength::S128).unwrap()),
            "89ded1b26624ec1e634c1989302849dd"
        );
    }

    /// BAC seed for the Appendix D TD2 Stevenson MRZ (extended document
    /// number `D23145890734`, DOB 1934-07-12, DOE 1995-07-12):
    /// `b366ad85…14730`.
    #[test]
    fn bac_seed_for_stevenson_td2_extended() {
        let key = DBAKey::new(
            "D23145890734",
            NaiveDate::from_ymd_opt(1934, 7, 12).unwrap(),
            NaiveDate::from_ymd_opt(1995, 7, 12).unwrap(),
            false,
        );
        assert_eq!(
            hex::encode(key.key_seed()),
            "b366ad857ddca2b08c0e299811714730"
        );
    }

    /// Same extended document number via the MRZ helper `DBAKey::from_mrz`.
    #[test]
    fn bac_seed_for_stevenson_td2_from_mrz() {
        let mrz = Mrz::from_bytes(
            "I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8"
                .as_bytes()
                .to_vec(),
        )
        .unwrap();
        let key = DBAKey::from_mrz(&mrz);
        assert_eq!(
            hex::encode(key.key_seed()),
            "b366ad857ddca2b08c0e299811714730"
        );
    }
}
