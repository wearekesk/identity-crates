//! Synchronous PACE session state machine for FFI use.
//!
//! Drives the full PACE handshake (MSE:Set AT → GA step 1/2/3/4) as a series
//! of `(next APDU → response)` steps. Like [`BacSession`], no async and no
//! NFC — the caller owns the transceive loop.
//!
//! This port currently supports **ECDH-GM on NIST P-256 only** (ICAO domain
//! parameter id `12`). DH and other curves are rejected at construction.
//!
//! ```text
//!   Start
//!     └─ next() → SendApdu(MSE:Set AT)
//!        └─ feed(9000)
//!   ReadyForStep1
//!     └─ next() → SendApdu(GA step 1)
//!        └─ feed(encrypted-nonce)
//!   ReadyForStep2 { nonce }
//!     └─ next() → SendApdu(GA step 2; terminal mapping public)
//!        └─ feed(ICC mapping public)
//!   ReadyForStep3
//!     └─ next() → SendApdu(GA step 3; terminal ephemeral public)
//!        └─ feed(ICC ephemeral public)
//!   ReadyForStep4 { icc_ephemeral_pub, k_enc, k_mac }
//!     └─ next() → SendApdu(GA step 4; auth token T_IFD)
//!        └─ feed(ICC auth token T_IC)  ← verified against expected
//!   Completed(sm)
//!     └─ next() → Done(sm)
//! ```
//!
//! [`BacSession`]: crate::proto::bac_session::BacSession

use elliptic_curve::sec1::ToSec1Point;
use p256::ProjectivePoint;
use thiserror::Error;

use crate::lds::asn1_object_identifiers::{
    CipherAlgorithm, OiePaceProtocol, TokenAgreementAlgo,
};
use crate::proto::access_key::AccessKey;
use crate::proto::aes_smcipher::AesSmCipher;
use crate::proto::ecdh_pace::{ECDHPace, ECDHPaceError, NIST_P256_ID};
use crate::proto::iso7816::command_apdu::CommandApdu;
use crate::proto::iso7816::iso7816::{cla, ins};
use crate::proto::iso7816::response_apdu::{ResponseApdu, StatusWord};
use crate::proto::mrtd_sm::MrtdSM;
use crate::proto::pace::{self, PaceError};
use crate::proto::public_key_pace::PublicKeyPace;
use crate::proto::ssc::AesSSC;

/// Action requested by [`PaceSession::next`].
pub enum PaceAction {
    /// Send this APDU and call [`PaceSession::feed_response`] with the reply.
    SendApdu(Vec<u8>),
    /// Handshake complete — take ownership of the secure-messaging session.
    Done(MrtdSM<AesSmCipher>),
}

/// PACE protocol error surface for the session layer.
#[derive(Debug, Error)]
pub enum PaceSessionError {
    #[error("PACE session: only ECDH-GM is supported (got {0:?})")]
    UnsupportedAgreement(TokenAgreementAlgo),
    #[error("PACE session: only AES cipher is supported (got {0:?})")]
    UnsupportedCipher(CipherAlgorithm),
    #[error("PACE session: only NIST P-256 (id 12) is supported (got id {0})")]
    UnsupportedCurve(u32),
    #[error("PACE session has no outstanding APDU to consume")]
    NoOutstandingApdu,
    #[error("PACE session is waiting for a response; feed_response first")]
    PendingResponse,
    #[error("PACE session already consumed")]
    AlreadyTaken,
    #[error("PACE step failed with status {0}")]
    ChipStatus(StatusWord),
    #[error("PACE step response was empty")]
    EmptyResponse,
    #[error("Invalid response APDU: {0}")]
    InvalidResponse(String),
    #[error("Shared secret has no x coordinate")]
    MissingSharedSecretX,
    #[error("ICC authentication token does not match the expected one")]
    AuthTokenMismatch,

    #[error(transparent)]
    Pace(#[from] PaceError),
    #[error(transparent)]
    Ecdh(#[from] ECDHPaceError),
}

/// Synchronous PACE handshake state machine.
///
/// Generic over the [`AccessKey`] used to derive `K_π` (e.g. [`DBAKey`] from
/// MRZ or [`CanKey`] from the 6-digit CAN).
///
/// [`DBAKey`]: crate::proto::dba_key::DBAKey
/// [`CanKey`]: crate::proto::can_key::CanKey
pub struct PaceSession<K: AccessKey> {
    key: K,
    protocol: OiePaceProtocol,
    engine: ECDHPace,
    /// Optional seed for the main ECDH scalar (test determinism).
    seed_main: Option<[u8; 32]>,
    /// Optional seed for the ephemeral ECDH scalar (test determinism).
    seed_ephemeral: Option<[u8; 32]>,
    state: State,
}

enum State {
    Start,
    WaitingForMseSetAt,
    ReadyForStep1,
    WaitingForStep1,
    ReadyForStep2 { nonce: Vec<u8> },
    WaitingForStep2 { nonce: Vec<u8> },
    ReadyForStep3,
    WaitingForStep3,
    ReadyForStep4 {
        icc_ephemeral_pub: PublicKeyPace,
        k_enc: Vec<u8>,
        k_mac: Vec<u8>,
    },
    WaitingForStep4 {
        k_enc: Vec<u8>,
        k_mac: Vec<u8>,
    },
    Completed(Option<MrtdSM<AesSmCipher>>),
}

impl<K: AccessKey> PaceSession<K> {
    /// Creates a new session. Fails unless the protocol is ECDH + AES on
    /// NIST P-256.
    pub fn new_ecdh(
        key: K,
        protocol: OiePaceProtocol,
        parameter_id: u32,
    ) -> Result<Self, PaceSessionError> {
        if protocol.token_agreement_algorithm != TokenAgreementAlgo::Ecdh {
            return Err(PaceSessionError::UnsupportedAgreement(
                protocol.token_agreement_algorithm,
            ));
        }
        if protocol.cipher_algorithm != CipherAlgorithm::Aes {
            return Err(PaceSessionError::UnsupportedCipher(protocol.cipher_algorithm));
        }
        if parameter_id != NIST_P256_ID {
            return Err(PaceSessionError::UnsupportedCurve(parameter_id));
        }
        let engine = ECDHPace::new(parameter_id)?;
        Ok(Self {
            key,
            protocol,
            engine,
            seed_main: None,
            seed_ephemeral: None,
            state: State::Start,
        })
    }

    /// Deterministic variant that seeds both the main and ephemeral ECDH
    /// scalars. For tests / replaying traces only.
    pub fn new_ecdh_deterministic(
        key: K,
        protocol: OiePaceProtocol,
        parameter_id: u32,
        seed_main: [u8; 32],
        seed_ephemeral: [u8; 32],
    ) -> Result<Self, PaceSessionError> {
        let mut s = Self::new_ecdh(key, protocol, parameter_id)?;
        s.seed_main = Some(seed_main);
        s.seed_ephemeral = Some(seed_ephemeral);
        Ok(s)
    }

    /// Advances the state machine and returns the next action.
    pub fn next(&mut self) -> Result<PaceAction, PaceSessionError> {
        match std::mem::replace(&mut self.state, State::Start) {
            State::Start => {
                let data = pace::generate_mse_set_at_data(
                    &self.protocol,
                    self.key.pace_ref_key_tag(),
                );
                let cmd = CommandApdu::new(
                    cla::NO_SM,
                    ins::MANAGE_SECURITY_ENVIRONMENT,
                    0xC1,
                    0xA4,
                    Some(data),
                    0,
                )
                .map_err(|e| PaceSessionError::InvalidResponse(e.to_string()))?;
                self.state = State::WaitingForMseSetAt;
                Ok(PaceAction::SendApdu(cmd.to_bytes()))
            }
            State::ReadyForStep1 => {
                let data = pace::generate_general_authenticate_data_step1();
                let cmd = CommandApdu::new(
                    cla::COMMAND_CHAINING,
                    ins::GENERAL_AUTHENTICATE,
                    0x00,
                    0x00,
                    Some(data),
                    256,
                )
                .map_err(|e| PaceSessionError::InvalidResponse(e.to_string()))?;
                self.state = State::WaitingForStep1;
                Ok(PaceAction::SendApdu(cmd.to_bytes()))
            }
            State::ReadyForStep2 { nonce } => {
                // Generate main key pair; send its public as mapping public.
                self.engine
                    .generate_key_pair(self.seed_main.as_ref().map(|s| &s[..]))?;
                let terminal_pub = self.engine.get_pub_key()?;
                let data =
                    pace::generate_general_authenticate_data_step2_or_3(&terminal_pub, false);
                let cmd = CommandApdu::new(
                    cla::COMMAND_CHAINING,
                    ins::GENERAL_AUTHENTICATE,
                    0x00,
                    0x00,
                    Some(data),
                    256,
                )
                .map_err(|e| PaceSessionError::InvalidResponse(e.to_string()))?;
                self.state = State::WaitingForStep2 { nonce };
                Ok(PaceAction::SendApdu(cmd.to_bytes()))
            }
            State::ReadyForStep3 => {
                let terminal_ephemeral_pub = self.engine.get_pub_key_ephemeral()?;
                let data = pace::generate_general_authenticate_data_step2_or_3(
                    &terminal_ephemeral_pub,
                    true,
                );
                let cmd = CommandApdu::new(
                    cla::COMMAND_CHAINING,
                    ins::GENERAL_AUTHENTICATE,
                    0x00,
                    0x00,
                    Some(data),
                    256,
                )
                .map_err(|e| PaceSessionError::InvalidResponse(e.to_string()))?;
                self.state = State::WaitingForStep3;
                Ok(PaceAction::SendApdu(cmd.to_bytes()))
            }
            State::ReadyForStep4 {
                icc_ephemeral_pub,
                k_enc,
                k_mac,
            } => {
                // Terminal's auth token is computed over the *ICC's* ephemeral key.
                let input =
                    pace::generate_encoding_input_data(&self.protocol, &icc_ephemeral_pub);
                let t_ifd = pace::calculate_auth_token(&self.protocol, &input, &k_mac)?;
                let data = pace::generate_general_authenticate_data_step4(&t_ifd);
                let cmd = CommandApdu::new(
                    cla::NO_SM,
                    ins::GENERAL_AUTHENTICATE,
                    0x00,
                    0x00,
                    Some(data),
                    256,
                )
                .map_err(|e| PaceSessionError::InvalidResponse(e.to_string()))?;
                self.state = State::WaitingForStep4 { k_enc, k_mac };
                Ok(PaceAction::SendApdu(cmd.to_bytes()))
            }
            State::Completed(slot) => match slot {
                Some(sm) => {
                    self.state = State::Completed(None);
                    Ok(PaceAction::Done(sm))
                }
                None => Err(PaceSessionError::AlreadyTaken),
            },
            other @ (State::WaitingForMseSetAt
            | State::WaitingForStep1
            | State::WaitingForStep2 { .. }
            | State::WaitingForStep3
            | State::WaitingForStep4 { .. }) => {
                self.state = other;
                Err(PaceSessionError::PendingResponse)
            }
        }
    }

    /// Consumes the full APDU response (data || SW) for the most recent
    /// outgoing APDU.
    pub fn feed_response(&mut self, response: &[u8]) -> Result<(), PaceSessionError> {
        let rapdu = ResponseApdu::from_bytes(response)
            .map_err(|e| PaceSessionError::InvalidResponse(e.to_string()))?;
        if rapdu.status != StatusWord::SUCCESS {
            return Err(PaceSessionError::ChipStatus(rapdu.status));
        }

        match std::mem::replace(&mut self.state, State::Start) {
            State::WaitingForMseSetAt => {
                // MSE:Set AT has no data body; SW=9000 already checked.
                self.state = State::ReadyForStep1;
                Ok(())
            }
            State::WaitingForStep1 => {
                let data = rapdu.data.ok_or(PaceSessionError::EmptyResponse)?;
                let encrypted_nonce = pace::parse_step1_response(&data)
                    .map_err(|e| PaceSessionError::InvalidResponse(e.0))?;
                let nonce =
                    pace::decrypt_nonce(&self.protocol, &encrypted_nonce, &self.key)?;
                self.state = State::ReadyForStep2 { nonce };
                Ok(())
            }
            State::WaitingForStep2 { nonce } => {
                let data = rapdu.data.ok_or(PaceSessionError::EmptyResponse)?;
                let icc_mapping_pub = pace::parse_step2_or_3_response(
                    &data,
                    TokenAgreementAlgo::Ecdh,
                )
                .map_err(|e| PaceSessionError::InvalidResponse(e.0))?;

                // Compute mapped generator and rebuild ephemeral key pair.
                let icc_pk = ECDHPace::transform_public(&icc_mapping_pub)?;
                let g_prime = self.engine.get_mapped_generator(&icc_pk, &nonce)?;
                self.engine.generate_ephemeral_with_custom_generator(
                    g_prime,
                    self.seed_ephemeral.as_ref().map(|s| &s[..]),
                )?;
                self.state = State::ReadyForStep3;
                Ok(())
            }
            State::WaitingForStep3 => {
                let data = rapdu.data.ok_or(PaceSessionError::EmptyResponse)?;
                let icc_ephemeral_pub = pace::parse_step2_or_3_response(
                    &data,
                    TokenAgreementAlgo::Ecdh,
                )
                .map_err(|e| PaceSessionError::InvalidResponse(e.0))?;

                // Compute the ephemeral shared secret and derive K_enc / K_mac.
                let icc_eph_pk = ECDHPace::transform_public(&icc_ephemeral_pub)?;
                let shared = self.engine.get_ephemeral_shared_secret(&icc_eph_pk)?;
                let seed = ecdh_shared_secret_x_bytes(shared)?;
                let k_enc = pace::calculate_enc_key(&self.protocol, &seed)?;
                let k_mac = pace::calculate_mac_key(&self.protocol, &seed)?;

                self.state = State::ReadyForStep4 {
                    icc_ephemeral_pub,
                    k_enc,
                    k_mac,
                };
                Ok(())
            }
            State::WaitingForStep4 { k_enc, k_mac } => {
                let data = rapdu.data.ok_or(PaceSessionError::EmptyResponse)?;
                let icc_token = pace::parse_step4_response(&data)
                    .map_err(|e| PaceSessionError::InvalidResponse(e.0))?;

                // ICC's token T_IC is computed over the *terminal's* ephemeral
                // public key — the terminal verifies with that same input.
                let terminal_ephemeral_pub = self.engine.get_pub_key_ephemeral()?;
                let expected_input = pace::generate_encoding_input_data(
                    &self.protocol,
                    &terminal_ephemeral_pub,
                );
                let expected_token = pace::calculate_auth_token(
                    &self.protocol,
                    &expected_input,
                    &k_mac,
                )?;
                if expected_token != icc_token {
                    return Err(PaceSessionError::AuthTokenMismatch);
                }

                let cipher = AesSmCipher::new(k_enc, k_mac, self.protocol.key_length);
                let sm = MrtdSM::new(cipher, AesSSC::default().0);
                self.state = State::Completed(Some(sm));
                Ok(())
            }
            other @ (State::Start
            | State::ReadyForStep1
            | State::ReadyForStep2 { .. }
            | State::ReadyForStep3
            | State::ReadyForStep4 { .. }
            | State::Completed(_)) => {
                self.state = other;
                Err(PaceSessionError::NoOutstandingApdu)
            }
        }
    }
}

fn ecdh_shared_secret_x_bytes(shared: ProjectivePoint) -> Result<Vec<u8>, PaceSessionError> {
    let encoded = shared.to_affine().to_sec1_point(false);
    let x = encoded.x().ok_or(PaceSessionError::MissingSharedSecretX)?;
    Ok(x.to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! End-to-end PACE loopback — the ICC side is simulated by a second
    //! `ECDHPace` engine seeded independently from the terminal's. The
    //! test drives every APDU exchange through real `next()` /
    //! `feed_response()` calls and asserts that a secure-messaging session
    //! is produced.

    use super::*;
    use crate::crypto::aes::{AesCipher, BlockCipherMode};
    use crate::lds::tlv::Tlv;
    use crate::proto::can_key::CanKey;

    fn ecdh_gm_aes128_oid() -> OiePaceProtocol {
        OiePaceProtocol::new(
            "0.4.0.127.0.7.2.2.4.2.2",
            "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
            vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 2],
        )
        .unwrap()
    }

    fn build_response(data: Option<&[u8]>) -> Vec<u8> {
        let r = ResponseApdu::new(
            StatusWord::SUCCESS,
            data.map(|d| d.to_vec()).filter(|d| !d.is_empty()),
        );
        r.to_bytes()
    }

    fn dyn_auth_wrap(tag: u32, body: &[u8]) -> Vec<u8> {
        // 7C { <tag> <body> }
        let inner = Tlv::encode(tag, body);
        Tlv::encode(0x7C, &inner)
    }

    #[test]
    fn rejects_dh_protocol() {
        let dh_protocol = OiePaceProtocol::new(
            "0.4.0.127.0.7.2.2.4.1.2",
            "id-PACE-DH-GM-AES-CBC-CMAC-128",
            vec![0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 2],
        )
        .unwrap();
        let can = CanKey::new("123456").unwrap();
        match PaceSession::new_ecdh(can, dh_protocol, 2) {
            Err(PaceSessionError::UnsupportedAgreement(_)) => {}
            _ => panic!("expected UnsupportedAgreement"),
        }
    }

    #[test]
    fn rejects_non_p256_curve() {
        let can = CanKey::new("123456").unwrap();
        match PaceSession::new_ecdh(can, ecdh_gm_aes128_oid(), 13) {
            Err(PaceSessionError::UnsupportedCurve(13)) => {}
            _ => panic!("expected UnsupportedCurve(13)"),
        }
    }

    #[test]
    fn first_action_is_mse_set_at() {
        let can = CanKey::new("123456").unwrap();
        let mut s = PaceSession::new_ecdh(can, ecdh_gm_aes128_oid(), NIST_P256_ID).unwrap();
        match s.next().unwrap() {
            PaceAction::SendApdu(apdu) => {
                // CLA=00, INS=22, P1=C1, P2=A4
                assert_eq!(&apdu[..4], &[0x00, 0x22, 0xC1, 0xA4]);
            }
            _ => panic!("expected SendApdu"),
        }
    }

    #[test]
    fn next_without_feed_errors() {
        let can = CanKey::new("123456").unwrap();
        let mut s = PaceSession::new_ecdh(can, ecdh_gm_aes128_oid(), NIST_P256_ID).unwrap();
        let _ = s.next().unwrap();
        assert!(s.next().is_err());
    }

    #[test]
    fn feed_before_next_errors() {
        let can = CanKey::new("123456").unwrap();
        let mut s = PaceSession::new_ecdh(can, ecdh_gm_aes128_oid(), NIST_P256_ID).unwrap();
        assert!(s.feed_response(&build_response(None)).is_err());
    }

    #[test]
    fn full_pace_loopback_produces_sm() {
        // ---- setup ----
        let protocol = ecdh_gm_aes128_oid();
        let can = CanKey::new("123456").unwrap();

        // Terminal + simulated ICC use separate seeded engines so the test
        // is deterministic.
        let seed_terminal_main = [0x11u8; 32];
        let seed_terminal_eph = [0x22u8; 32];
        let seed_icc_main = [0x33u8; 32];
        let seed_icc_eph = [0x44u8; 32];

        let mut session = PaceSession::new_ecdh_deterministic(
            can,
            protocol.clone(),
            NIST_P256_ID,
            seed_terminal_main,
            seed_terminal_eph,
        )
        .unwrap();

        // The "chip" side mirror.
        let can_chip = CanKey::new("123456").unwrap();
        let mut icc = ECDHPace::new(NIST_P256_ID).unwrap();

        // ---- Step A: MSE:Set AT ----
        match session.next().unwrap() {
            PaceAction::SendApdu(_) => {}
            _ => panic!("expected MSE:Set AT"),
        }
        session.feed_response(&build_response(None)).unwrap();

        // ---- Step 1: GA step 1 ----
        match session.next().unwrap() {
            PaceAction::SendApdu(_) => {}
            _ => panic!("expected step 1"),
        }
        // Simulated ICC chooses a random 16-byte nonce and encrypts with K_π.
        let nonce = [0x5Au8; 16];
        let cipher = AesCipher::new(protocol.key_length);
        let kpi = can_chip
            .kpi(protocol.cipher_algorithm, protocol.key_length)
            .unwrap();
        let enc_nonce = cipher
            .encrypt(&nonce, &kpi, None, BlockCipherMode::Cbc, false)
            .unwrap();
        let step1_body = dyn_auth_wrap(0x80, &enc_nonce);
        session.feed_response(&build_response(Some(&step1_body))).unwrap();

        // ---- Step 2: GA step 2 — mapping public exchange ----
        let _step2_apdu = match session.next().unwrap() {
            PaceAction::SendApdu(bytes) => bytes,
            _ => panic!("expected step 2"),
        };
        // Simulated ICC side generates its own key pair and returns its public.
        icc.generate_key_pair(Some(&seed_icc_main)).unwrap();
        let icc_mapping_pub = icc.get_pub_key().unwrap();
        let mut step2_body = vec![0x04];
        step2_body.extend_from_slice(&icc_mapping_pub.to_bytes());
        let step2_response = dyn_auth_wrap(0x82, &step2_body);
        session
            .feed_response(&build_response(Some(&step2_response)))
            .unwrap();

        // ---- Step 3: GA step 3 — ephemeral public exchange ----
        let _step3_apdu = match session.next().unwrap() {
            PaceAction::SendApdu(bytes) => bytes,
            _ => panic!("expected step 3"),
        };
        // Chip also computes the mapped generator, then its own ephemeral.
        let terminal_mapping_pk = icc_mapping_pub_from_session(&session)
            .expect("terminal's main pubkey after step 2");
        let terminal_mapping_ec = ECDHPace::transform_public(&terminal_mapping_pk).unwrap();
        let g_prime = icc.get_mapped_generator(&terminal_mapping_ec, &nonce).unwrap();
        icc.generate_ephemeral_with_custom_generator(g_prime, Some(&seed_icc_eph))
            .unwrap();
        let icc_eph_pub = icc.get_pub_key_ephemeral().unwrap();
        let mut step3_body = vec![0x04];
        step3_body.extend_from_slice(&icc_eph_pub.to_bytes());
        let step3_response = dyn_auth_wrap(0x84, &step3_body);
        session
            .feed_response(&build_response(Some(&step3_response)))
            .unwrap();

        // ---- Step 4: GA step 4 — token exchange ----
        let _step4_apdu = match session.next().unwrap() {
            PaceAction::SendApdu(bytes) => bytes,
            _ => panic!("expected step 4"),
        };
        // ICC computes its own token over the *terminal's* ephemeral public.
        let terminal_eph_pub = terminal_ephemeral_pub_from_session(&session)
            .expect("terminal ephemeral public after step 3");
        let terminal_eph_ec = ECDHPace::transform_public(&terminal_eph_pub).unwrap();
        let icc_shared = icc.get_ephemeral_shared_secret(&terminal_eph_ec).unwrap();
        let seed_bytes = ecdh_shared_secret_x_bytes(icc_shared).unwrap();
        let icc_k_mac = pace::calculate_mac_key(&protocol, &seed_bytes).unwrap();
        let icc_auth_input = pace::generate_encoding_input_data(&protocol, &terminal_eph_pub);
        let icc_token =
            pace::calculate_auth_token(&protocol, &icc_auth_input, &icc_k_mac).unwrap();
        let step4_response = dyn_auth_wrap(0x86, &icc_token);
        session
            .feed_response(&build_response(Some(&step4_response)))
            .unwrap();

        // ---- Completion ----
        match session.next().unwrap() {
            PaceAction::Done(sm) => {
                assert_eq!(sm.cipher.ks_enc.len(), 16);
                assert_eq!(sm.cipher.ks_mac.len(), 16);
                assert_eq!(sm.ssc().to_bytes().len(), 16); // AES SSC = 128-bit
            }
            _ => panic!("expected Done"),
        }
    }

    /// Test helper — rebuilds the terminal's main (mapping) public by
    /// inspecting the ECDH engine inside a `PaceSession`. Uses the session's
    /// transient state between feed_response(step 2) and next().
    fn icc_mapping_pub_from_session<K: AccessKey>(
        session: &PaceSession<K>,
    ) -> Option<PublicKeyPace> {
        session.engine.get_pub_key().ok()
    }

    fn terminal_ephemeral_pub_from_session<K: AccessKey>(
        session: &PaceSession<K>,
    ) -> Option<PublicKeyPace> {
        session.engine.get_pub_key_ephemeral().ok()
    }
}
