//! Synchronous BAC session state machine for FFI use.
//!
//! Drives the BAC handshake as a series of `(next APDU → response)` steps,
//! so that callers (e.g. Flutter apps over Dart FFI) can own the transceive
//! loop and perform the actual NFC I/O themselves. No async, no transport,
//! no NFC dependencies.
//!
//! Usage sketch:
//! ```no_run
//! use dmrtd::proto::bac_session::{BacAction, BacSession};
//! use dmrtd::proto::dba_key::DBAKey;
//! # use chrono::NaiveDate;
//! # fn transceive(_cmd: &[u8]) -> Vec<u8> { unimplemented!() }
//! # let key = DBAKey::new("L898902C",
//! #     NaiveDate::from_ymd_opt(1969, 8, 6).unwrap(),
//! #     NaiveDate::from_ymd_opt(1994, 6, 23).unwrap(),
//! #     false).unwrap();
//! let mut session = BacSession::new(key);
//! loop {
//!     match session.next().unwrap() {
//!         BacAction::SendApdu(apdu) => {
//!             let response = transceive(&apdu);
//!             session.feed_response(&response).unwrap();
//!         }
//!         BacAction::Done(sm) => {
//!             // SM is ready — use sm.protect / sm.unprotect from here.
//!             let _ = sm;
//!             break;
//!         }
//!     }
//! }
//! ```

use rand::rand_core::UnwrapErr;
use rand::{rngs::SysRng, Rng};

use crate::proto::bac::{self, BacError, E_LEN, K_LEN, MAC_LEN, NONCE_LEN};
use crate::proto::dba_key::DBAKey;
use crate::proto::des_smcipher::DesSmCipher;
use crate::proto::iso7816::command_apdu::CommandApdu;
use crate::proto::iso7816::iso7816::{cla, ins};
use crate::proto::iso7816::response_apdu::{ResponseApdu, StatusWord};
use crate::proto::mrtd_sm::MrtdSM;

/// Action requested by [`BacSession::next`].
pub enum BacAction {
    /// Send these bytes as an APDU to the chip; feed the full response
    /// (including status word) back via [`BacSession::feed_response`].
    SendApdu(Vec<u8>),
    /// Handshake complete — take ownership of the secure-messaging session.
    Done(MrtdSM<DesSmCipher>),
}

/// Synchronous BAC handshake state machine.
///
/// States advance linearly:
///
/// ```text
///     Start
///       │  next() → SendApdu(GET CHALLENGE)
///       ▼
///   WaitingForChallenge
///       │  feed_response(RND.IC || SW)
///       ▼
///   ReadyForExternalAuth
///       │  next() → SendApdu(EXTERNAL AUTHENTICATE)
///       ▼
///   WaitingForAuth
///       │  feed_response(E_IC || M_IC || SW)
///       ▼
///   Completed
///       │  next() → Done(sm)
///       ▼
///   Taken    (session consumed)
/// ```
pub struct BacSession {
    key: DBAKey,
    rnd_ifd: [u8; NONCE_LEN],
    kifd: [u8; K_LEN],
    state: State,
}

enum State {
    /// Haven't emitted anything yet.
    Start,
    /// Emitted GET CHALLENGE, waiting for RND.IC.
    WaitingForChallenge,
    /// Received RND.IC; ready to emit EXTERNAL AUTHENTICATE.
    ReadyForExternalAuth { rnd_icc: [u8; NONCE_LEN] },
    /// Emitted EXTERNAL AUTHENTICATE, waiting for E_IC || M_IC.
    WaitingForAuth { rnd_icc: [u8; NONCE_LEN] },
    /// Handshake finished; `Done` is ready to be taken.
    Completed(Option<MrtdSM<DesSmCipher>>),
    /// A response failed to validate; the session is poisoned and cannot be
    /// reused. This preserves the linear contract — a bad (even SW=9000)
    /// response must not silently rewind the machine to `Start`.
    Failed,
}

impl BacSession {
    /// Creates a new session with `RND.IFD` and `K.IFD` drawn from `SysRng`.
    pub fn new(key: DBAKey) -> Self {
        let mut rng = UnwrapErr(SysRng);
        let mut rnd_ifd = [0u8; NONCE_LEN];
        let mut kifd = [0u8; K_LEN];
        rng.fill_bytes(&mut rnd_ifd);
        rng.fill_bytes(&mut kifd);
        Self::with_random_bytes(key, rnd_ifd, kifd)
    }

    /// Creates a session with caller-supplied `RND.IFD` and `K.IFD`. Intended
    /// for tests and replaying recorded traces; do not use in production.
    pub fn with_random_bytes(key: DBAKey, rnd_ifd: [u8; NONCE_LEN], kifd: [u8; K_LEN]) -> Self {
        Self {
            key,
            rnd_ifd,
            kifd,
            state: State::Start,
        }
    }

    /// Advances the state machine and returns the next action.
    pub fn next(&mut self) -> Result<BacAction, BacError> {
        match &self.state {
            State::Start => {
                // GET CHALLENGE — request 8 random bytes from the chip.
                let cmd = CommandApdu::new(
                    cla::NO_SM,
                    ins::GET_CHALLENGE,
                    0x00,
                    0x00,
                    None,
                    NONCE_LEN as u32,
                )
                .map_err(|e| BacError(format!("GET CHALLENGE APDU: {e}")))?;
                self.state = State::WaitingForChallenge;
                Ok(BacAction::SendApdu(cmd.to_bytes()))
            }
            State::ReadyForExternalAuth { rnd_icc } => {
                let s = bac::generate_s(&self.rnd_ifd, rnd_icc, &self.kifd)?;
                let k_enc = self.key.enc_key();
                let k_mac = self.key.mac_key();
                let e_ifd = bac::encrypt_s(&k_enc, &s)?;
                let m_ifd = bac::mac_e(&k_mac, &e_ifd)?;
                let data = bac::generate_ea_data(&e_ifd, &m_ifd)?;

                let cmd = CommandApdu::new(
                    cla::NO_SM,
                    ins::EXTERNAL_AUTHENTICATE,
                    0x00,
                    0x00,
                    Some(data),
                    (E_LEN + MAC_LEN) as u32,
                )
                .map_err(|e| BacError(format!("EXTERNAL AUTHENTICATE APDU: {e}")))?;

                self.state = State::WaitingForAuth { rnd_icc: *rnd_icc };
                Ok(BacAction::SendApdu(cmd.to_bytes()))
            }
            State::Completed(sm_slot) => {
                // We placed the SM here when we parsed the EXTERNAL
                // AUTHENTICATE response; hand it over now.
                let sm = sm_slot
                    .as_ref()
                    .is_some()
                    .then(|| ())
                    .ok_or_else(|| BacError("BAC session already consumed".into()))?;
                let _ = sm;
                let taken = match &mut self.state {
                    State::Completed(slot) => slot.take(),
                    _ => unreachable!(),
                };
                Ok(BacAction::Done(taken.unwrap()))
            }
            State::WaitingForChallenge | State::WaitingForAuth { .. } => Err(BacError(
                "BAC session is waiting for a response; call feed_response first".into(),
            )),
            State::Failed => Err(BacError(
                "BAC session has failed and cannot continue".into(),
            )),
        }
    }

    /// Validates a GET CHALLENGE response body and returns `RND.IC`.
    fn handle_challenge(data: &[u8]) -> Result<[u8; NONCE_LEN], BacError> {
        if data.len() != NONCE_LEN {
            return Err(BacError(format!(
                "Expected {NONCE_LEN}-byte challenge, got {}",
                data.len()
            )));
        }
        let mut rnd_icc = [0u8; NONCE_LEN];
        rnd_icc.copy_from_slice(data);
        Ok(rnd_icc)
    }

    /// Validates an EXTERNAL AUTHENTICATE response body and builds the SM.
    fn handle_auth(
        &self,
        data: &[u8],
        rnd_icc: &[u8; NONCE_LEN],
    ) -> Result<MrtdSM<DesSmCipher>, BacError> {
        if data.len() != E_LEN + MAC_LEN {
            return Err(BacError(format!(
                "Expected {} bytes for external-auth response, got {}",
                E_LEN + MAC_LEN,
                data.len()
            )));
        }
        // Split E_IC || M_IC, verify MAC, decrypt, extract K.IC.
        let pair = bac::extract_eicc_and_micc(data)?;
        let k_enc = self.key.enc_key();
        let k_mac = self.key.mac_key();

        if !bac::verify_eicc(&pair.first, &k_mac, &pair.second)? {
            return Err(BacError("Verifying MAC of E.IC failed".into()));
        }

        let r = bac::decrypt_e_icc(&k_enc, &pair.first)?;
        let kicc = bac::verify_rnd_ifd_and_extract_kicc(&self.rnd_ifd, &r)?;
        let ks = bac::calculate_session_keys(&self.kifd, &kicc)?;
        let ssc = bac::calculate_ssc(&self.rnd_ifd, rnd_icc)?;
        let sm = bac::establish_sm(&ks.first, &ks.second, ssc)?;
        Ok(sm)
    }

    /// Consumes the full APDU response (data || SW) for the most recent
    /// outgoing APDU.
    ///
    /// If the session is not currently awaiting a response this is a usage error
    /// and the state is left untouched. Otherwise *any* failure — a malformed
    /// APDU, a non-`9000` status, empty data, or unparseable payload — poisons
    /// the session (transitions it to `Failed`) so a bad response can never
    /// leave the handshake retryable with the same terminal randomness.
    pub fn feed_response(&mut self, response: &[u8]) -> Result<(), BacError> {
        if !matches!(
            self.state,
            State::WaitingForChallenge | State::WaitingForAuth { .. }
        ) {
            return Err(BacError(
                "BAC session has no outstanding APDU to consume".into(),
            ));
        }
        let result = self.consume_response(response);
        if result.is_err() {
            self.state = State::Failed;
        }
        result
    }

    /// Inner handler — only called while waiting for a response (guaranteed by
    /// [`feed_response`]); any `Err` it returns poisons the session there.
    fn consume_response(&mut self, response: &[u8]) -> Result<(), BacError> {
        let rapdu = ResponseApdu::from_bytes(response)
            .map_err(|e| BacError(format!("Invalid response APDU: {e}")))?;
        if rapdu.status != StatusWord::SUCCESS {
            return Err(BacError(format!(
                "BAC step failed with status {}",
                rapdu.status
            )));
        }
        let data = rapdu
            .data
            .ok_or_else(|| BacError("Empty response data".into()))?;

        match std::mem::replace(&mut self.state, State::Start) {
            State::WaitingForChallenge => {
                let rnd_icc = Self::handle_challenge(&data)?;
                self.state = State::ReadyForExternalAuth { rnd_icc };
                Ok(())
            }
            State::WaitingForAuth { rnd_icc } => {
                let sm = self.handle_auth(&data, &rnd_icc)?;
                self.state = State::Completed(Some(sm));
                Ok(())
            }
            // Unreachable: `feed_response` already guarded the waiting states.
            _ => unreachable!("consume_response called outside a waiting state"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! ICAO 9303 p11 Appendix D.3 BAC worked example — end-to-end loopback.
    //!
    //! We simulate the ICC side by:
    //!   - returning a fixed `RND.IC` from the GET CHALLENGE command,
    //!   - computing the expected `E_IC` + `M_IC` for the EXTERNAL
    //!     AUTHENTICATE response using the same keys the terminal would
    //!     derive.
    //!
    //! After `BacSession::next()` returns `Done(sm)`, we assert the derived
    //! session keys and SSC match the Appendix D.3 reference values.

    use super::*;
    use crate::proto::bac::S_LEN;
    use crate::proto::iso7816::response_apdu::{ResponseApdu, StatusWord};
    use chrono::NaiveDate;

    fn hex(s: &str) -> Vec<u8> {
        ::hex::decode(s).unwrap()
    }

    fn icao_d3_key() -> DBAKey {
        // ICAO 9303 p11 Appendix D.3 worked example.
        DBAKey::new(
            "L898902C",
            NaiveDate::from_ymd_opt(1969, 8, 6).unwrap(),
            NaiveDate::from_ymd_opt(1994, 6, 23).unwrap(),
            false,
        )
        .unwrap()
    }

    fn build_response(data: &[u8]) -> Vec<u8> {
        ResponseApdu::new(StatusWord::SUCCESS, Some(data.to_vec())).to_bytes()
    }

    #[test]
    fn first_action_is_get_challenge() {
        let mut s = BacSession::new(icao_d3_key());
        let a = s.next().unwrap();
        match a {
            BacAction::SendApdu(bytes) => {
                // CLA=00, INS=84, P1=00, P2=00, Le=08
                assert_eq!(bytes, vec![0x00, 0x84, 0x00, 0x00, 0x08]);
            }
            _ => panic!("expected SendApdu"),
        }
    }

    #[test]
    fn next_without_feed_after_challenge_errors() {
        let mut s = BacSession::new(icao_d3_key());
        let _ = s.next().unwrap(); // emit GET CHALLENGE
        assert!(s.next().is_err()); // no response fed yet
    }

    #[test]
    fn feed_before_first_next_errors() {
        let mut s = BacSession::new(icao_d3_key());
        let resp = build_response(&[0u8; NONCE_LEN]);
        assert!(s.feed_response(&resp).is_err());
    }

    #[test]
    fn feed_rejects_non_9000_status() {
        let mut s = BacSession::new(icao_d3_key());
        let _ = s.next().unwrap();
        // Build response with SW=6A82 (file not found).
        let rapdu = ResponseApdu::new(StatusWord::new(0x6A, 0x82), Some(vec![0u8; 8]));
        let err = s.feed_response(&rapdu.to_bytes()).unwrap_err();
        assert!(err.0.contains("BAC step failed"));
    }

    #[test]
    fn feed_rejects_wrong_challenge_length() {
        let mut s = BacSession::new(icao_d3_key());
        let _ = s.next().unwrap();
        let resp = build_response(&[0u8; 7]); // too short
        assert!(s.feed_response(&resp).is_err());
    }

    #[test]
    fn malformed_challenge_poisons_session_not_resets_to_start() {
        let mut s = BacSession::new(icao_d3_key());
        let _ = s.next().unwrap(); // GET CHALLENGE
                                   // SW=9000 but a wrong-length body must not rewind the machine to Start.
        let resp = build_response(&[0u8; 7]);
        assert!(s.feed_response(&resp).is_err());
        // next() must NOT re-issue GET CHALLENGE; the session is poisoned.
        assert!(s.next().is_err());
    }

    #[test]
    fn empty_or_error_response_poisons_session() {
        // Empty-body SW=9000 while waiting must poison (not leave retryable).
        let mut s = BacSession::new(icao_d3_key());
        let _ = s.next().unwrap(); // GET CHALLENGE
        let empty = ResponseApdu::new(StatusWord::SUCCESS, None).to_bytes();
        assert!(s.feed_response(&empty).is_err());
        assert!(s.next().is_err()); // poisoned

        // A non-9000 status also poisons.
        let mut s2 = BacSession::new(icao_d3_key());
        let _ = s2.next().unwrap();
        let err_status = ResponseApdu::new(StatusWord::SM_DATA_INVALID, None).to_bytes();
        assert!(s2.feed_response(&err_status).is_err());
        assert!(s2.next().is_err());

        // But feeding when NOT awaiting a response is a usage error that does
        // NOT poison — a fresh session can still be driven from the start.
        let mut s3 = BacSession::new(icao_d3_key());
        assert!(s3
            .feed_response(&build_response(&[0u8; NONCE_LEN]))
            .is_err());
        assert!(s3.next().is_ok()); // still usable (emits GET CHALLENGE)
    }

    #[test]
    fn full_icao_d3_loopback_produces_expected_session_keys() {
        // ICAO 9303 Appendix D.3 fixed values.
        let rnd_ifd = hex("781723860C06C226");
        let kifd = hex("0B795240CB7049B01C19B33E32804F0B");
        let rnd_icc = hex("4608F91988702212");
        let kicc = hex("0B4F80323EB3191CB04970CB4052790B");

        // Expected outputs:
        let exp_ssc = hex("887022120C06C226");
        let exp_ks_enc = hex("979EC13B1CBFE9DCD01AB0FED307EAE5");
        let exp_ks_mac = hex("F1CB1F1FB5ADF208806B89DC579DC1F8");

        // Build a session with the spec's terminal randoms.
        let mut session = BacSession::with_random_bytes(
            icao_d3_key(),
            rnd_ifd.clone().try_into().unwrap(),
            kifd.clone().try_into().unwrap(),
        );

        // Step 1: GET CHALLENGE.
        match session.next().unwrap() {
            BacAction::SendApdu(apdu) => {
                assert_eq!(apdu, vec![0x00, 0x84, 0x00, 0x00, 0x08]);
            }
            _ => panic!("expected GET CHALLENGE"),
        }
        // ICC returns RND.IC.
        session.feed_response(&build_response(&rnd_icc)).unwrap();

        // Step 2: EXTERNAL AUTHENTICATE.
        let ea_apdu = match session.next().unwrap() {
            BacAction::SendApdu(bytes) => bytes,
            _ => panic!("expected EXTERNAL AUTHENTICATE"),
        };
        // Minimum sanity: header = 00 82 00 00, Lc = 0x28.
        assert_eq!(&ea_apdu[..5], &[0x00, 0x82, 0x00, 0x00, 0x28]);

        // Simulate ICC: compute E_IC = 3DES(K_enc, R) where
        // R = RND.IC || RND.IFD || K.IC.
        let key = icao_d3_key();
        let k_enc = key.enc_key();
        let k_mac = key.mac_key();
        let mut r = Vec::with_capacity(S_LEN);
        r.extend_from_slice(&rnd_icc);
        r.extend_from_slice(&rnd_ifd);
        r.extend_from_slice(&kicc);
        let eicc = bac::encrypt_s(&k_enc, &r).unwrap();
        let micc = bac::mac_e(&k_mac, &eicc).unwrap();
        let mut ea_body = eicc;
        ea_body.extend_from_slice(&micc);
        session.feed_response(&build_response(&ea_body)).unwrap();

        // Step 3: Done.
        let sm = match session.next().unwrap() {
            BacAction::Done(sm) => sm,
            _ => panic!("expected Done"),
        };

        // The session keys + SSC should match the spec exactly. K_enc is no
        // longer stored as raw bytes, so verify it functionally: the derived
        // cipher must encrypt identically to one built from the expected K_enc.
        use crate::proto::iso7816::smcipher::SmCipher as _;
        let probe = [0u8; 8];
        let expected_cipher = DesSmCipher::new(&exp_ks_enc, exp_ks_mac.clone()).unwrap();
        assert_eq!(
            sm.cipher.encrypt(&probe, None).unwrap(),
            expected_cipher.encrypt(&probe, None).unwrap(),
        );
        assert_eq!(sm.cipher.mac_key, exp_ks_mac);
        assert_eq!(sm.ssc().to_bytes(), exp_ssc);
    }

    #[test]
    fn mac_mismatch_on_eicc_is_rejected() {
        let rnd_ifd = [0xAAu8; NONCE_LEN];
        let kifd = [0xBBu8; K_LEN];
        let rnd_icc = [0xCCu8; NONCE_LEN];

        let mut session = BacSession::with_random_bytes(icao_d3_key(), rnd_ifd, kifd);
        let _ = session.next().unwrap();
        session.feed_response(&build_response(&rnd_icc)).unwrap();

        let _ea_apdu = match session.next().unwrap() {
            BacAction::SendApdu(bytes) => bytes,
            _ => panic!("expected EXTERNAL AUTHENTICATE"),
        };

        // Forge E_IC + bogus MAC.
        let bogus = vec![0u8; E_LEN + MAC_LEN];
        let err = session.feed_response(&build_response(&bogus)).unwrap_err();
        assert!(err.0.contains("MAC"));
    }

    #[test]
    fn done_cannot_be_taken_twice() {
        // Run a successful handshake, then call next() again.
        let rnd_ifd = hex("781723860C06C226");
        let kifd = hex("0B795240CB7049B01C19B33E32804F0B");
        let rnd_icc = hex("4608F91988702212");
        let kicc = hex("0B4F80323EB3191CB04970CB4052790B");

        let mut s = BacSession::with_random_bytes(
            icao_d3_key(),
            rnd_ifd.clone().try_into().unwrap(),
            kifd.clone().try_into().unwrap(),
        );
        let _ = s.next().unwrap();
        s.feed_response(&build_response(&rnd_icc)).unwrap();
        let _ = s.next().unwrap();

        let key = icao_d3_key();
        let mut r = Vec::new();
        r.extend_from_slice(&rnd_icc);
        r.extend_from_slice(&rnd_ifd);
        r.extend_from_slice(&kicc);
        let eicc = bac::encrypt_s(&key.enc_key(), &r).unwrap();
        let micc = bac::mac_e(&key.mac_key(), &eicc).unwrap();
        let mut body = eicc;
        body.extend_from_slice(&micc);
        s.feed_response(&build_response(&body)).unwrap();

        let _sm = match s.next().unwrap() {
            BacAction::Done(sm) => sm,
            _ => panic!("expected Done"),
        };
        // Second call should fail.
        assert!(s.next().is_err());
    }
}
