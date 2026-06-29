//! ICC-level protocol orchestrator.
//!
//! Wraps a synchronous [`Transceiver`] with optional secure-messaging state,
//! and exposes the minimal command surface the [`Passport`] layer needs:
//! SELECT MF / DF, READ BINARY (by SFI with chunked tail), INTERNAL
//! AUTHENTICATE, and session establishment via BAC or PACE.
//!
//! [`Passport`]: crate::passport::Passport
//! [`Transceiver`]: crate::com::Transceiver

use thiserror::Error;

use crate::com::{TransceiveError, Transceiver};
use crate::lds::df1::df1::AID;
use crate::lds::efcard_access::EfCardAccess;
use crate::lds::tlv::Tlv;
use crate::proto::access_key::AccessKey;
use crate::proto::bac_session::{BacAction, BacSession};
use crate::proto::dba_key::DBAKey;
use crate::proto::iso7816::command_apdu::{CommandApdu, CommandApduError};
use crate::proto::iso7816::iso7816::{cla, ins, select_file_p1, select_file_p2};
use crate::proto::iso7816::response_apdu::{
    ResponseApdu, ResponseApduError, StatusWord,
};
use crate::proto::iso7816::sm::SecureMessaging;
use crate::proto::pace_session::{PaceAction, PaceSession};

/// Errors surfaced by [`MrtdApi`].
#[derive(Debug, Error)]
pub enum MrtdApiError {
    #[error(transparent)]
    Transceive(#[from] TransceiveError),
    #[error("chip returned status {0}")]
    ChipStatus(StatusWord),
    #[error("APDU construction failed: {0}")]
    Apdu(String),
    #[error("response parse failed: {0}")]
    Response(String),
    #[error("TLV parse failed: {0}")]
    Tlv(String),
    #[error("invalid challenge length {0} (expected 8)")]
    InvalidChallengeLen(usize),
    #[error("EF.CardAccess is missing a PACEInfo record")]
    MissingPaceInfo,
    #[error("offset {0} exceeds READ BINARY limit (32767)")]
    OffsetTooLarge(u32),
    #[error("session establishment failed: {0}")]
    Session(String),
}

impl From<CommandApduError> for MrtdApiError {
    fn from(e: CommandApduError) -> Self {
        Self::Apdu(e.to_string())
    }
}
impl From<ResponseApduError> for MrtdApiError {
    fn from(e: ResponseApduError) -> Self {
        Self::Response(e.to_string())
    }
}

/// Initial read length used to pull the outer BER-TLV header so that the
/// total file size can be decoded before fetching the tail.
const HEADER_CHUNK_LEN: u32 = 8;
/// Chunk size used for subsequent `READ BINARY` calls — leaves headroom for
/// secure-messaging overhead under a 256-byte chip buffer.
const BODY_CHUNK_LEN: u32 = 0xDC;

/// ICC-level API handle.
pub struct MrtdApi<T: Transceiver> {
    transceiver: T,
    sm: Option<Box<dyn SecureMessaging>>,
}

impl<T: Transceiver> MrtdApi<T> {
    pub fn new(transceiver: T) -> Self {
        Self {
            transceiver,
            sm: None,
        }
    }

    /// Returns `true` once a secure-messaging session has been established.
    pub fn has_sm(&self) -> bool {
        self.sm.is_some()
    }

    /// Destroys any active SM session. Useful for re-authenticating.
    pub fn clear_sm(&mut self) {
        self.sm = None;
    }

    // -----------------------------------------------------------------------
    // SELECT
    // -----------------------------------------------------------------------

    /// `SELECT FILE` by file ID for the Master File (`0x3F00`).
    pub fn select_master_file(&mut self) -> Result<(), MrtdApiError> {
        let cmd = CommandApdu::new(
            cla::NO_SM,
            ins::SELECT_FILE,
            select_file_p1::BY_ID,
            select_file_p2::RETURN_FCI,
            Some(vec![0x3F, 0x00]),
            0,
        )?;
        self.transceive_cmd(&cmd)?;
        Ok(())
    }

    /// `SELECT FILE` by DF name for the eMRTD application (AID `A0000002471001`).
    pub fn select_emrtd_application(&mut self) -> Result<(), MrtdApiError> {
        let cmd = CommandApdu::new(
            cla::NO_SM,
            ins::SELECT_FILE,
            select_file_p1::BY_DF_NAME,
            select_file_p2::RETURN_FCI,
            Some(AID.clone()),
            0,
        )?;
        self.transceive_cmd(&cmd)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // INTERNAL AUTHENTICATE (AA)
    // -----------------------------------------------------------------------

    /// Sends `INTERNAL AUTHENTICATE` with the given 8-byte challenge and
    /// returns the signature bytes.
    pub fn active_authenticate(
        &mut self,
        challenge: &[u8],
    ) -> Result<Vec<u8>, MrtdApiError> {
        if challenge.len() != 8 {
            return Err(MrtdApiError::InvalidChallengeLen(challenge.len()));
        }
        let cmd = CommandApdu::new(
            cla::NO_SM,
            ins::INTERNAL_AUTHENTICATE,
            0x00,
            0x00,
            Some(challenge.to_vec()),
            256,
        )?;
        let rapdu = self.transceive_cmd(&cmd)?;
        rapdu
            .data
            .ok_or_else(|| MrtdApiError::Response("empty response to INTERNAL AUTHENTICATE".into()))
    }

    // -----------------------------------------------------------------------
    // READ BINARY (by SFI + chunked tail)
    // -----------------------------------------------------------------------

    /// Reads the full BER-TLV file addressed by its short file ID.
    ///
    /// First fetches enough bytes to decode the outer TLV header, then loops
    /// `READ BINARY` calls at successive offsets until the whole record has
    /// been retrieved.
    pub fn read_file_by_sfi(&mut self, sfi: u8) -> Result<Vec<u8>, MrtdApiError> {
        let first = self.read_binary_by_sfi(sfi, 0, HEADER_CHUNK_LEN)?;
        if first.len() < 2 {
            return Err(MrtdApiError::Tlv("not enough bytes for TLV header".into()));
        }
        let decoded = Tlv::decode_tag_and_length(&first)
            .map_err(|e| MrtdApiError::Tlv(e.to_string()))?;
        let total_len = decoded.encoded_len + decoded.length.value;

        let mut data = first;
        while data.len() < total_len {
            let remaining = (total_len - data.len()) as u32;
            let ne = remaining.min(BODY_CHUNK_LEN);
            let offset = data.len() as u32;
            let chunk = self.read_binary(offset, ne)?;
            if chunk.is_empty() {
                break;
            }
            data.extend_from_slice(&chunk);
        }
        data.truncate(total_len);
        Ok(data)
    }

    fn read_binary_by_sfi(
        &mut self,
        sfi: u8,
        offset: u8,
        ne: u32,
    ) -> Result<Vec<u8>, MrtdApiError> {
        // Per ISO 7816-4: SFI-flagged READ BINARY encodes the SFI in P1 (bit 8
        // set, low 5 bits = SFI number). Offset must fit in P2 (<= 255).
        let p1 = 0x80 | (sfi & 0x1F);
        let cmd = CommandApdu::new(cla::NO_SM, ins::READ_BINARY, p1, offset, None, ne)?;
        let rapdu = self.transceive_cmd(&cmd)?;
        Ok(rapdu.data.unwrap_or_default())
    }

    fn read_binary(&mut self, offset: u32, ne: u32) -> Result<Vec<u8>, MrtdApiError> {
        if offset > 0x7FFF {
            return Err(MrtdApiError::OffsetTooLarge(offset));
        }
        let p1 = (offset >> 8) as u8;
        let p2 = (offset & 0xFF) as u8;
        let cmd = CommandApdu::new(cla::NO_SM, ins::READ_BINARY, p1, p2, None, ne)?;
        let rapdu = self.transceive_cmd(&cmd)?;
        Ok(rapdu.data.unwrap_or_default())
    }

    // -----------------------------------------------------------------------
    // Session establishment
    // -----------------------------------------------------------------------

    /// Runs the BAC handshake driving [`BacSession`] through this transceiver.
    pub fn init_session_via_bac(&mut self, key: DBAKey) -> Result<(), MrtdApiError> {
        let mut session = BacSession::new(key);
        loop {
            match session.next().map_err(|e| MrtdApiError::Session(e.0))? {
                BacAction::SendApdu(apdu) => {
                    let resp = self.transceiver.transceive(&apdu)?;
                    session
                        .feed_response(&resp)
                        .map_err(|e| MrtdApiError::Session(e.0))?;
                }
                BacAction::Done(sm) => {
                    self.sm = Some(Box::new(sm));
                    return Ok(());
                }
            }
        }
    }

    /// Runs the PACE (ECDH-GM on NIST P-256) handshake using the PaceInfo
    /// carried in `ef_card_access`.
    pub fn init_session_via_pace<K: AccessKey>(
        &mut self,
        access_key: K,
        ef_card_access: &EfCardAccess,
    ) -> Result<(), MrtdApiError> {
        let pi = ef_card_access
            .pace_info()
            .ok_or(MrtdApiError::MissingPaceInfo)?;
        let protocol = pi.protocol.clone();
        let parameter_id = u32::try_from(pi.parameter_id)
            .map_err(|_| MrtdApiError::Session("parameter_id out of range".into()))?;
        let mut session = PaceSession::new_ecdh(access_key, protocol, parameter_id)
            .map_err(|e| MrtdApiError::Session(e.to_string()))?;
        loop {
            match session.next().map_err(|e| MrtdApiError::Session(e.to_string()))? {
                PaceAction::SendApdu(apdu) => {
                    let resp = self.transceiver.transceive(&apdu)?;
                    session
                        .feed_response(&resp)
                        .map_err(|e| MrtdApiError::Session(e.to_string()))?;
                }
                PaceAction::Done(sm) => {
                    self.sm = Some(Box::new(sm));
                    return Ok(());
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Core transceive (SM-aware)
    // -----------------------------------------------------------------------

    fn transceive_cmd(&mut self, cmd: &CommandApdu) -> Result<ResponseApdu, MrtdApiError> {
        let wire = match self.sm.as_mut() {
            Some(sm) => sm
                .protect(cmd)
                .map_err(|e| MrtdApiError::Response(e.0))?,
            None => cmd.clone(),
        };
        let resp_bytes = self.transceiver.transceive(&wire.to_bytes())?;
        let rapdu = ResponseApdu::from_bytes(&resp_bytes)?;
        let unwrapped = match self.sm.as_mut() {
            Some(sm) => sm
                .unprotect(&rapdu)
                .map_err(|e| MrtdApiError::Response(e.0))?,
            None => rapdu,
        };
        if unwrapped.status != StatusWord::SUCCESS {
            return Err(MrtdApiError::ChipStatus(unwrapped.status));
        }
        Ok(unwrapped)
    }
}
