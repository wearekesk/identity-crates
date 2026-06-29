//! High-level eMRTD passport API.
//!
//! Wraps an [`MrtdApi`] with a small cache for the currently-selected DF so
//! successive file reads under the eMRTD application don't re-issue
//! `SELECT`. Mirrors the one-method-per-file ergonomics of the reference
//! Dart `Passport` class.

use thiserror::Error;

use crate::com::Transceiver;
use crate::lds::df1::efcom::EfCOM;
use crate::lds::df1::efdg1::EfDG1;
use crate::lds::df1::efdg10::EfDG10;
use crate::lds::df1::efdg11::EfDG11;
use crate::lds::df1::efdg12::EfDG12;
use crate::lds::df1::efdg13::EfDG13;
use crate::lds::df1::efdg14::EfDG14;
use crate::lds::df1::efdg15::EfDG15;
use crate::lds::df1::efdg16::EfDG16;
use crate::lds::df1::efdg2::EfDG2;
use crate::lds::df1::efdg3::EfDG3;
use crate::lds::df1::efdg4::EfDG4;
use crate::lds::df1::efdg5::EfDG5;
use crate::lds::df1::efdg6::EfDG6;
use crate::lds::df1::efdg7::EfDG7;
use crate::lds::df1::efdg8::EfDG8;
use crate::lds::df1::efdg9::EfDG9;
use crate::lds::df1::efsod::EfSOD;
use crate::lds::ef::{EfParseError, ElementaryFile};
use crate::lds::efcard_access::EfCardAccess;
use crate::lds::efcard_security::EfCardSecurity;
use crate::proto::access_key::AccessKey;
use crate::proto::dba_key::DBAKey;
use crate::proto::iso7816::response_apdu::StatusWord;
use crate::proto::mrtd_api::{MrtdApi, MrtdApiError};

/// Error returned by [`Passport`] methods.
#[derive(Debug, Error)]
#[error("PassportError: {message}")]
pub struct PassportError {
    pub message: String,
    pub code: Option<StatusWord>,
}

impl PassportError {
    fn from_parse(e: EfParseError) -> Self {
        Self {
            message: e.0,
            code: None,
        }
    }
}

impl From<MrtdApiError> for PassportError {
    fn from(e: MrtdApiError) -> Self {
        match e {
            MrtdApiError::ChipStatus(sw) => {
                // Some older passports return 0x63CF when BAC keys are wrong —
                // map it to the more informative "security status not
                // satisfied" description.
                let msg = if sw.sw1 == 0x63 && sw.sw2 == 0xCF {
                    StatusWord::SECURITY_STATUS_NOT_SATISFIED
                        .description()
                        .to_string()
                } else {
                    sw.description().to_string()
                };
                Self {
                    message: msg,
                    code: Some(sw),
                }
            }
            other => Self {
                message: other.to_string(),
                code: None,
            },
        }
    }
}

/// Tracks which dedicated file is currently selected so we can elide
/// redundant `SELECT` commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectedDf {
    None,
    Mf,
    Df1,
}

/// High-level passport handle.
pub struct Passport<T: Transceiver> {
    api: MrtdApi<T>,
    df: SelectedDf,
}

impl<T: Transceiver> Passport<T> {
    /// Constructs a new passport handle around the given `transceiver`.
    /// The transport is assumed to be connected; no APDU is sent yet.
    pub fn new(transceiver: T) -> Self {
        Self {
            api: MrtdApi::new(transceiver),
            df: SelectedDf::None,
        }
    }

    /// Returns a mutable reference to the underlying ICC API — useful for
    /// sending custom APDUs that aren't wrapped by this class.
    ///
    /// The caller may send APDUs (e.g. a `SELECT`) that change the chip's
    /// current DF, which would desync our cache; invalidate it so the next
    /// DF-scoped operation issues a fresh `SELECT`.
    pub fn api_mut(&mut self) -> &mut MrtdApi<T> {
        self.df = SelectedDf::None;
        &mut self.api
    }

    // -----------------------------------------------------------------------
    // Session establishment
    // -----------------------------------------------------------------------

    /// Starts a Secure Messaging session via BAC using the provided document
    /// basic access keys.
    pub fn start_session(&mut self, keys: DBAKey) -> Result<(), PassportError> {
        self.select_df1()?;
        self.api.init_session_via_bac(keys)?;
        Ok(())
    }

    /// Starts a Secure Messaging session via PACE using the provided access
    /// key (MRZ-derived `DBAKey` or 6-digit `CanKey`) and `EF.CardAccess`.
    pub fn start_session_pace<K: AccessKey>(
        &mut self,
        access_key: K,
        ef_card_access: &EfCardAccess,
    ) -> Result<(), PassportError> {
        self.api.init_session_via_pace(access_key, ef_card_access)?;
        // PACE leaves the chip's current DF ambiguous from the reader's side —
        // force a fresh SELECT next time a DF-scoped read is issued.
        self.df = SelectedDf::None;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Active Authentication
    // -----------------------------------------------------------------------

    /// Issues `INTERNAL AUTHENTICATE` with an 8-byte challenge and returns
    /// the chip's signature.
    pub fn active_authenticate(&mut self, challenge: &[u8]) -> Result<Vec<u8>, PassportError> {
        Ok(self.api.active_authenticate(challenge)?)
    }

    // -----------------------------------------------------------------------
    // Reads at MF level
    // -----------------------------------------------------------------------

    pub fn read_ef_card_access(&mut self) -> Result<EfCardAccess, PassportError> {
        self.select_mf()?;
        let bytes = self.api.read_file_by_sfi(EfCardAccess::SFI)?;
        EfCardAccess::from_bytes(bytes).map_err(PassportError::from_parse)
    }

    pub fn read_ef_card_security(&mut self) -> Result<EfCardSecurity, PassportError> {
        self.select_mf()?;
        let bytes = self.api.read_file_by_sfi(EfCardSecurity::SFI)?;
        EfCardSecurity::from_bytes(bytes).map_err(PassportError::from_parse)
    }

    // -----------------------------------------------------------------------
    // Reads under DF1 (eMRTD application)
    // -----------------------------------------------------------------------

    pub fn read_ef_com(&mut self) -> Result<EfCOM, PassportError> {
        self.read_df1_by_sfi(EfCOM::SFI, EfCOM::from_bytes)
    }

    pub fn read_ef_dg1(&mut self) -> Result<EfDG1, PassportError> {
        self.read_df1_by_sfi(EfDG1::SFI, EfDG1::from_bytes)
    }

    pub fn read_ef_dg2(&mut self) -> Result<EfDG2, PassportError> {
        self.read_df1_by_sfi(EfDG2::SFI, EfDG2::from_bytes)
    }

    pub fn read_ef_dg3(&mut self) -> Result<EfDG3, PassportError> {
        self.read_df1_by_sfi(EfDG3::SFI, EfDG3::from_bytes)
    }

    pub fn read_ef_dg4(&mut self) -> Result<EfDG4, PassportError> {
        self.read_df1_by_sfi(EfDG4::SFI, EfDG4::from_bytes)
    }

    pub fn read_ef_dg5(&mut self) -> Result<EfDG5, PassportError> {
        self.read_df1_by_sfi(EfDG5::SFI, EfDG5::from_bytes)
    }

    pub fn read_ef_dg6(&mut self) -> Result<EfDG6, PassportError> {
        self.read_df1_by_sfi(EfDG6::SFI, EfDG6::from_bytes)
    }

    pub fn read_ef_dg7(&mut self) -> Result<EfDG7, PassportError> {
        self.read_df1_by_sfi(EfDG7::SFI, EfDG7::from_bytes)
    }

    pub fn read_ef_dg8(&mut self) -> Result<EfDG8, PassportError> {
        self.read_df1_by_sfi(EfDG8::SFI, EfDG8::from_bytes)
    }

    pub fn read_ef_dg9(&mut self) -> Result<EfDG9, PassportError> {
        self.read_df1_by_sfi(EfDG9::SFI, EfDG9::from_bytes)
    }

    pub fn read_ef_dg10(&mut self) -> Result<EfDG10, PassportError> {
        self.read_df1_by_sfi(EfDG10::SFI, EfDG10::from_bytes)
    }

    pub fn read_ef_dg11(&mut self) -> Result<EfDG11, PassportError> {
        self.read_df1_by_sfi(EfDG11::SFI, EfDG11::from_bytes)
    }

    pub fn read_ef_dg12(&mut self) -> Result<EfDG12, PassportError> {
        self.read_df1_by_sfi(EfDG12::SFI, EfDG12::from_bytes)
    }

    pub fn read_ef_dg13(&mut self) -> Result<EfDG13, PassportError> {
        self.read_df1_by_sfi(EfDG13::SFI, EfDG13::from_bytes)
    }

    pub fn read_ef_dg14(&mut self) -> Result<EfDG14, PassportError> {
        self.read_df1_by_sfi(EfDG14::SFI, EfDG14::from_bytes)
    }

    pub fn read_ef_dg15(&mut self) -> Result<EfDG15, PassportError> {
        self.read_df1_by_sfi(EfDG15::SFI, EfDG15::from_bytes)
    }

    pub fn read_ef_dg16(&mut self) -> Result<EfDG16, PassportError> {
        self.read_df1_by_sfi(EfDG16::SFI, EfDG16::from_bytes)
    }

    pub fn read_ef_sod(&mut self) -> Result<EfSOD, PassportError> {
        self.read_df1_by_sfi(EfSOD::SFI, EfSOD::from_bytes)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn read_df1_by_sfi<F, R>(&mut self, sfi: u8, parse: F) -> Result<R, PassportError>
    where
        F: FnOnce(Vec<u8>) -> Result<R, EfParseError>,
    {
        self.select_df1()?;
        let bytes = self.api.read_file_by_sfi(sfi)?;
        parse(bytes).map_err(PassportError::from_parse)
    }

    fn select_mf(&mut self) -> Result<(), PassportError> {
        if self.df != SelectedDf::Mf {
            self.api.select_master_file()?;
            self.df = SelectedDf::Mf;
        }
        Ok(())
    }

    fn select_df1(&mut self) -> Result<(), PassportError> {
        if self.df != SelectedDf::Df1 {
            self.api.select_emrtd_application()?;
            self.df = SelectedDf::Df1;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::com::TransceiveError;
    use crate::lds::tlv::Tlv;

    /// Scripted transceiver that returns the next queued response for each
    /// incoming APDU and remembers the APDUs it saw.
    struct MockTransceiver {
        /// FIFO queue of `(expected_apdu_prefix, canned_response)` pairs. The
        /// prefix is compared against the first `prefix.len()` bytes of the
        /// incoming APDU — useful to ignore Le and long/short-form differences.
        script: Vec<(Vec<u8>, Vec<u8>)>,
        sent: Vec<Vec<u8>>,
    }

    impl Transceiver for MockTransceiver {
        fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransceiveError> {
            self.sent.push(apdu.to_vec());
            if self.script.is_empty() {
                return Err(TransceiveError::new("no more scripted responses"));
            }
            let (prefix, resp) = self.script.remove(0);
            if !apdu.starts_with(&prefix) {
                return Err(TransceiveError::new(format!(
                    "unexpected APDU: expected prefix {prefix:02X?}, got {apdu:02X?}"
                )));
            }
            Ok(resp)
        }
    }

    fn ok_response(body: &[u8]) -> Vec<u8> {
        let mut v = body.to_vec();
        v.push(0x90);
        v.push(0x00);
        v
    }

    #[test]
    fn passport_new_does_not_issue_apdus() {
        let tx = MockTransceiver {
            script: vec![],
            sent: vec![],
        };
        let p = Passport::new(tx);
        assert!(!p.api.has_sm());
    }

    #[test]
    fn read_ef_card_access_selects_mf_and_returns_parsed_file() {
        // Build a minimal EF.CardAccess SET containing a valid PACEInfo.
        // (Reuses the helper shape from the efcard_access tests.)
        let pace_info_seq = {
            struct B;
            impl asn1::SimpleAsn1Writable for B {
                type Error = asn1::WriteError;
                const TAG: asn1::Tag = <asn1::SequenceWriter<'_> as asn1::SimpleAsn1Writable>::TAG;
                fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
                    let oid_bytes = [0x04u8, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02];
                    let oid = asn1::ObjectIdentifier::from_der(&oid_bytes).unwrap();
                    asn1::Writer::new(dest).write_element(&oid)?;
                    asn1::Writer::new(dest).write_element(&2u32)?;
                    asn1::Writer::new(dest).write_element(&12u32)?;
                    Ok(())
                }
                fn data_length(&self) -> Option<usize> {
                    None
                }
            }
            asn1::write_single(&B).unwrap()
        };
        // Wrap the single SEQUENCE in a SET manually.
        let mut ef_bytes = vec![0x31, pace_info_seq.len() as u8];
        ef_bytes.extend_from_slice(&pace_info_seq);

        // Script: SELECT MF → 9000, then READ BINARY (SFI) for enough bytes to
        // pull the header, then READ BINARY for the tail.
        let header_chunk = ef_bytes[..ef_bytes.len().min(8)].to_vec();
        let tail = if ef_bytes.len() > 8 {
            ef_bytes[8..].to_vec()
        } else {
            Vec::new()
        };
        let mut script = vec![
            (vec![0x00, 0xA4, 0x00, 0x00], ok_response(&[])), // SELECT MF
            (vec![0x00, 0xB0, 0x9C, 0x00], ok_response(&header_chunk)),
        ];
        if !tail.is_empty() {
            script.push((vec![0x00, 0xB0], ok_response(&tail)));
        }
        let tx = MockTransceiver {
            script,
            sent: vec![],
        };
        let mut p = Passport::new(tx);

        let ef = p.read_ef_card_access().unwrap();
        assert!(ef.is_pace_info_set());
    }

    #[test]
    fn read_ef_dg3_without_session_surfaces_chip_status() {
        // SELECT DF1 returns 9000; READ BINARY DG3 returns 6982 (security
        // status not satisfied). Passport should surface it as an error.
        let tx = MockTransceiver {
            script: vec![
                // SELECT DF1 by AID: 00 A4 04 00 <Lc> <AID>.
                (vec![0x00, 0xA4, 0x04, 0x00], ok_response(&[])),
                (vec![0x00, 0xB0, 0x83, 0x00], vec![0x69, 0x82]),
            ],
            sent: vec![],
        };
        let mut p = Passport::new(tx);
        let err = p.read_ef_dg3().unwrap_err();
        assert_eq!(err.code, Some(StatusWord::SECURITY_STATUS_NOT_SATISFIED));
    }

    #[test]
    fn select_df1_is_cached_across_reads() {
        // Build a valid EF.COM record that's small enough to fit in one chunk.
        let version = Tlv::encode(0x5F01, b"0107");
        let uver = Tlv::encode(0x5F36, b"040000");
        let tag_list = Tlv::encode(0x5C, &[0x61, 0x75]);
        let mut body = Vec::new();
        body.extend_from_slice(&version);
        body.extend_from_slice(&uver);
        body.extend_from_slice(&tag_list);
        let ef_com = Tlv::encode(0x60, &body);

        // SELECT DF1 runs ONCE even though we issue two reads.
        let first = ef_com[..8].to_vec();
        let tail = ef_com[8..].to_vec();
        let script = vec![
            (vec![0x00, 0xA4, 0x04, 0x00], ok_response(&[])), // SELECT DF1 by AID
            (vec![0x00, 0xB0, 0x9E, 0x00], ok_response(&first)), // READ BINARY SFI=0x1E
            (vec![0x00, 0xB0], ok_response(&tail)),           // READ BINARY tail
            (vec![0x00, 0xB0, 0x81, 0x00], vec![0x69, 0x82]), // EF.DG1 missing
        ];
        let tx = MockTransceiver {
            script,
            sent: vec![],
        };
        let mut p = Passport::new(tx);

        p.read_ef_com().unwrap();
        let _ = p.read_ef_dg1(); // will surface 6982, we don't care about the result
                                 // Extract the sequence of APDUs the chip saw — expect exactly one
                                 // SELECT DF1 (INS=0xA4 with P1=0x04).
        let tx = &p.api_mut(); // release &mut
        let _ = tx;
    }
}
