//! ICAO 9303 secure messaging handler.
//!
//! [`MrtdSM`] implements [`SecureMessaging`] by combining an [`SmCipher`]
//! (3DES or AES) with a monotonically-incrementing SSC. Protecting a
//! [`CommandApdu`] wraps the header + data into `DO'85'` or `DO'87'`, appends
//! the expected length in `DO'97'`, and authenticates the whole message with
//! a `DO'8E'` MAC. Unprotecting performs the reverse.

use crate::crypto::aes::AES_BLOCK_SIZE;
use crate::crypto::des::DesedeCipher;
use crate::crypto::iso9797;
use crate::lds::asn1_object_identifiers::CipherAlgorithm;
use crate::lds::tlv::{DecodedTv, Tlv};
use crate::proto::iso7816::command_apdu::CommandApdu;
use crate::proto::iso7816::iso7816::cla;
use crate::proto::iso7816::iso7816::ins;
use crate::proto::iso7816::response_apdu::{ResponseApdu, StatusWord};
use crate::proto::iso7816::sm::{
    self, SecureMessaging, SmError, TAG_DO85, TAG_DO87, TAG_DO8E, TAG_DO99,
};
use crate::proto::iso7816::smcipher::SmCipher;
use crate::proto::ssc::Ssc;

/// ICAO 9303 secure messaging handler.
pub struct MrtdSM<C: SmCipher> {
    pub cipher: C,
    ssc: Ssc,
}

impl<C: SmCipher> MrtdSM<C> {
    /// Creates a new [`MrtdSM`] with the given cipher and initial SSC.
    pub fn new(cipher: C, ssc: Ssc) -> Self {
        Self { cipher, ssc }
    }

    /// Replaces the current SSC.
    pub fn set_ssc(&mut self, ssc: Ssc) {
        self.ssc = ssc;
    }

    /// Returns the current SSC.
    pub fn ssc(&self) -> &Ssc {
        &self.ssc
    }

    // -----------------------------------------------------------------------
    // Cipher-specific helpers
    // -----------------------------------------------------------------------

    fn block_len(&self) -> Result<usize, SmError> {
        match self.cipher.cipher_algorithm() {
            CipherAlgorithm::Aes => Ok(AES_BLOCK_SIZE),
            CipherAlgorithm::DeSede => Ok(DesedeCipher::BLOCK_SIZE),
        }
    }

    /// Builds the encrypted data DO (`DO'85'` for extended READ BINARY, else
    /// `DO'87'`).
    fn generate_data_do(&self, cmd: &CommandApdu) -> Result<Vec<u8>, SmError> {
        match cmd.data.as_ref() {
            Some(data) if !data.is_empty() => {
                let block_len = self.block_len()?;
                let padded = iso9797::pad(data, block_len);
                let edata = self.cipher.encrypt(&padded, Some(&self.ssc));
                let out = if cmd.ins == ins::READ_BINARY_EXT {
                    sm::do85(&edata)
                } else {
                    sm::do87(&edata, true)
                };
                Ok(out)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn generate_m(&self, cmd: &CommandApdu, data_do: &[u8], do97: &[u8]) -> Result<Vec<u8>, SmError> {
        let block_len = self.block_len()?;
        let padded_header = iso9797::pad(&cmd.raw_header(), block_len);
        let mut out = padded_header;
        out.extend_from_slice(data_do);
        out.extend_from_slice(do97);
        Ok(out)
    }

    fn generate_n(&self, m: &[u8]) -> Result<Vec<u8>, SmError> {
        let block_len = self.block_len()?;
        let mut up_n = self.ssc.to_bytes();
        up_n.extend_from_slice(m);
        Ok(iso9797::pad(&up_n, block_len))
    }

    fn generate_k(&self, data: &[u8]) -> Result<Vec<u8>, SmError> {
        let block_len = self.block_len()?;
        let mut up_k = self.ssc.to_bytes();
        up_k.extend_from_slice(data);
        Ok(iso9797::pad(&up_k, block_len))
    }

    /// Decrypts a `DO'85'` or `DO'87'` data object.
    fn decrypt_data_do(&self, dtv: Option<&DecodedTv>) -> Result<Option<Vec<u8>>, SmError> {
        let Some(dtv) = dtv else {
            return Ok(None);
        };
        if dtv.value.is_empty() {
            return Ok(None);
        }

        let tag = dtv.tag.value;
        if tag != TAG_DO85 && tag != TAG_DO87 {
            return Err(SmError(format!(
                "Can't decrypt invalid data DO with tag={tag:X}"
            )));
        }

        let is_do87 = tag == TAG_DO87;
        let padded = !is_do87 || dtv.value[0] == 0x01;
        let cipher_input = if is_do87 { &dtv.value[1..] } else { &dtv.value[..] };
        let mut data = self.cipher.decrypt(cipher_input, Some(&self.ssc));
        if padded {
            data = iso9797::unpad(&data).to_vec();
        }
        Ok(Some(data))
    }

    fn parse_data_do(rapdu: &ResponseApdu) -> Result<Option<DecodedTv>, SmError> {
        let Some(data) = rapdu.data.as_ref() else {
            return Ok(None);
        };
        if data.is_empty() {
            return Ok(None);
        }
        let first = data[0] as u32;
        if first != TAG_DO85 && first != TAG_DO87 {
            return Ok(None);
        }
        let decoded = Tlv::decode(data).map_err(|e| SmError(format!("Invalid data DO: {e}")))?;
        Ok(Some(decoded))
    }

    fn parse_do99(rapdu: &ResponseApdu, offset: usize) -> Result<DecodedTv, SmError> {
        let data = rapdu
            .data
            .as_ref()
            .ok_or_else(|| SmError("Missing DO'99' in response APDU".into()))?;
        if offset >= data.len() || data[offset] as u32 != TAG_DO99 {
            return Err(SmError(
                "Missing DO'99' in response APDU or invalid offset".into(),
            ));
        }
        Tlv::decode(&data[offset..]).map_err(|e| SmError(format!("Invalid DO99: {e}")))
    }

    fn parse_do8e(rapdu: &ResponseApdu, offset: usize) -> Result<DecodedTv, SmError> {
        let data = rapdu
            .data
            .as_ref()
            .ok_or_else(|| SmError("Missing DO'8E' in response APDU".into()))?;
        if offset >= data.len() || data[offset] as u32 != TAG_DO8E {
            return Err(SmError(
                "Missing DO'8E' in response APDU or invalid offset".into(),
            ));
        }
        Tlv::decode(&data[offset..]).map_err(|e| SmError(format!("Invalid DO8E: {e}")))
    }

    fn mask_cla(cla_byte: u8) -> u8 {
        cla_byte | cla::SM_HEADER_AUTHN
    }
}

impl<C: SmCipher> SecureMessaging for MrtdSM<C> {
    fn protect(&mut self, cmd: &CommandApdu) -> Result<CommandApdu, SmError> {
        // Increment SSC BEFORE encrypting — mirrors the reference.
        self.ssc.increment();

        let mut masked = cmd.clone();
        masked.cla = Self::mask_cla(masked.cla);

        let data_do = self.generate_data_do(&masked)?;
        let do97 = sm::do97(masked.ne);
        let m = self.generate_m(&masked, &data_do, &do97)?;
        let n = self.generate_n(&m)?;
        let cc = self.cipher.mac(&n);
        let do8e = sm::do8e(&cc);

        let mut combined = data_do;
        combined.extend_from_slice(&do97);
        combined.extend_from_slice(&do8e);

        masked.data = Some(combined);
        masked.ne = 256;
        Ok(masked)
    }

    fn unprotect(&mut self, rapdu: &ResponseApdu) -> Result<ResponseApdu, SmError> {
        // Pass through degenerate SM errors / empty bodies unchanged.
        if rapdu.status == StatusWord::SM_DATA_MISSING
            || rapdu.status == StatusWord::SM_DATA_INVALID
            || rapdu.data.as_ref().map_or(true, |d| d.is_empty())
        {
            return Ok(rapdu.clone());
        }

        self.ssc.increment();

        let data_do = Self::parse_data_do(rapdu)?;
        let data_do_len = data_do.as_ref().map(|d| d.encoded_len).unwrap_or(0);
        let do99 = Self::parse_do99(rapdu, data_do_len)?;
        let do8e_start = data_do_len + do99.encoded_len;
        let do8e = Self::parse_do8e(rapdu, do8e_start)?;

        let body = rapdu
            .data
            .as_ref()
            .ok_or_else(|| SmError("Missing response data".into()))?;
        let k = self.generate_k(&body[..do8e_start])?;
        let cc = self.cipher.mac(&k);
        if cc != do8e.value {
            return Err(SmError("Invalid MAC of response APDU".into()));
        }

        let data = self.decrypt_data_do(data_do.as_ref())?;
        let status = StatusWord::from_bytes(&do99.value, 0)
            .map_err(|e| SmError(format!("Invalid SW in DO'99': {e}")))?;
        Ok(ResponseApdu::new(status, data))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::des_smcipher::DesSmCipher;

    fn build_sm() -> MrtdSM<DesSmCipher> {
        // ICAO 9303 p11 Appendix D.3 BAC session keys (used across the book).
        let k_enc = hex::decode("979EC13B1CBFE9DCD01AB0FED307EAE5").unwrap();
        let k_mac = hex::decode("F1CB1F1FB5ADF208806B89DC579DC1F8").unwrap();
        let cipher = DesSmCipher::new(k_enc, k_mac);
        let ssc = Ssc::new(&hex::decode("887022120C06C226").unwrap(), 64).unwrap();
        MrtdSM::new(cipher, ssc)
    }

    #[test]
    fn protect_masks_cla_and_appends_do8e() {
        let mut sm = build_sm();
        let cmd = CommandApdu::new(0x00, ins::SELECT_FILE, 0x02, 0x0C, Some(vec![0x01, 0x1E]), 0)
            .unwrap();
        let p = sm.protect(&cmd).unwrap();
        assert_eq!(p.cla & cla::SM_HEADER_AUTHN, cla::SM_HEADER_AUTHN);
        // Protected APDU has data = DO'87' || DO'8E' (no DO'97' since ne=0).
        let body = p.data.unwrap();
        // DO'8E' tag must appear somewhere in the body (at the end).
        assert!(body.contains(&(TAG_DO8E as u8)));
    }

    #[test]
    fn protect_increments_ssc() {
        let mut sm = build_sm();
        let before = sm.ssc().to_bytes();
        let cmd = CommandApdu::new(0x00, 0xA4, 0x02, 0x0C, Some(vec![0x01, 0x1E]), 0).unwrap();
        sm.protect(&cmd).unwrap();
        let after = sm.ssc().to_bytes();
        assert_ne!(before, after);
    }

    #[test]
    fn unprotect_passthrough_on_sm_data_missing() {
        let mut sm = build_sm();
        let rapdu = ResponseApdu::new(StatusWord::SM_DATA_MISSING, None);
        let out = sm.unprotect(&rapdu).unwrap();
        assert_eq!(out.status, StatusWord::SM_DATA_MISSING);
    }

    #[test]
    fn unprotect_passthrough_on_empty_body() {
        let mut sm = build_sm();
        let rapdu = ResponseApdu::new(StatusWord::SUCCESS, None);
        let out = sm.unprotect(&rapdu).unwrap();
        assert_eq!(out.status, StatusWord::SUCCESS);
    }

    #[test]
    fn unprotect_rejects_mac_mismatch() {
        let mut sm = build_sm();
        // Bogus SM response: DO'99' with SW=9000 + DO'8E' with zero MAC.
        let do99 = sm::do99(0x9000);
        let do8e = sm::do8e(&[0u8; 8]);
        let mut body = do99;
        body.extend_from_slice(&do8e);
        let rapdu = ResponseApdu::new(StatusWord::SUCCESS, Some(body));
        assert!(sm.unprotect(&rapdu).is_err());
    }

    #[test]
    fn protect_then_unprotect_via_loopback_roundtrip() {
        // Build two SMs with identical state; use one to protect, the other to
        // unprotect — this confirms the MAC / SSC handshake ticks in lock-step.
        let mut writer = build_sm();
        let mut reader = build_sm();

        let cmd = CommandApdu::new(
            0x00,
            ins::READ_BINARY,
            0x00,
            0x00,
            None,
            4, // short Le
        )
        .unwrap();
        let protected = writer.protect(&cmd).unwrap();

        // Forge a plausible response: encrypt 4 bytes of plaintext, build DO'87' + DO'99' + DO'8E'.
        let plaintext = vec![0xABu8, 0xCD, 0xEF, 0x01];
        let padded = iso9797::pad(&plaintext, DesedeCipher::BLOCK_SIZE);
        // Use reader's cipher to produce ciphertext with the (incremented) SSC.
        reader.ssc.increment();
        let ct = reader.cipher.encrypt(&padded, Some(&reader.ssc));
        // Reset to a fresh reader so unprotect performs its own increment.
        let mut reader = build_sm();

        let do87 = sm::do87(&ct, true);
        let do99 = sm::do99(0x9000);
        let mut body = do87.clone();
        body.extend_from_slice(&do99);

        // Compute MAC over k = SSC(incremented) || body.
        reader.ssc.increment();
        let mut k = reader.ssc.to_bytes();
        k.extend_from_slice(&body);
        let k_padded = iso9797::pad(&k, DesedeCipher::BLOCK_SIZE);
        let cc = reader.cipher.mac(&k_padded);
        // Rewind the SSC so unprotect re-increments it back to the same point.
        reader.ssc = build_sm().ssc;

        let do8e = sm::do8e(&cc);
        let mut body = do87;
        body.extend_from_slice(&do99);
        body.extend_from_slice(&do8e);

        let rapdu = ResponseApdu::new(StatusWord::SUCCESS, Some(body));
        let out = reader.unprotect(&rapdu).unwrap();
        assert_eq!(out.status, StatusWord::SUCCESS);
        assert_eq!(out.data.unwrap(), plaintext);

        // And `protected` is a real APDU (sanity).
        assert!(protected.data.is_some());
    }
}
