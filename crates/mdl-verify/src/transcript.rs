//! The `SessionTranscript` — the verifier-side half of device authentication.

use isomdl::cbor;
use isomdl::definitions::session::SessionTranscript as SessionTranscriptTrait;
use serde::{Deserialize, Serialize};

use crate::MdlError;

/// The CBOR `SessionTranscript` the holder signed over.
///
/// Device authentication signs `DeviceAuthentication = ["DeviceAuthentication",
/// SessionTranscript, DocType, DeviceNameSpacesBytes]`, so the verifier has to
/// reproduce the transcript **byte for byte**. Its shape depends on how the
/// credential was presented, and the variants are still moving:
///
/// | Flow | Handover |
/// |---|---|
/// | Proximity (BLE / NFC / QR), ISO 18013-5 §9.1.5.1 | `QRHandover` / `NFCHandover` |
/// | Online, ISO 18013-7 Annex B | `OID4VPHandover` |
/// | Browser Digital Credentials API, OpenID4VP 1.0 | `OpenID4VPDCAPIHandover` |
///
/// Rather than model each one and go stale, this type takes the transcript your
/// session layer already built — [`from_cbor`](Self::from_cbor) — or lets you
/// assemble one from parts. [`openid4vp_handover`](Self::openid4vp_handover) and
/// [`openid4vp_dcapi_handover`](Self::openid4vp_dcapi_handover) build the two online
/// shapes, taking the hashes as inputs because *what* gets hashed is exactly the part
/// that differs between drafts.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionTranscript {
    value: ciborium::Value,
    bytes: Vec<u8>,
}

impl SessionTranscript {
    /// Adopt an already-encoded `SessionTranscript`.
    ///
    /// The bytes are decoded and re-encoded, and rejected with
    /// [`MdlError::NonCanonicalTranscript`] if that does not reproduce the input
    /// exactly. That check matters: this crate hands the decoded value to the COSE
    /// layer, which re-encodes it before verifying. If the two encodings could
    /// differ, a genuine presentation would fail — or worse, a crafted non-canonical
    /// transcript could verify against something the holder never signed. ISO/IEC
    /// 18013-5 §9.1.5 requires deterministic encoding, so conforming implementations
    /// round-trip cleanly.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, MdlError> {
        let value: ciborium::Value = cbor::from_slice(bytes).map_err(|e| {
            MdlError::Unreadable(format!("session transcript is not valid CBOR: {e}"))
        })?;

        let reencoded = cbor::to_vec(&value).map_err(|e| {
            MdlError::Unreadable(format!("session transcript could not be re-encoded: {e}"))
        })?;

        if reencoded != bytes {
            return Err(MdlError::NonCanonicalTranscript);
        }

        Ok(Self {
            value,
            bytes: reencoded,
        })
    }

    /// Assemble `[DeviceEngagementBytes, EReaderKeyBytes, Handover]`.
    ///
    /// Pass `None` for the first two in the online flows, where ISO/IEC 18013-7 sets
    /// both to `null`.
    pub fn from_parts(
        device_engagement_bytes: Option<ciborium::Value>,
        e_reader_key_bytes: Option<ciborium::Value>,
        handover: ciborium::Value,
    ) -> Result<Self, MdlError> {
        let value = ciborium::Value::Array(vec![
            device_engagement_bytes.unwrap_or(ciborium::Value::Null),
            e_reader_key_bytes.unwrap_or(ciborium::Value::Null),
            handover,
        ]);

        let bytes = cbor::to_vec(&value).map_err(|e| {
            MdlError::Unreadable(format!("session transcript could not be encoded: {e}"))
        })?;

        Ok(Self { value, bytes })
    }

    /// The ISO/IEC 18013-7 Annex B online handover:
    /// `[null, null, [clientIdHash, responseUriHash, nonce]]`.
    ///
    /// Both hashes are SHA-256 over a two-element CBOR array of the value and the
    /// mdoc-generated nonce — `[client_id, mdoc_nonce]` and `[response_uri,
    /// mdoc_nonce]`. They are taken as inputs rather than computed here because the
    /// exact preimage has changed between drafts, and getting it wrong should fail
    /// loudly in your OpenID4VP layer, not silently here.
    pub fn openid4vp_handover(
        client_id_hash: &[u8],
        response_uri_hash: &[u8],
        nonce: &str,
    ) -> Result<Self, MdlError> {
        Self::from_parts(
            None,
            None,
            ciborium::Value::Array(vec![
                ciborium::Value::Bytes(client_id_hash.to_vec()),
                ciborium::Value::Bytes(response_uri_hash.to_vec()),
                ciborium::Value::Text(nonce.to_string()),
            ]),
        )
    }

    /// The OpenID4VP 1.0 Digital Credentials API handover:
    /// `[null, null, ["OpenID4VPDCAPIHandover", handoverInfoHash]]`.
    ///
    /// This is the shape used when a browser presents an mDL through the W3C Digital
    /// Credentials API — the path Apple Wallet and Google Wallet take on the web.
    /// `handover_info_hash` is SHA-256 over the CBOR-encoded `OpenID4VPDCAPIHandoverInfo`
    /// (`[origin, nonce, jwkThumbprint]`), which your OpenID4VP layer computes.
    pub fn openid4vp_dcapi_handover(handover_info_hash: &[u8]) -> Result<Self, MdlError> {
        Self::from_parts(
            None,
            None,
            ciborium::Value::Array(vec![
                ciborium::Value::Text("OpenID4VPDCAPIHandover".to_string()),
                ciborium::Value::Bytes(handover_info_hash.to_vec()),
            ]),
        )
    }

    /// The encoded transcript.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The decoded transcript, for callers that want to inspect the handover.
    pub fn as_value(&self) -> &ciborium::Value {
        &self.value
    }
}

impl Serialize for SessionTranscript {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SessionTranscript {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = ciborium::Value::deserialize(deserializer)?;
        let bytes = cbor::to_vec(&value).map_err(serde::de::Error::custom)?;
        Ok(Self { value, bytes })
    }
}

// Lets this stand in wherever isomdl wants a session transcript, which is what makes
// the "bring your own handover" approach work for both device-auth paths.
impl SessionTranscriptTrait for SessionTranscript {}
