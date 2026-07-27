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
    /// exactly.
    ///
    /// The check is *reproducibility*, not canonical form. This crate hands the
    /// decoded value to the COSE layer, which re-encodes it while building
    /// `DeviceAuthentication`; if that re-encoding could differ from what you passed
    /// in, verification would fail for a reason indistinguishable from a bad
    /// signature. Catching it here turns a mystery into a clear error. In practice
    /// the inputs that fail are the non-deterministic ones — indefinite-length items,
    /// non-minimal integers — which ISO/IEC 18013-5 §9.1.5 forbids anyway.
    ///
    /// It deliberately does *not* enforce deterministic map ordering. The transcript
    /// is built by your session layer, not supplied by the holder, so there is no
    /// attacker input to police here — and a holder that signed a non-canonically
    /// ordered transcript must still verify against those exact bytes. Canonicalising
    /// would reject genuine presentations.
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

    /// The ISO/IEC 18013-7 Annex B online handover, built from the values your
    /// OpenID4VP layer already has.
    ///
    /// This is the one to reach for in a `response_uri` flow: you minted `nonce` when
    /// you built the request, and the wallet returned `mdoc_generated_nonce` with the
    /// `vp_token`.
    ///
    /// The hashing is done here on purpose. It is SHA-256 over a CBOR array of two
    /// text strings — not the concatenation, not JSON — and getting it wrong produces
    /// a device-authentication failure indistinguishable from a real one. That is a
    /// miserable thing to debug in a verifier, so it lives in one tested place.
    pub fn openid4vp_iso_18013_7(
        client_id: &str,
        response_uri: &str,
        nonce: &str,
        mdoc_generated_nonce: &str,
    ) -> Result<Self, MdlError> {
        Self::openid4vp_handover(
            &hash_pair(client_id, mdoc_generated_nonce)?,
            &hash_pair(response_uri, mdoc_generated_nonce)?,
            nonce,
        )
    }

    /// The OpenID4VP 1.0 Digital Credentials API handover, built from its inputs.
    ///
    /// `origin` is the browser origin or the Android APK key hash, `nonce` the one
    /// from the credential request, and `jwk_thumbprint` the thumbprint of your
    /// response-encryption key. They are hashed as `SHA-256(CBOR([origin, nonce,
    /// jwk_thumbprint]))`, per the DC API profile.
    pub fn openid4vp_dcapi(
        origin: &str,
        nonce: &str,
        jwk_thumbprint: &[u8],
    ) -> Result<Self, MdlError> {
        let info = ciborium::Value::Array(vec![
            ciborium::Value::Text(origin.to_string()),
            ciborium::Value::Text(nonce.to_string()),
            ciborium::Value::Bytes(jwk_thumbprint.to_vec()),
        ]);

        Self::openid4vp_dcapi_handover(&sha256(&info)?)
    }

    /// The ISO/IEC 18013-7 Annex B online handover:
    /// `[null, null, [clientIdHash, responseUriHash, nonce]]`.
    ///
    /// Takes the hashes already computed. Prefer
    /// [`openid4vp_iso_18013_7`](Self::openid4vp_iso_18013_7), which computes them;
    /// this exists for a profile whose preimage differs from the one that method
    /// assumes.
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

/// `SHA-256(CBOR([value, mdoc_generated_nonce]))` — the Annex B hash.
fn hash_pair(value: &str, mdoc_generated_nonce: &str) -> Result<Vec<u8>, MdlError> {
    sha256(&ciborium::Value::Array(vec![
        ciborium::Value::Text(value.to_string()),
        ciborium::Value::Text(mdoc_generated_nonce.to_string()),
    ]))
}

fn sha256(value: &ciborium::Value) -> Result<Vec<u8>, MdlError> {
    use sha2::{Digest, Sha256};

    let encoded = cbor::to_vec(value)
        .map_err(|e| MdlError::Unreadable(format!("could not encode the handover inputs: {e}")))?;

    Ok(Sha256::digest(&encoded).to_vec())
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
