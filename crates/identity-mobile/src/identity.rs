//! The one result shape, whichever document it came from.

/// Which document the identity was read from, with the detail specific to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentSource {
    /// An ePassport or other eMRTD chip (ICAO 9303).
    Passport {
        /// `P`, `ID`, `I`… from the MRZ.
        document_code: String,
        /// The issuing state, as the three-letter MRZ code.
        issuing_state: String,
        /// Which data groups were hashed and matched against EF.SOD.
        verified_data_groups: Vec<u8>,
        /// Every data group EF.SOD commits to. Any element you rely on that came
        /// from a group *not* in `verified_data_groups` is unauthenticated.
        signed_data_groups: Vec<u8>,
    },
    /// An ISO/IEC 18013-5 mobile driving licence.
    MobileDrivingLicence {
        /// e.g. `org.iso.18013.5.1.mDL`.
        doc_type: String,
        /// The issuing authority as named in the credential, e.g. `"NY DMV"`.
        issuing_authority: Option<String>,
        /// Which session transcript the holder actually signed, when more than one was
        /// offered — `openid4vp-1.0`, `openid4vp-dcapi`, `iso-18013-7`, `cbor`.
        ///
        /// `None` when no session was supplied, and device authentication therefore did
        /// not happen at all. Worth logging: it tells you what your wallets emit, and
        /// so which profiles you can stop offering.
        session_profile: Option<String>,
    },
}

/// What was actually proven about a document, as three separate questions.
///
/// They are kept apart because they fail independently and a caller's policy for each
/// is different. Nothing here is a single "valid" boolean, because there is no honest
/// single boolean: a genuine credential from an unknown issuer, and a well-formed
/// forgery, are both "invalid" for very different reasons.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Authenticity {
    /// The data is what the issuer signed, and has not been altered.
    ///
    /// For a passport this is passive authentication: the data group hashes match a
    /// genuine EF.SOD. For an mDL it is the MSO signature plus the element digests.
    pub data_authentic: bool,

    /// The signer chains to a trust anchor *you* supplied — a CSCA for a passport, an
    /// IACA for an mDL.
    ///
    /// `false` with `data_authentic == true` means the document is internally
    /// consistent but you have no basis to say who issued it. That is the normal
    /// result when no anchors were passed in.
    pub issuer_trusted: bool,

    /// The document proved it is the original rather than a copy: chip active
    /// authentication for a passport, device authentication for an mDL.
    ///
    /// `None` means it was not attempted — which is not the same as `Some(false)`.
    /// Without it, cloned chip data and captured mDL responses both verify.
    ///
    /// It binds the **document**, not the person. `Some(true)` says the chip or device
    /// present holds the private key the issuer signed; it says nothing about whether
    /// the person presenting it is the person it was issued to. That comparison is
    /// between [`portrait`](VerifiedIdentity::portrait) and the face in front of you,
    /// and this crate does not make it.
    pub holder_bound: Option<bool>,

    /// The credential is inside its own validity window.
    pub not_expired: bool,

    /// Things that did not fail the verification but that an operator should see —
    /// an unreachable CRL, a data group present on the chip but not read, an
    /// unparseable field.
    pub warnings: Vec<String>,
}

impl Authenticity {
    /// Genuine, attributable to an issuer you trust, and in date.
    ///
    /// Deliberately does **not** include [`holder_bound`](Self::holder_bound): whether
    /// you need proof of presence depends on whether you are reading a document in
    /// person or accepting one over a wire, and pretending otherwise would make the
    /// weaker check look like the stronger one. Gate on both when it matters.
    pub fn is_trustworthy(&self) -> bool {
        self.data_authentic && self.issuer_trusted && self.not_expired
    }

    /// [`is_trustworthy`](Self::is_trustworthy) plus proof this is the original
    /// document and not a replay. The bar for an in-person check.
    pub fn is_present_and_trustworthy(&self) -> bool {
        self.is_trustworthy() && self.holder_bound == Some(true)
    }
}

/// A verified person, from a passport chip or an mDL.
///
/// Every field is optional because both document types support partial data: an mDL
/// can disclose `age_over_21` and nothing else, and a passport read can be limited to
/// the groups you asked for. Absent means "not disclosed or not read", never
/// "rejected" — anything rejected is an error rather than a missing field.
///
/// Dates are ISO 8601 strings (`YYYY-MM-DD`) rather than a date type, because this
/// crosses an FFI boundary and every platform can read a string.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifiedIdentity {
    pub family_name: Option<String>,
    pub given_name: Option<String>,
    /// `YYYY-MM-DD`.
    pub date_of_birth: Option<String>,
    /// `YYYY-MM-DD`.
    pub date_of_expiry: Option<String>,
    pub document_number: Option<String>,
    /// Three-letter code for a passport, ISO 3166 for an mDL.
    pub nationality: Option<String>,
    /// `M`, `F`, or `None` when the document does not say.
    ///
    /// Normalised across the two: a passport's MRZ already uses these letters, and an
    /// mDL's ISO/IEC 5218 codes are mapped onto them (1 and 2 to `M` and `F`). Both
    /// spell "not stated" as absence — an MRZ `<`, and codes 0 and 9 — so the same fact
    /// tests the same way whichever document it came from. A code outside that set
    /// arrives as its number rather than being discarded, since the issuer signed it and
    /// this crate should not pretend otherwise.
    pub sex: Option<String>,
    /// The holder's photograph, as the bytes the issuer signed — JPEG or JPEG 2000
    /// from a passport's DG2, JPEG from an mDL's `portrait`.
    pub portrait: Option<Vec<u8>>,
    /// `age_over_NN` attestations the document made, as `(NN, answer)`.
    ///
    /// Passports do not carry these; they are the mDL's reason for existing in a bar.
    pub age_attestations: Vec<(u8, bool)>,

    pub source: Option<DocumentSource>,
    pub authenticity: Authenticity,
}

impl VerifiedIdentity {
    /// An `age_over_NN` answer, if the document made that particular claim.
    ///
    /// For a passport, derive it from [`date_of_birth`](Self::date_of_birth) instead —
    /// and note that doing so reveals the date of birth to your application, which is
    /// exactly what the mDL attestation exists to avoid.
    pub fn age_over(&self, years: u8) -> Option<bool> {
        self.age_attestations
            .iter()
            .find(|(n, _)| *n == years)
            .map(|(_, answer)| *answer)
    }

    /// `"Priya Sharma"`, or whichever half is present.
    pub fn display_name(&self) -> Option<String> {
        match (&self.given_name, &self.family_name) {
            (Some(given), Some(family)) => Some(format!("{given} {family}")),
            (Some(one), None) | (None, Some(one)) => Some(one.clone()),
            (None, None) => None,
        }
    }
}
