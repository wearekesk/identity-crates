//! ePassport / eMRTD chips (ICAO 9303).
//!
//! Split deliberately in two:
//!
//! - [`read_passport`] drives a live chip, which needs NFC from the platform.
//! - [`verify_passport`] takes files that were already read and does the verification
//!   and mapping. Nothing in it touches hardware.
//!
//! The split matters because plenty of apps already have an NFC stack — a Flutter
//! plugin, a native SDK — and only want the verification half. It also means the
//! security-relevant code is testable without a chip.

use std::cell::Cell;
use std::rc::Rc;

use chrono::NaiveDate;
use dmrtd::auth::passive::{self, ChainStatus, DataGroup, PassiveAuth, TrustAnchor};
use dmrtd::com::{TransceiveError, Transceiver};
use dmrtd::lds::df1::efdg1::EfDG1;
use dmrtd::lds::df1::efdg2::EfDG2;
use dmrtd::lds::ef::ElementaryFile;
use dmrtd::passport::Passport;
use dmrtd::proto::dba_key::DBAKey;

use crate::identity::{Authenticity, DocumentSource, VerifiedIdentity};
use crate::IdentityError;

/// The platform's NFC, seen from Rust.
///
/// Implement this over whatever the host gives you — `NfcAdapter`/`IsoDep` on Android,
/// `NFCISO7816Tag` on iOS, or a Dart callback through `flutter_rust_bridge`. One APDU
/// in, the full response (data followed by SW1 SW2) out.
///
/// Errors are strings because they cross an FFI boundary and there is nothing this
/// crate can usefully do with a typed platform error beyond showing it.
pub trait ApduChannel {
    /// Send one APDU and return the chip's complete response.
    ///
    /// Return `Err` only for transport failures — a lost tag, a timeout. A status
    /// word indicating the chip refused something is a *successful* transceive: pass
    /// it back and let the protocol layer interpret it.
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String>;
}

/// Bridges the FFI-friendly trait to the one `dmrtd` wants, remembering whether the
/// transport itself ever failed.
///
/// That flag decides what the holder gets told. A session that will not start looks
/// identical from the protocol's side whether the key was wrong or the phone moved,
/// and those need opposite responses: retype the details, versus hold still. Without
/// this, every dropped tag becomes "check your document number".
struct Channel {
    inner: Box<dyn ApduChannel>,
    transport_failed: Rc<Cell<bool>>,
}

impl Transceiver for Channel {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransceiveError> {
        self.inner.transceive(apdu).map_err(|e| {
            self.transport_failed.set(true);
            TransceiveError::new(e)
        })
    }
}

/// The key printed on the document, which unlocks the chip.
///
/// This is the point of scanning the MRZ first: without it the chip will not talk.
/// Nothing here is secret — it is all printed on the page — but the chip requires
/// proof you have physically seen the document.
#[derive(Debug, Clone)]
pub struct MrzKey {
    pub document_number: String,
    pub date_of_birth: NaiveDate,
    pub date_of_expiry: NaiveDate,
}

impl MrzKey {
    /// Build from ISO 8601 dates (`YYYY-MM-DD`), the form that survives an FFI
    /// boundary.
    pub fn new(
        document_number: impl Into<String>,
        date_of_birth: &str,
        date_of_expiry: &str,
    ) -> Result<Self, IdentityError> {
        let parse = |what: &str, value: &str| {
            NaiveDate::parse_from_str(value, "%Y-%m-%d").map_err(|e| {
                IdentityError::Unreadable(format!("{what} is not a YYYY-MM-DD date: {e}"))
            })
        };

        Ok(Self {
            document_number: document_number.into(),
            date_of_birth: parse("date of birth", date_of_birth)?,
            date_of_expiry: parse("date of expiry", date_of_expiry)?,
        })
    }
}

/// Which session-establishment protocol to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Session {
    /// Try PACE, fall back to BAC. What you want on a fleet of mixed documents:
    /// PACE is mandatory for newer passports and absent from older ones.
    #[default]
    Auto,
    /// PACE only. Fails on a document that does not support it.
    Pace,
    /// BAC only.
    Bac,
}

/// What to read, and how hard to work.
#[derive(Debug, Clone)]
pub struct PassportOptions {
    pub session: Session,
    /// Read DG2, the holder's photograph. It is the largest file on the chip by a
    /// wide margin, so skipping it makes a read noticeably faster.
    pub read_portrait: bool,
    /// Run active authentication, proving the chip is not a clone.
    ///
    /// Costs an extra round trip and only works on documents carrying DG15. Worth it
    /// for an in-person check; pointless if you are verifying files read elsewhere.
    pub active_authentication: bool,
}

impl Default for PassportOptions {
    fn default() -> Self {
        Self {
            session: Session::Auto,
            read_portrait: true,
            active_authentication: true,
        }
    }
}

/// The files read off a chip.
///
/// Hand these to [`verify_passport`] if your NFC stack already read them.
#[derive(Debug, Clone, Default)]
pub struct PassportFiles {
    /// EF.SOD — the issuer's signature over the data group hashes. Without it nothing
    /// can be verified.
    pub sod: Vec<u8>,
    /// EF.DG1 — the MRZ, and therefore the identity.
    pub dg1: Vec<u8>,
    /// EF.DG2 — the photograph.
    pub dg2: Option<Vec<u8>>,
    /// Whether active authentication succeeded, if it was attempted.
    pub active_authentication: Option<bool>,
}

/// Read a passport from a live chip and verify it.
///
/// `anchors` are DER-encoded CSCA certificates from a masterlist. With none supplied
/// the read still happens and the data is still checked against EF.SOD, but
/// `issuer_trusted` comes back `false` — genuine-looking is not the same as genuine.
pub fn read_passport(
    channel: Box<dyn ApduChannel>,
    key: &MrzKey,
    anchors: &[Vec<u8>],
    options: &PassportOptions,
) -> Result<VerifiedIdentity, IdentityError> {
    let transport_failed = Rc::new(Cell::new(false));
    let mut passport = Passport::new(Channel {
        inner: channel,
        transport_failed: Rc::clone(&transport_failed),
    });

    // A session failure means one of two things, and the holder should be told which.
    let session_failed = || {
        if transport_failed.get() {
            IdentityError::Nfc("the chip stopped responding during setup".to_string())
        } else {
            IdentityError::Access
        }
    };

    let dba = |pace| {
        DBAKey::new(
            key.document_number.clone(),
            key.date_of_birth,
            key.date_of_expiry,
            pace,
        )
        .map_err(|e| IdentityError::Unreadable(format!("the access key is not usable: {e}")))
    };

    // PACE is negotiated from EF.CardAccess, which is readable before any session is
    // established. A chip without it cannot do PACE at all.
    let card_access = passport.read_ef_card_access().ok();

    match (options.session, card_access) {
        (Session::Pace, None) => {
            return Err(IdentityError::Unreadable(
                "PACE was required but the chip has no EF.CardAccess".to_string(),
            ))
        }
        (Session::Pace, Some(access)) => passport
            .start_session_pace(dba(true)?, &access)
            .map_err(|_| session_failed())?,

        (Session::Bac, _) => passport
            .start_session(dba(false)?)
            .map_err(|_| session_failed())?,

        // PACE first where the chip offers it: it is mandatory on newer documents and
        // strictly stronger. A failure here is usually "this chip does not really do
        // PACE" rather than a bad key, so BAC gets a turn before the holder is told to
        // retype anything.
        (Session::Auto, Some(access)) => {
            if passport.start_session_pace(dba(true)?, &access).is_err() {
                passport
                    .start_session(dba(false)?)
                    .map_err(|_| session_failed())?;
            }
        }
        (Session::Auto, None) => passport
            .start_session(dba(false)?)
            .map_err(|_| session_failed())?,
    }

    let dg1 = passport
        .read_ef_dg1()
        .map_err(|e| IdentityError::Nfc(format!("could not read the MRZ (DG1): {e}")))?;

    let dg2 = if options.read_portrait {
        match passport.read_ef_dg2() {
            Ok(dg2) => Some(dg2.to_bytes().to_vec()),
            // A missing or unreadable photograph is not a reason to fail an otherwise
            // good read; it is reported as a warning further down.
            Err(_) => None,
        }
    } else {
        None
    };

    let sod = passport
        .read_ef_sod()
        .map_err(|e| IdentityError::Nfc(format!("could not read EF.SOD: {e}")))?;

    // Active authentication needs a challenge the chip cannot have seen before —
    // a fixed one lets a recorded response be replayed, which defeats the point.
    let active_authentication = if options.active_authentication {
        let mut challenge = [0u8; 8];
        getrandom::fill(&mut challenge)
            .map_err(|e| IdentityError::Nfc(format!("no source of randomness: {e}")))?;

        match passport.verify_active_authentication(&challenge) {
            Ok(()) => Some(true),
            // A document without DG15 cannot do this at all, which is different from
            // failing it. Both come back as `Err` here, so treat it as "not
            // established" and let the warning say which.
            Err(_) => Some(false),
        }
    } else {
        None
    };

    verify_passport(
        &PassportFiles {
            sod: sod.to_bytes().to_vec(),
            dg1: dg1.to_bytes().to_vec(),
            dg2,
            active_authentication,
        },
        anchors,
    )
}

/// Verify files already read off a chip, and map them to an identity.
///
/// This is the whole security-relevant half of the passport path, and it touches no
/// hardware: passive authentication over the data groups, the CSCA chain, then the
/// MRZ and photograph.
pub fn verify_passport(
    files: &PassportFiles,
    anchors: &[Vec<u8>],
) -> Result<VerifiedIdentity, IdentityError> {
    let anchors = anchors
        .iter()
        .map(|der| {
            TrustAnchor::from_certificate(der)
                .map_err(|e| IdentityError::Anchor(format!("CSCA certificate: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Only hash what we actually have. Passive authentication vouches for the groups
    // it is given and nothing else, so claiming DG2 when it was not read would be a
    // lie of exactly the kind this crate exists to avoid.
    let mut groups = vec![DataGroup {
        number: 1,
        bytes: files.dg1.as_slice(),
    }];
    if let Some(dg2) = files.dg2.as_deref() {
        groups.push(DataGroup {
            number: 2,
            bytes: dg2,
        });
    }

    let passive = passive::verify(&files.sod, &groups, &anchors)
        .map_err(|e| IdentityError::NotAuthentic(e.to_string()))?;

    let (mut identity, document_code) = identity_from_files(files)?;
    identity.authenticity = authenticity(&passive, files, &identity);
    identity.source = Some(DocumentSource::Passport {
        document_code,
        issuing_state: identity.nationality.clone().unwrap_or_default(),
        verified_data_groups: passive.verified_groups.clone(),
        signed_data_groups: passive.sod_groups.clone(),
    });

    Ok(identity)
}

fn identity_from_files(files: &PassportFiles) -> Result<(VerifiedIdentity, String), IdentityError> {
    let dg1 = EfDG1::from_bytes(files.dg1.clone())
        .map_err(|e| IdentityError::Unreadable(format!("EF.DG1 (the MRZ): {e}")))?;
    let mrz = dg1.mrz();

    let portrait = files
        .dg2
        .as_ref()
        .and_then(|bytes| EfDG2::from_bytes(bytes.clone()).ok())
        .and_then(|dg2| dg2.image_data.clone());

    Ok((
        VerifiedIdentity {
            family_name: non_empty(&mrz.last_name),
            given_name: non_empty(&mrz.first_name),
            date_of_birth: Some(mrz.date_of_birth.format("%Y-%m-%d").to_string()),
            date_of_expiry: Some(mrz.date_of_expiry.format("%Y-%m-%d").to_string()),
            document_number: non_empty(mrz.document_number()),
            nationality: non_empty(&mrz.nationality),
            sex: non_empty(&mrz.gender),
            portrait,
            // A passport makes no age claims; it carries the date of birth and leaves the
            // arithmetic — and the disclosure — to whoever reads it.
            age_attestations: Vec::new(),
            source: None,
            authenticity: Authenticity::default(),
        },
        mrz.document_code.clone(),
    ))
}

fn authenticity(
    passive: &PassiveAuth,
    files: &PassportFiles,
    identity: &VerifiedIdentity,
) -> Authenticity {
    let mut warnings = Vec::new();

    if !passive.covers_all_groups() {
        let unread: Vec<u8> = passive
            .sod_groups
            .iter()
            .filter(|dg| !passive.verified_groups.contains(dg))
            .copied()
            .collect();
        if !unread.is_empty() {
            warnings.push(format!(
                "the chip signs data groups {unread:?} that were not read, so nothing \
                 they contain is authenticated"
            ));
        }
    }

    if files.dg2.is_some() && identity.portrait.is_none() {
        warnings.push("EF.DG2 was read but no image could be decoded from it".to_string());
    }

    if files.active_authentication == Some(false) {
        warnings.push(
            "active authentication did not succeed: the chip may be a clone, or may \
             simply not support it (no EF.DG15)"
                .to_string(),
        );
    }

    let not_expired = identity
        .date_of_expiry
        .as_deref()
        .and_then(|date| NaiveDate::parse_from_str(date, "%Y-%m-%d").ok())
        .is_some_and(|expiry| expiry >= chrono::Utc::now().date_naive());

    if !not_expired {
        warnings.push("the document is past its date of expiry".to_string());
    }

    Authenticity {
        // `passive::verify` returning at all means every supplied group matched
        // EF.SOD; the chain is a separate question.
        data_authentic: true,
        issuer_trusted: matches!(passive.chain, ChainStatus::Trusted { .. }),
        holder_bound: files.active_authentication,
        not_expired,
        warnings,
    }
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('<').trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}
