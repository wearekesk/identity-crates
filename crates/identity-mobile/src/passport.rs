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
use std::fmt;
use std::rc::Rc;

use chrono::NaiveDate;
use dmrtd::auth::active;
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
    /// Keep the elementary files the read produced, in [`PassportRead::files`].
    ///
    /// Off by default, and deliberately so: DG1 is the MRZ and DG2 is a facial image,
    /// and holding either in memory is a decision a caller should make rather than
    /// inherit. With this `false` the bytes live no longer than the call.
    ///
    /// Turn it on when something other than this device is the authority — a server
    /// that wants to check the signature chain and the hashes itself rather than
    /// believe a client's verdict. The files come back in the shape
    /// [`verify_passport`] takes, so the far end runs exactly the check this one did.
    pub retain_files: bool,
}

impl Default for PassportOptions {
    fn default() -> Self {
        Self {
            session: Session::Auto,
            read_portrait: true,
            active_authentication: true,
            retain_files: false,
        }
    }
}

/// The files read off a chip.
///
/// Hand these to [`verify_passport`] if your NFC stack already read them, or ask
/// [`read_passport`] for them with [`PassportOptions::retain_files`] when a server
/// rather than this device is the authority.
///
/// The bytes are owned outright — plain `Vec<u8>`, borrowed from nothing — so they live
/// exactly as long as the value does and may be moved, sent between threads or dropped
/// whenever the caller likes.
#[derive(Clone, Default)]
pub struct PassportFiles {
    /// EF.SOD — the issuer's signature over the data group hashes. Without it nothing
    /// can be verified.
    pub sod: Vec<u8>,
    /// EF.DG1 — the MRZ, and therefore the identity.
    pub dg1: Vec<u8>,
    /// EF.DG2 — the photograph.
    pub dg2: Option<Vec<u8>>,
    /// EF.DG15 — the chip's active-authentication public key.
    ///
    /// Supply it if you read it. It is hashed against EF.SOD like any other group,
    /// which is the only thing that makes an active-authentication result mean
    /// anything: the key AA is checked against has to be the key the issuer signed.
    pub dg15: Option<Vec<u8>>,
}

/// Lengths rather than contents.
///
/// A derived `Debug` would put the whole MRZ and the holder's photograph into any log
/// line that formatted one of these — which is the same data the reader declines to
/// retain by default, arriving somewhere nobody chose to put it. What is worth seeing
/// in a diagnostic is which files were read and how big they were.
impl fmt::Debug for PassportFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Size(usize);

        impl fmt::Debug for Size {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "<{} bytes>", self.0)
            }
        }

        let size = |bytes: &Option<Vec<u8>>| bytes.as_ref().map(|b| Size(b.len()));

        f.debug_struct("PassportFiles")
            .field("sod", &Size(self.sod.len()))
            .field("dg1", &Size(self.dg1.len()))
            .field("dg2", &size(&self.dg2))
            .field("dg15", &size(&self.dg15))
            .finish()
    }
}

/// What a read produced.
///
/// [`identity`](Self::identity) is the verdict, and is all most callers want. The files
/// are there only when [`PassportOptions::retain_files`] asked for them, for the
/// architecture where the phone reads the chip and a server does the authoritative
/// verification: that server wants the EF bytes so it can check the signature chain and
/// the hashes itself, rather than believe a client that graded its own document.
///
/// Reading twice to get them would mean a second full APDU exchange for bytes this
/// crate already had in hand.
#[derive(Debug, Clone)]
pub struct PassportRead {
    /// The verified identity, exactly as before.
    pub identity: VerifiedIdentity,
    /// The elementary files the read produced, or `None` when they were not asked for.
    ///
    /// Owned by you the moment this returns; see [`PassportFiles`].
    pub files: Option<PassportFiles>,
}

// Note what is *not* here: a field saying active authentication succeeded.
//
// It used to be one, and that was wrong. Holder binding is a property this crate
// establishes by challenging the chip, not a claim a caller can hand in — with it as
// an input, `is_present_and_trustworthy()` would pass for a set of files someone
// assembled, which is exactly the assurance it is supposed to deny. `verify_passport`
// therefore always reports `holder_bound: None`; only [`read_passport`], which does
// the exchange, can report anything else.

/// Read a passport from a live chip and verify it.
///
/// `anchors` are DER-encoded CSCA certificates from a masterlist. With none supplied
/// the read still happens and the data is still checked against EF.SOD, but
/// `issuer_trusted` comes back `false` — genuine-looking is not the same as genuine.
///
/// The files read are returned alongside the verdict when
/// [`PassportOptions::retain_files`] is set, and dropped at the end of this call when it
/// is not.
pub fn read_passport(
    channel: Box<dyn ApduChannel>,
    key: &MrzKey,
    anchors: &[Vec<u8>],
    options: &PassportOptions,
) -> Result<PassportRead, IdentityError> {
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

    // A chip that stopped responding has not told us it lacks EF.CardAccess. Separating
    // the two matters: one is worth retrying, and the other sends the caller down the
    // BAC path to argue with a chip that is no longer listening.
    if card_access.is_none() && transport_failed.get() {
        return Err(IdentityError::Nfc(
            "the chip stopped responding while probing for EF.CardAccess".to_string(),
        ));
    }

    // Short of that the read is a probe: older documents simply do not have the file,
    // and failing it is normal. Clearing the flag here stops a probe failure making
    // every later wrong-key rejection look like a lost tag.
    transport_failed.set(false);

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

    // Past this point every read is mandatory, so any failure is fatal either way —
    // but the message still tells the holder which kind of problem they have.
    // The session is up. Anything the flag recorded on the way here — a PACE attempt
    // that failed at transport before BAC succeeded — is history, and leaving it set
    // would make the next optional read look like a lost tag.
    transport_failed.set(false);

    let dg1 = passport.read_ef_dg1().map_err(|e| {
        // A chip that answered with something unparseable is a different problem from
        // one that stopped answering, and the holder is told to do different things.
        if transport_failed.get() {
            IdentityError::Nfc(format!(
                "the chip stopped responding while reading the MRZ: {e}"
            ))
        } else {
            IdentityError::Unreadable(format!("EF.DG1 (the MRZ) could not be read: {e}"))
        }
    })?;

    let dg2 = if options.read_portrait {
        transport_failed.set(false);
        match passport.read_ef_dg2() {
            Ok(dg2) => Some(dg2.to_bytes().to_vec()),
            // A document without a readable photograph is not a reason to fail an
            // otherwise good read — it is reported as a warning further down. A chip
            // that stopped answering is a different thing entirely, and must not be
            // quietly downgraded to "no photograph".
            Err(_) if transport_failed.get() => {
                return Err(IdentityError::Nfc(
                    "the chip stopped responding while reading the photograph".to_string(),
                ))
            }
            Err(_) => None,
        }
    } else {
        None
    };

    // DG15 carries the key active authentication is checked against, so it has to be
    // read and passed through passive authentication — an AA result against a DG15
    // nobody verified proves nothing, since an attacker who can rewrite the group can
    // supply their own key and answer their own challenge.
    // Kept parsed rather than as bytes: the key checked below and the bytes hashed
    // against EF.SOD then come from one object, so there is no second parse that could
    // disagree with the first.
    let dg15_file = if options.active_authentication {
        transport_failed.set(false);
        match passport.read_ef_dg15() {
            Ok(dg15) => Some(dg15),
            // A chip that stopped responding has not said the document lacks DG15.
            // Recording that as "active authentication not attempted" would file a
            // retryable fault under a permanent-looking one, and the holder would be
            // told their passport does not support a check it does support.
            Err(_) if transport_failed.get() => {
                return Err(IdentityError::Nfc(
                    "the chip stopped responding while reading DG15".to_string(),
                ))
            }
            // Genuinely absent: the document does not support active authentication.
            Err(_) => None,
        }
    } else {
        None
    };
    let dg15 = dg15_file.as_ref().map(|dg| dg.to_bytes().to_vec());

    transport_failed.set(false);
    let sod = passport.read_ef_sod().map_err(|e| {
        if transport_failed.get() {
            IdentityError::Nfc(format!(
                "the chip stopped responding while reading EF.SOD: {e}"
            ))
        } else {
            IdentityError::Unreadable(format!("EF.SOD could not be read: {e}"))
        }
    })?;

    // Active authentication needs a challenge the chip cannot have seen before —
    // a fixed one lets a recorded response be replayed, which defeats the point.
    //
    // The verification deliberately does not use `Passport::verify_active_authentication`,
    // which re-reads DG15 from the chip. That would leave two reads of the same group:
    // the one hashed against EF.SOD, and the one the challenge is checked against. A
    // chip that answers the first honestly and the second with a key of its choosing
    // would pass both, which is the whole attack this check exists to stop. The file
    // captured above is used for both purposes.
    let active_authentication = match (options.active_authentication, dg15_file.as_ref()) {
        (true, Some(dg15_file)) => {
            transport_failed.set(false);

            let mut challenge = [0u8; 8];
            // Not an NFC error, though it sits on the NFC path: the tag is fine and
            // repositioning the phone will not help. `Nfc` is the retry-and-tell-the-
            // holder-to-hold-still kind, and this challenge is the security boundary of
            // the whole check — a reader with no randomness should stop, not loop.
            getrandom::fill(&mut challenge).map_err(|e| {
                IdentityError::Unreadable(format!(
                    "no source of randomness for the active authentication challenge: {e}"
                ))
            })?;

            let response = match passport.active_authenticate(&challenge) {
                Ok(response) => Some(response),
                // A lost tag here would otherwise be recorded as "this chip may be a
                // clone", which is a serious thing to say about a document that was
                // merely moved.
                Err(_) if transport_failed.get() => {
                    return Err(IdentityError::Nfc(
                        "the chip stopped responding during active authentication".to_string(),
                    ))
                }
                // The chip answered, and refused. That is a failure.
                Err(_) => None,
            };

            match response {
                Some(response) => {
                    Some(active::verify(dg15_file.aa_public_key(), &challenge, &response).is_ok())
                }
                None => Some(false),
            }
        }
        // No DG15 means the document does not support active authentication at all,
        // which is not the same as failing it.
        (true, None) => None,
        (false, _) => None,
    };

    let files = PassportFiles {
        sod: sod.to_bytes().to_vec(),
        dg1: dg1.to_bytes().to_vec(),
        dg2,
        dg15,
    };

    // Only now, with the data groups verified against EF.SOD, is an active
    // authentication result worth anything.
    let identity = verify_files(&files, anchors, active_authentication)?;

    Ok(PassportRead {
        identity,
        // `files` goes out of scope here when it was not asked for, which is the whole
        // of the "not retained by default" promise: there is no cache and no second
        // owner, so the MRZ and the photograph outlive this call only when a caller
        // said they should.
        files: options.retain_files.then_some(files),
    })
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
    // `None`: this path performs no challenge, so it cannot establish holder binding
    // and must not appear to.
    verify_files(files, anchors, None)
}

fn verify_files(
    files: &PassportFiles,
    anchors: &[Vec<u8>],
    active_authentication: Option<bool>,
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
    if let Some(dg15) = files.dg15.as_deref() {
        groups.push(DataGroup {
            number: 15,
            bytes: dg15,
        });
    }

    let passive = passive::verify(&files.sod, &groups, &anchors)
        .map_err(|e| IdentityError::NotAuthentic(e.to_string()))?;

    // An active-authentication success is only meaningful if the key it was checked
    // against came through passive authentication. If DG15 was not read, or EF.SOD does
    // not cover it, the answer is "not established" rather than "yes".
    let holder_bound = holder_binding(active_authentication, passive.verified_groups.contains(&15));

    let (mut identity, document_code, issuing_state) = identity_from_files(files)?;
    identity.authenticity = authenticity(&passive, files, &identity, holder_bound);
    identity.source = Some(DocumentSource::Passport {
        document_code,
        // The MRZ's issuing state, not the holder's nationality. They usually match
        // and are not the same field — a travel document issued to a non-national is
        // exactly the case where assuming they are would be wrong.
        issuing_state,
        verified_data_groups: passive.verified_groups.clone(),
        signed_data_groups: passive.sod_groups.clone(),
    });

    Ok(identity)
}

fn identity_from_files(
    files: &PassportFiles,
) -> Result<(VerifiedIdentity, String, String), IdentityError> {
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
        mrz.country.clone(),
    ))
}

fn authenticity(
    passive: &PassiveAuth,
    files: &PassportFiles,
    identity: &VerifiedIdentity,
    holder_bound: Option<bool>,
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

    if holder_bound == Some(false) {
        // Only a chip that was asked and answered wrongly reaches here: a document
        // without EF.DG15 is `None`, and a lost tag is an error. Offering "it may simply
        // not support it" as an alternative would talk down the one result that actually
        // suggests a clone.
        warnings.push(
            "active authentication failed: the chip did not prove possession of the \
             private key for the DG15 public key the issuer signed"
                .to_string(),
        );
    }

    if files.dg15.is_some() && !passive.verified_groups.contains(&15) {
        warnings.push(
            "EF.DG15 was read but EF.SOD does not cover it, so the active \
             authentication key is not the one the issuer signed"
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
        holder_bound,
        not_expired,
        warnings,
    }
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('<').trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Whether an active-authentication result may be reported as holder binding.
///
/// A success only counts if EF.SOD covered DG15, because DG15 holds the key the
/// challenge was checked against. Without that, an attacker who can rewrite the group
/// supplies their own key, answers their own challenge, and a cloned chip reports as
/// the original.
fn holder_binding(active_authentication: Option<bool>, dg15_authenticated: bool) -> Option<bool> {
    match active_authentication {
        Some(true) if !dg15_authenticated => None,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::{holder_binding, PassportFiles, PassportOptions};

    /// Retaining has to be something a caller asks for, not something they discover.
    #[test]
    fn files_are_not_retained_by_default() {
        assert!(!PassportOptions::default().retain_files);
    }

    /// A `{:?}` on these must not be a way to get the MRZ and a facial image into a log
    /// aggregator.
    #[test]
    fn debug_reports_sizes_rather_than_contents() {
        let files = PassportFiles {
            sod: vec![1, 2, 3],
            dg1: b"P<GBRSHARMA<<PRIYA".to_vec(),
            dg2: Some(vec![0xFF, 0xD8, 0xFF]),
            dg15: None,
        };

        let rendered = format!("{files:?}");

        assert!(rendered.contains("<18 bytes>"), "{rendered}");
        assert!(rendered.contains("dg15: None"), "{rendered}");
        assert!(!rendered.contains("SHARMA"), "{rendered}");
        assert!(!rendered.contains("255"), "{rendered}");
    }

    #[test]
    fn a_success_needs_an_authenticated_dg15() {
        assert_eq!(holder_binding(Some(true), true), Some(true));
        // The dangerous case: AA said yes, but against a key nobody verified.
        assert_eq!(holder_binding(Some(true), false), None);
    }

    #[test]
    fn a_failure_stands_regardless() {
        // Still worth telling the caller about; it is not a claim of authenticity.
        assert_eq!(holder_binding(Some(false), false), Some(false));
        assert_eq!(holder_binding(Some(false), true), Some(false));
    }

    #[test]
    fn not_attempted_stays_not_attempted() {
        assert_eq!(holder_binding(None, true), None);
        assert_eq!(holder_binding(None, false), None);
    }
}
