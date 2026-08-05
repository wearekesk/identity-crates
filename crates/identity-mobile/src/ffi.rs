//! The C ABI the Flutter plugin calls through.
//!
//! Everything crosses as bytes in and one JSON string out. That is deliberate:
//! a struct layout shared between Rust and Dart is a standing invitation for the two
//! to drift, and the cost of serialising a result that a human is about to look at is
//! irrelevant next to an NFC read.
//!
//! Ownership rule, in one line: **every non-null `char *` this module returns must be
//! handed back to [`identity_mobile_string_free`]**. The Dart side does that in a
//! `finally`.
//!
//! This is the only module that uses `unsafe`. The verification code it calls is
//! entirely safe Rust; what is unsafe here is exclusively the act of trusting the
//! pointers the caller passed.

#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, CStr, CString};

use crate::bridge::{self, Exchange};
use crate::identity::VerifiedIdentity;
use crate::passport::{ApduChannel, MrzKey, PassportFiles, PassportOptions, PassportRead, Session};
use crate::IdentityError;

/// The shape of this ABI, bumped whenever an exported signature changes.
///
/// This library does not keep old entry points alive. At `0.0.0`, with one in-tree
/// consumer, versioned duplicates would be weight carried for nobody — the Dart package
/// and the native artifact are built from the same tree and belong together.
///
/// What that costs is a failure mode worth closing. Dart resolves these symbols by name
/// at runtime, and the release artifacts are built by one job and placed into the plugin
/// by hand, so pairing a new Dart package with a stale `.so` is a state a person can
/// reach. The names would still resolve, and the call would go through with the
/// arguments landing in the wrong slots — a function pointer read out of a `bool`, which
/// is undefined behaviour on a device rather than an error anyone can read.
///
/// So the host checks this first and refuses a library it was not built against. Bump it
/// in the same commit as any signature change, and change
/// `IdentityBindings.expectedAbiVersion` in `bindings.dart` to match — a test reads that
/// declaration out of the Dart source and fails if the two have drifted, so this is a
/// checked pairing rather than a remembered one.
///
/// - **1** — the original surface.
/// - **2** — `retain_data_groups` added to both passport read entry points.
pub const IDENTITY_MOBILE_ABI_VERSION: u32 = 2;

/// Which ABI this library exports; see [`IDENTITY_MOBILE_ABI_VERSION`].
///
/// Call it before anything else. A library too old to have this symbol at all fails the
/// lookup, which is the same answer arriving a different way.
#[no_mangle]
pub extern "C" fn identity_mobile_abi_version() -> u32 {
    IDENTITY_MOBILE_ABI_VERSION
}

/// A borrowed byte slice, as C sees it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Bytes {
    pub ptr: *const u8,
    pub len: usize,
}

impl Bytes {
    /// # Safety
    ///
    /// `ptr` must be valid for `len` bytes, or null with `len == 0`.
    unsafe fn as_slice<'a>(&self) -> &'a [u8] {
        if self.ptr.is_null() || self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }
}

/// How the host sends one APDU to the chip.
///
/// Returns the number of bytes written to `response`, or a negative value if the
/// exchange failed. A response longer than `response_capacity` is an error rather
/// than a truncation — silently losing the tail of an APDU would corrupt the session
/// in a way that is very hard to diagnose.
pub type TransceiveFn = extern "C" fn(
    context: *mut std::ffi::c_void,
    apdu: *const u8,
    apdu_len: usize,
    response: *mut u8,
    response_capacity: usize,
) -> c_int;

/// Verify an mDL presentation. Returns owned JSON; free it with
/// [`identity_mobile_string_free`].
///
/// Pass the session transcript when you have one — a null `session_transcript` means
/// issuer authentication only, `holderBound` comes back null, and a captured response
/// can be replayed for as long as the credential remains valid — expiry still applies
/// and is all that bounds it. `e_reader_key` is the reader's 32-byte ephemeral private key,
/// required when the holder authenticated with `DeviceMac`.
///
/// # Safety
///
/// Every slice must be valid for the duration of the call, and `e_reader_key`, if not
/// null, must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn identity_mobile_verify_mdl(
    device_response: Bytes,
    anchors: *const Bytes,
    anchor_count: usize,
    session_transcript: Bytes,
    e_reader_key: Bytes,
) -> *mut c_char {
    let response = unsafe { device_response.as_slice() };
    let anchors = unsafe { collect(anchors, anchor_count) };
    let transcript = unsafe { session_transcript.as_slice() };

    if transcript.is_empty() {
        return json(crate::mdl::verify_mdl(response, &anchors, None));
    }

    let key = unsafe { e_reader_key.as_slice() };
    let key = match key.len() {
        0 => None,
        32 => Some(<[u8; 32]>::try_from(key).expect("checked above")),
        other => {
            return json::<VerifiedIdentity>(Err(IdentityError::Unreadable(format!(
                "the reader's ephemeral key must be 32 bytes, got {other}"
            ))))
        }
    };

    let session = match crate::mdl::Session::from_cbor(transcript, key) {
        Ok(session) => session,
        Err(e) => return json::<VerifiedIdentity>(Err(e)),
    };

    json(crate::mdl::verify_mdl(response, &anchors, Some(&session)))
}

/// The OpenID4VP values the session transcript is built from.
///
/// Every string is optional — pass null for what you do not have. Which candidates get
/// built follows from what is present, so a caller holding only `origin` + `nonce` gets
/// the DC API profile and a caller holding a wallet nonce as well gets the older ISO
/// profile too.
#[repr(C)]
#[derive(Debug)]
pub struct OpenId4VpParams {
    /// Including the Client Identifier Prefix where one applies.
    pub client_id: *const c_char,
    /// Whichever of `response_uri` / `redirect_uri` the response mode uses.
    pub response_uri: *const c_char,
    /// The `nonce` request parameter — yours, not the wallet's.
    pub nonce: *const c_char,
    /// The wallet-supplied `mdoc_generated_nonce`, for the ISO/IEC 18013-7 profile.
    pub mdoc_generated_nonce: *const c_char,
    /// The request origin for the Digital Credentials API profile, with no `origin:`
    /// prefix.
    pub origin: *const c_char,
    /// RFC 7638 SHA-256 thumbprint of the response-encryption key. Empty means the
    /// response was not encrypted, which the spec encodes as a CBOR `null` — not as an
    /// empty byte string, which would hash differently.
    pub jwk_thumbprint: Bytes,
}

/// Verify an mDL presented over OpenID4VP, without making the caller build a
/// `SessionTranscript`.
///
/// Every candidate the parameters support is tried, because two profiles are live and
/// they encode the same session inputs differently: OpenID4VP 1.0 (Appendix B.2.6.1),
/// its Digital Credentials API variant (B.2.6.2), and the older ISO/IEC 18013-7 Annex B
/// shape with a wallet nonce. This is a question about encoding rather than trust — the
/// holder still has to have signed one of them with the device key the issuer bound
/// into the MSO — and the result reports which one matched as `sessionProfile`.
///
/// # Safety
///
/// Every non-null string must be a valid NUL-terminated UTF-8 C string, and every slice
/// valid for the duration of the call. `e_reader_key`, if not null, must point to 32
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn identity_mobile_verify_mdl_openid4vp(
    device_response: Bytes,
    anchors: *const Bytes,
    anchor_count: usize,
    params: OpenId4VpParams,
    e_reader_key: Bytes,
) -> *mut c_char {
    let response = unsafe { device_response.as_slice() };
    let anchors = unsafe { collect(anchors, anchor_count) };

    let key = unsafe { e_reader_key.as_slice() };
    let key = match key.len() {
        0 => None,
        32 => Some(<[u8; 32]>::try_from(key).expect("checked above")),
        other => {
            return json::<VerifiedIdentity>(Err(IdentityError::Unreadable(format!(
                "the reader's ephemeral key must be 32 bytes, got {other}"
            ))))
        }
    };

    let (client_id, response_uri, nonce, mdoc_nonce, origin) = unsafe {
        (
            text(params.client_id),
            text(params.response_uri),
            text(params.nonce),
            text(params.mdoc_generated_nonce),
            text(params.origin),
        )
    };

    // Empty means absent, which the spec encodes as a CBOR `null`. Any other length is
    // rejected by the builders themselves, so a direct Rust caller gets the same answer
    // as this one.
    let thumbprint = unsafe { params.jwk_thumbprint.as_slice() };
    let thumbprint = (!thumbprint.is_empty()).then_some(thumbprint);

    // An empty nonce is a caller mistake that does not look like one. It builds a
    // perfectly valid transcript binding the session to nothing, and every presentation
    // ever signed against an empty nonce would verify against it — while still reporting
    // holder_bound. A nonce that is not there at all is the same mistake, said quietly.
    let nonce = nonce.as_deref().filter(|nonce| !nonce.is_empty());
    let Some(nonce) = nonce else {
        return json::<VerifiedIdentity>(Err(IdentityError::Unreadable(
            "a non-empty nonce is required to build an OpenID4VP session transcript".to_string(),
        )));
    };

    let mut session = crate::mdl::Session::candidates(key);

    if let Some(origin) = origin.as_deref() {
        session = match session.openid4vp_dcapi(origin, nonce, thumbprint) {
            Ok(session) => session,
            Err(e) => return json::<VerifiedIdentity>(Err(e)),
        };
    }

    if let (Some(client_id), Some(response_uri)) = (client_id.as_deref(), response_uri.as_deref()) {
        session = match session.openid4vp_1_0(client_id, nonce, thumbprint, response_uri) {
            Ok(session) => session,
            Err(e) => return json::<VerifiedIdentity>(Err(e)),
        };

        // Only when the wallet supplied its nonce: without one there is no ISO/IEC
        // 18013-7 transcript to build, and guessing a value would produce a device
        // authentication failure with no useful explanation.
        if let Some(mdoc_nonce) = mdoc_nonce.as_deref() {
            session =
                match session.openid4vp_iso_18013_7(client_id, response_uri, nonce, mdoc_nonce) {
                    Ok(session) => session,
                    Err(e) => return json::<VerifiedIdentity>(Err(e)),
                };
        }
    }

    if session.candidates.is_empty() {
        return json::<VerifiedIdentity>(Err(IdentityError::Unreadable(
            "no OpenID4VP profile could be built: supply either an origin, or a client_id \
             and response_uri"
                .to_string(),
        )));
    }

    json(crate::mdl::verify_mdl(response, &anchors, Some(&session)))
}

/// Verify passport files that were read elsewhere.
///
/// Pass a null `dg2` or `dg15` for groups that were not read; the result reports the
/// gap rather than pretending they were covered.
///
/// This path never reports holder binding: establishing it means challenging the chip,
/// which only [`identity_mobile_read_passport_async`] does.
///
/// # Safety
///
/// Every slice must be valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn identity_mobile_verify_passport(
    sod: Bytes,
    dg1: Bytes,
    dg2: Bytes,
    dg15: Bytes,
    anchors: *const Bytes,
    anchor_count: usize,
) -> *mut c_char {
    let dg2 = unsafe { dg2.as_slice() };
    let dg15 = unsafe { dg15.as_slice() };

    let files = PassportFiles {
        sod: unsafe { sod.as_slice() }.to_vec(),
        dg1: unsafe { dg1.as_slice() }.to_vec(),
        dg2: (!dg2.is_empty()).then(|| dg2.to_vec()),
        dg15: (!dg15.is_empty()).then(|| dg15.to_vec()),
    };

    let anchors = unsafe { collect(anchors, anchor_count) };

    json(crate::passport::verify_passport(&files, &anchors))
}

/// Read a passport from a live chip, exchanging APDUs through `transceive`.
///
/// `context` is passed back to `transceive` untouched — use it to carry whatever
/// handle the platform needs.
///
/// Set `retain_data_groups` to have the elementary files come back in the result as
/// `dataGroups`; see [`identity_mobile_read_passport_async`] for what that costs and
/// who owns them.
///
/// # Safety
///
/// The three strings must be valid NUL-terminated UTF-8, the anchors valid for the
/// call, and `transceive` must remain callable until this function returns.
#[no_mangle]
pub unsafe extern "C" fn identity_mobile_read_passport(
    document_number: *const c_char,
    date_of_birth: *const c_char,
    date_of_expiry: *const c_char,
    anchors: *const Bytes,
    anchor_count: usize,
    read_portrait: bool,
    active_authentication: bool,
    retain_data_groups: bool,
    transceive: TransceiveFn,
    context: *mut std::ffi::c_void,
) -> *mut c_char {
    let strings = (
        unsafe { text(document_number) },
        unsafe { text(date_of_birth) },
        unsafe { text(date_of_expiry) },
    );

    let (Some(number), Some(birth), Some(expiry)) = strings else {
        return json::<VerifiedIdentity>(Err(IdentityError::Unreadable(
            "the access key fields must be valid UTF-8".to_string(),
        )));
    };

    let key = match MrzKey::new(number, &birth, &expiry) {
        Ok(key) => key,
        Err(e) => return json::<VerifiedIdentity>(Err(e)),
    };

    let anchors = unsafe { collect(anchors, anchor_count) };

    let channel = HostChannel {
        transceive,
        context,
    };

    let options = PassportOptions {
        session: Session::Auto,
        read_portrait,
        active_authentication,
        retain_files: retain_data_groups,
    };

    json(crate::passport::read_passport(
        Box::new(channel),
        &key,
        &anchors,
        &options,
    ))
}

/// How the host is told an APDU is waiting.
///
/// Called on the worker thread that is running the read. The host must not block here
/// — post the exchange to wherever its NFC lives and return. The answer comes back
/// through [`identity_mobile_supply_apdu`].
///
/// **The host takes ownership of `apdu`** and must release it with
/// [`identity_mobile_free_apdu`] once it has copied the bytes. The buffer deliberately
/// does not belong to the waiting call: if an exchange times out, that call unwinds
/// while a busy host may still be on its way to reading the pointer, and a borrowed
/// buffer would be gone by then.
pub type PostApduFn =
    extern "C" fn(context: *mut std::ffi::c_void, exchange_id: u64, apdu: *mut u8, apdu_len: usize);

/// Read a passport, exchanging APDUs asynchronously.
///
/// This is the entry point for a host whose NFC returns futures — which is every
/// Flutter NFC package. **Call it on a worker thread** (`Isolate.run` in Dart): it
/// blocks for the whole read, and the thread servicing `post` must stay free.
///
/// # Retaining the data groups
///
/// With `retain_data_groups` set, the result carries a `dataGroups` object holding
/// EF.SOD, EF.DG1 and — when they were read — EF.DG2 and EF.DG15, hex-encoded like the
/// portrait. That is for the architecture where this device reads the chip and a server
/// does the authoritative verification: the server wants the bytes so it can check the
/// signature chain and the hashes itself rather than believe a client's verdict. The
/// same bytes go straight back into [`identity_mobile_verify_passport`].
///
/// It is off by default because DG1 is the MRZ and DG2 is a facial image, and hex
/// doubles them on the way across — a DG2 read turns a small result into a few hundred
/// kilobytes of JSON. Ask for it when you have somewhere to send it.
///
/// Ownership does not change: the bytes are part of the one string this function
/// returns, so they live until that string goes to [`identity_mobile_string_free`] and
/// not one moment longer. Copy what you intend to keep.
///
/// # Safety
///
/// As [`identity_mobile_read_passport`], and `post` must remain callable until this
/// function returns.
#[no_mangle]
pub unsafe extern "C" fn identity_mobile_read_passport_async(
    document_number: *const c_char,
    date_of_birth: *const c_char,
    date_of_expiry: *const c_char,
    anchors: *const Bytes,
    anchor_count: usize,
    read_portrait: bool,
    active_authentication: bool,
    retain_data_groups: bool,
    post: PostApduFn,
    context: *mut std::ffi::c_void,
) -> *mut c_char {
    let strings = (
        unsafe { text(document_number) },
        unsafe { text(date_of_birth) },
        unsafe { text(date_of_expiry) },
    );

    let (Some(number), Some(birth), Some(expiry)) = strings else {
        return json::<VerifiedIdentity>(Err(IdentityError::Unreadable(
            "the access key fields must be valid UTF-8".to_string(),
        )));
    };

    let key = match MrzKey::new(number, &birth, &expiry) {
        Ok(key) => key,
        Err(e) => return json::<VerifiedIdentity>(Err(e)),
    };

    let anchors = unsafe { collect(anchors, anchor_count) };

    let options = PassportOptions {
        session: Session::Auto,
        read_portrait,
        active_authentication,
        retain_files: retain_data_groups,
    };

    json(crate::passport::read_passport(
        Box::new(AsyncChannel { post, context }),
        &key,
        &anchors,
        &options,
    ))
}

/// Answer an exchange that [`PostApduFn`] announced.
///
/// Pass `ok = false` to report that the exchange failed; the read then unwinds with an
/// NFC error rather than waiting out the timeout.
///
/// Returns false if the exchange is unknown — already answered, or timed out.
///
/// # Safety
///
/// `response` must be valid for `response_len` bytes when `ok` is true.
#[no_mangle]
pub unsafe extern "C" fn identity_mobile_supply_apdu(
    exchange_id: u64,
    response: *const u8,
    response_len: usize,
    ok: bool,
) -> bool {
    let answer = if ok {
        Some(
            unsafe {
                Bytes {
                    ptr: response,
                    len: response_len,
                }
                .as_slice()
            }
            .to_vec(),
        )
    } else {
        None
    };

    bridge::supply(exchange_id, answer)
}

/// An [`ApduChannel`] that posts each exchange and parks until the host answers.
struct AsyncChannel {
    post: PostApduFn,
    context: *mut std::ffi::c_void,
}

impl ApduChannel for AsyncChannel {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        let exchange = Exchange::open();

        // Hand the bytes over rather than lending them. `apdu` is borrowed for the
        // duration of this call, and this call ends when the exchange is answered *or
        // times out* — so a host that was slow to reach the callback could otherwise
        // read a buffer that no longer exists.
        // A boxed slice, not a `Vec`: `shrink_to_fit` is permitted to leave spare
        // capacity, and reconstructing with `Vec::from_raw_parts(ptr, len, len)` when
        // the real capacity differs is undefined behaviour. `into_boxed_slice` gives an
        // allocation whose size is exactly its length, which the free path can rebuild
        // without knowing anything else.
        let owned: Box<[u8]> = apdu.to_vec().into_boxed_slice();
        let len = owned.len();
        let ptr = Box::into_raw(owned).cast::<u8>();

        (self.post)(self.context, exchange.id(), ptr, len);
        exchange.wait()
    }
}

/// Release an APDU buffer handed to [`PostApduFn`].
///
/// Call this once per posted exchange, after copying the bytes. Skipping it leaks the
/// buffer; calling it twice, or with a pointer from anywhere else, is undefined.
///
/// # Safety
///
/// `apdu` must be the pointer from a `PostApduFn` call, with the same `len`, and must
/// not have been freed already.
#[no_mangle]
pub unsafe extern "C" fn identity_mobile_free_apdu(apdu: *mut u8, len: usize) {
    if !apdu.is_null() && len > 0 {
        // Rebuilt as the boxed slice it was allocated as; see `AsyncChannel::transceive`.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(apdu, len)) });
    }
}

/// Release a string returned by this module.
///
/// # Safety
///
/// `value` must have come from this module and must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn identity_mobile_string_free(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}

/// An [`ApduChannel`] backed by a host function pointer.
struct HostChannel {
    transceive: TransceiveFn,
    context: *mut std::ffi::c_void,
}

impl ApduChannel for HostChannel {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        // Extended-length APDUs cap out around 64 KiB, and DG2 is read in chunks well
        // under that. Allocating the ceiling once beats growing per exchange.
        let mut response = vec![0u8; 65_536];

        let written = (self.transceive)(
            self.context,
            apdu.as_ptr(),
            apdu.len(),
            response.as_mut_ptr(),
            response.len(),
        );

        // Order matters: a negative `c_int` cast to `usize` wraps to something huge,
        // so testing the length before the sign would report every transport failure
        // as an oversized response.
        if written < 0 {
            return Err(format!(
                "the host could not exchange an APDU (code {written})"
            ));
        }

        let len = written as usize;
        if len > response.len() {
            // `truncate` past the end is a no-op, so an over-long length would leave
            // 64 KiB of zeroes standing in for the chip's answer and corrupt the
            // session in a way that is very hard to trace back to here.
            return Err(format!(
                "the host reported {len} bytes for a {} byte buffer",
                response.len()
            ));
        }

        response.truncate(len);
        Ok(response)
    }
}

/// # Safety
///
/// `anchors` must point to `count` valid [`Bytes`].
unsafe fn collect(anchors: *const Bytes, count: usize) -> Vec<Vec<u8>> {
    if anchors.is_null() || count == 0 {
        return Vec::new();
    }

    unsafe { std::slice::from_raw_parts(anchors, count) }
        .iter()
        .map(|anchor| unsafe { anchor.as_slice() }.to_vec())
        .collect()
}

/// # Safety
///
/// `value` must be null or a valid NUL-terminated string.
unsafe fn text(value: *const c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// Render a result as the JSON the Dart side parses.
///
/// Errors come back as `{"error": {...}}` rather than a null pointer, so the host
/// always has something to show — and, critically, so a refusal to verify never looks
/// like a crash.
fn json<T: Into<Json>>(result: Result<T, IdentityError>) -> *mut c_char {
    let rendered = match result {
        Ok(value) => value.into().render(),
        Err(error) => Json::error(&error).render(),
    };

    CString::new(rendered)
        .unwrap_or_else(|_| CString::new(r#"{"error":{"kind":"internal"}}"#).expect("static"))
        .into_raw()
}

/// A very small JSON writer.
///
/// Deliberately not `serde_json`: the shape here is fixed and tiny, and this keeps the
/// dependency list of a crate that ships to phones down to what it actually needs.
pub(crate) struct Json(String);

impl Json {
    fn render(self) -> String {
        self.0
    }

    fn error(error: &IdentityError) -> Self {
        let kind = match error {
            IdentityError::Nfc(_) => "nfc",
            IdentityError::Access => "access",
            IdentityError::Unreadable(_) => "unreadable",
            IdentityError::NotAuthentic(_) => "notAuthentic",
            IdentityError::SessionKeyRequired => "sessionKeyRequired",
            IdentityError::Anchor(_) => "anchor",
            IdentityError::UnsupportedAlgorithm(_) => "unsupportedAlgorithm",
        };

        Self(format!(
            r#"{{"error":{{"kind":"{kind}","message":{}}}}}"#,
            quote(&error.to_string())
        ))
    }
}

impl From<VerifiedIdentity> for Json {
    fn from(identity: VerifiedIdentity) -> Self {
        Self(format!(r#"{{"identity":{}}}"#, identity_object(&identity)))
    }
}

impl From<PassportRead> for Json {
    fn from(read: PassportRead) -> Self {
        Self(format!(
            r#"{{"identity":{},"dataGroups":{}}}"#,
            identity_object(&read.identity),
            match &read.files {
                Some(files) => data_groups(files),
                // Distinct from an empty object: nothing was retained, as opposed to
                // nothing being there to retain.
                None => "null".to_string(),
            }
        ))
    }
}

/// The elementary files, hex-encoded as the portrait already is.
///
/// `sod` and `dg1` are always present — a read cannot succeed without them — while the
/// optional groups are `null` when they were not read, which is the same distinction
/// `verifiedDataGroups` draws and the shape `identity_mobile_verify_passport` takes back.
fn data_groups(files: &PassportFiles) -> String {
    let optional = |bytes: &Option<Vec<u8>>| match bytes {
        Some(bytes) => quote(&hex(bytes)),
        None => "null".to_string(),
    };

    format!(
        r#"{{"sod":{},"dg1":{},"dg2":{},"dg15":{}}}"#,
        quote(&hex(&files.sod)),
        quote(&hex(&files.dg1)),
        optional(&files.dg2),
        optional(&files.dg15),
    )
}

/// The identity itself, without the envelope — shared by the two results that carry one.
fn identity_object(identity: &VerifiedIdentity) -> String {
    let authenticity = &identity.authenticity;

    let ages = identity
        .age_attestations
        .iter()
        .map(|(years, answer)| format!(r#"{{"years":{years},"answer":{answer}}}"#))
        .collect::<Vec<_>>()
        .join(",");

    let warnings = authenticity
        .warnings
        .iter()
        .map(|w| quote(w))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        concat!(
            r#"{{"familyName":{},"givenName":{},"dateOfBirth":{},"dateOfExpiry":{},"#,
            r#""documentNumber":{},"nationality":{},"sex":{},"portrait":{},"#,
            r#""ageAttestations":[{}],"source":{},"#,
            r#""authenticity":{{"dataAuthentic":{},"issuerTrusted":{},"#,
            r#""holderBound":{},"notExpired":{},"warnings":[{}]}}}}"#,
        ),
        optional(&identity.family_name),
        optional(&identity.given_name),
        optional(&identity.date_of_birth),
        optional(&identity.date_of_expiry),
        optional(&identity.document_number),
        optional(&identity.nationality),
        optional(&identity.sex),
        // Base64 would need a dependency; hex costs a little size and no thinking.
        match &identity.portrait {
            Some(bytes) => quote(&hex(bytes)),
            None => "null".to_string(),
        },
        ages,
        source(identity),
        authenticity.data_authentic,
        authenticity.issuer_trusted,
        match authenticity.holder_bound {
            Some(value) => value.to_string(),
            None => "null".to_string(),
        },
        authenticity.not_expired,
        warnings,
    )
}

fn source(identity: &VerifiedIdentity) -> String {
    use crate::identity::DocumentSource::*;

    match &identity.source {
        Some(Passport {
            document_code,
            issuing_state,
            verified_data_groups,
            signed_data_groups,
        }) => format!(
            r#"{{"kind":"passport","documentCode":{},"issuingState":{},"verifiedDataGroups":{:?},"signedDataGroups":{:?}}}"#,
            quote(document_code),
            quote(issuing_state),
            verified_data_groups,
            signed_data_groups
        ),
        Some(MobileDrivingLicence {
            doc_type,
            issuing_authority,
            session_profile,
        }) => format!(
            r#"{{"kind":"mdl","docType":{},"issuingAuthority":{},"sessionProfile":{}}}"#,
            quote(doc_type),
            optional(issuing_authority),
            optional(session_profile)
        ),
        None => "null".to_string(),
    }
}

fn optional(value: &Option<String>) -> String {
    match value {
        Some(value) => quote(value),
        None => "null".to_string(),
    }
}

fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{Json, PassportFiles, PassportRead, VerifiedIdentity, IDENTITY_MOBILE_ABI_VERSION};

    /// The ABI version is one number kept in two files, and the two are useless apart:
    /// old entry points are not kept alive, so a bump here that `bindings.dart` does not
    /// follow produces a host that refuses to load — or, if it were missed in the other
    /// direction, one that calls a signature which has moved.
    ///
    /// So it is read out of the Dart source rather than restated here. A literal in this
    /// test would pass just as happily when only Rust and the literal were bumped, which
    /// is the mistake most likely to actually happen — the two files are edited hours
    /// apart, by whoever is deep in one side of the boundary.
    ///
    /// `include_str!` resolves at compile time, so moving or renaming `bindings.dart`
    /// fails the build here rather than quietly leaving this unchecked.
    #[test]
    fn the_dart_binding_expects_the_abi_this_library_exports() {
        const BINDINGS: &str = include_str!("../flutter/identity_mobile/lib/src/bindings.dart");
        const DECLARATION: &str = "static const int expectedAbiVersion = ";

        let declared = BINDINGS
            .split_once(DECLARATION)
            .and_then(|(_, rest)| rest.split_once(';'))
            .map(|(value, _)| value.trim())
            .unwrap_or_else(|| {
                panic!("`{DECLARATION}<n>;` is not in bindings.dart — was it renamed?")
            });

        assert_eq!(
            declared.parse::<u32>().ok(),
            Some(IDENTITY_MOBILE_ABI_VERSION),
            "bindings.dart is built against ABI {declared}, this library exports \
             {IDENTITY_MOBILE_ABI_VERSION} — they are bumped together or not at all"
        );
    }

    fn read(files: Option<PassportFiles>) -> String {
        Json::from(PassportRead {
            identity: VerifiedIdentity::default(),
            files,
        })
        .render()
    }

    fn files() -> PassportFiles {
        PassportFiles {
            sod: vec![0x30, 0x82],
            dg1: vec![0x61, 0x5B],
            dg2: Some(vec![0xFF, 0xD8]),
            dg15: None,
        }
    }

    /// Both halves of the envelope, in the shape `models.dart` parses. The identity has
    /// to stay exactly where it was — every existing caller reads `identity` and knows
    /// nothing about data groups.
    #[test]
    fn a_retained_read_carries_the_files_beside_the_identity() {
        let rendered = read(Some(files()));

        assert!(
            rendered.starts_with(r#"{"identity":{"familyName":null"#),
            "{rendered}"
        );
        assert!(
            rendered
                .contains(r#""dataGroups":{"sod":"3082","dg1":"615b","dg2":"ffd8","dg15":null}"#),
            "{rendered}"
        );
    }

    /// The default, and the one that matters for privacy: no bytes, and a `null` that
    /// says so rather than an empty object that reads as "read but empty".
    #[test]
    fn a_read_without_retention_carries_no_bytes() {
        let rendered = read(None);

        assert!(rendered.contains(r#""dataGroups":null"#), "{rendered}");
        assert!(!rendered.contains(r#""sod""#), "{rendered}");
    }

    /// The other result type shares the identity body, so a change to one cannot quietly
    /// diverge from the other.
    #[test]
    fn a_plain_identity_result_is_unchanged() {
        let rendered = Json::from(VerifiedIdentity::default()).render();

        assert!(rendered.starts_with(r#"{"identity":{"#), "{rendered}");
        assert!(!rendered.contains("dataGroups"), "{rendered}");
    }
}
