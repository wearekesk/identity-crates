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
use crate::passport::{ApduChannel, MrzKey, PassportFiles, PassportOptions, Session};
use crate::IdentityError;

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
/// replays forever. `e_reader_key` is the reader's 32-byte ephemeral private key,
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

        Self(format!(
            concat!(
                r#"{{"identity":{{"#,
                r#""familyName":{},"givenName":{},"dateOfBirth":{},"dateOfExpiry":{},"#,
                r#""documentNumber":{},"nationality":{},"sex":{},"portrait":{},"#,
                r#""ageAttestations":[{}],"source":{},"#,
                r#""authenticity":{{"dataAuthentic":{},"issuerTrusted":{},"#,
                r#""holderBound":{},"notExpired":{},"warnings":[{}]}}}}}}"#,
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
            source(&identity),
            authenticity.data_authentic,
            authenticity.issuer_trusted,
            match authenticity.holder_bound {
                Some(value) => value.to_string(),
                None => "null".to_string(),
            },
            authenticity.not_expired,
            warnings,
        ))
    }
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
        }) => format!(
            r#"{{"kind":"mdl","docType":{},"issuingAuthority":{}}}"#,
            quote(doc_type),
            optional(issuing_authority)
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
