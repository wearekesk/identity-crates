//! The C ABI, exercised the way the plugin calls it.
//!
//! The JSON writer is hand-rolled, so these parse the output rather than matching on
//! substrings: a writer that emits *almost* valid JSON would pass a substring check
//! and fail on the Dart side, which is a miserable place to discover it.

use std::ffi::{CStr, CString};

use identity_mobile::ffi::{
    identity_mobile_string_free, identity_mobile_verify_mdl, identity_mobile_verify_passport, Bytes,
};

static DG1: &[u8] = include_bytes!("fixtures/dg1.bin");
static DG2: &[u8] = include_bytes!("fixtures/dg2.bin");
static SOD: &[u8] = include_bytes!("fixtures/efsod.bin");
static CSCA: &[u8] = include_bytes!("fixtures/csca.der");

fn bytes(slice: &[u8]) -> Bytes {
    Bytes {
        ptr: slice.as_ptr(),
        len: slice.len(),
    }
}

const NOTHING: Bytes = Bytes {
    ptr: std::ptr::null(),
    len: 0,
};

/// Call through the ABI and take ownership of the result, as the host must.
fn take(result: *mut std::ffi::c_char) -> serde_json::Value {
    assert!(!result.is_null(), "the ABI never returns null");

    let json = unsafe { CStr::from_ptr(result) }
        .to_str()
        .expect("valid UTF-8")
        .to_owned();

    unsafe { identity_mobile_string_free(result) };

    serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("the ABI emitted invalid JSON: {e}\n{json}"))
}

#[test]
fn a_verified_passport_crosses_the_boundary_intact() {
    let anchors = [bytes(CSCA)];

    let value = take(unsafe {
        identity_mobile_verify_passport(
            bytes(SOD),
            bytes(DG1),
            bytes(DG2),
            anchors.as_ptr(),
            anchors.len(),
        )
    });

    let identity = &value["identity"];
    assert_eq!(identity["familyName"], "SHARMA");
    assert_eq!(identity["givenName"], "PRIYA");
    assert_eq!(identity["dateOfBirth"], "1988-03-14");
    assert_eq!(identity["nationality"], "GBR");

    assert_eq!(identity["authenticity"]["dataAuthentic"], true);
    assert_eq!(identity["authenticity"]["issuerTrusted"], true);
    // Not attempted, and it has to arrive as null rather than false.
    assert!(identity["authenticity"]["holderBound"].is_null());

    assert_eq!(identity["source"]["kind"], "passport");
    assert_eq!(identity["source"]["issuingState"], "GBR");
    assert_eq!(
        identity["source"]["verifiedDataGroups"],
        serde_json::json!([1, 2])
    );

    // The portrait crosses as hex, and it is the JPEG the issuer signed.
    let portrait = identity["portrait"].as_str().expect("a portrait");
    assert!(portrait.starts_with("ffd8ffe0"), "{portrait}");
}

/// A null DG2 means "not read", and must not be reported as a covered group.
#[test]
fn an_absent_portrait_is_reported_rather_than_assumed() {
    let anchors = [bytes(CSCA)];

    let value = take(unsafe {
        identity_mobile_verify_passport(
            bytes(SOD),
            bytes(DG1),
            NOTHING,
            anchors.as_ptr(),
            anchors.len(),
        )
    });

    let identity = &value["identity"];
    assert!(identity["portrait"].is_null());
    assert_eq!(
        identity["source"]["verifiedDataGroups"],
        serde_json::json!([1])
    );
    assert_eq!(
        identity["source"]["signedDataGroups"],
        serde_json::json!([1, 2])
    );
    assert!(!identity["authenticity"]["warnings"]
        .as_array()
        .unwrap()
        .is_empty());
}

/// Failures arrive as a structured error, never as a null pointer — the host should
/// never have to distinguish "refused to verify" from "crashed".
#[test]
fn a_failure_crosses_as_a_typed_error() {
    let mut tampered = DG1.to_vec();
    let position = tampered.windows(6).position(|w| w == b"SHARMA").unwrap();
    tampered[position] = b'C';

    let anchors = [bytes(CSCA)];

    let value = take(unsafe {
        identity_mobile_verify_passport(
            bytes(SOD),
            bytes(&tampered),
            bytes(DG2),
            anchors.as_ptr(),
            anchors.len(),
        )
    });

    assert_eq!(value["error"]["kind"], "notAuthentic");
    assert!(value["error"]["message"].as_str().unwrap().len() > 10);
    assert!(value["identity"].is_null());
}

#[test]
fn no_anchors_is_a_valid_call() {
    let value = take(unsafe {
        identity_mobile_verify_passport(bytes(SOD), bytes(DG1), bytes(DG2), std::ptr::null(), 0)
    });

    assert_eq!(value["identity"]["authenticity"]["dataAuthentic"], true);
    assert_eq!(value["identity"]["authenticity"]["issuerTrusted"], false);
}

#[test]
fn garbage_reaches_the_host_as_an_error_not_a_crash() {
    let junk = b"not an mdoc";
    let value = take(unsafe { identity_mobile_verify_mdl(bytes(junk), std::ptr::null(), 0) });

    assert_eq!(value["error"]["kind"], "unreadable");
}

/// Freeing twice would be a double free; freeing null must simply do nothing, because
/// a host's cleanup path will hit that case.
#[test]
fn freeing_null_is_harmless() {
    unsafe { identity_mobile_string_free(std::ptr::null_mut()) };
}

/// The strings the writer emits have to survive a round trip through a C string,
/// including the characters JSON cares about.
#[test]
fn text_is_escaped_for_json() {
    let value = take(unsafe {
        identity_mobile_verify_passport(
            bytes(b"not a security object"),
            bytes(DG1),
            NOTHING,
            std::ptr::null(),
            0,
        )
    });

    let message = value["error"]["message"].as_str().expect("a message");
    assert!(!message.is_empty());
    // Round-tripping through CString would have failed on an interior NUL.
    assert!(CString::new(message).is_ok());
}
