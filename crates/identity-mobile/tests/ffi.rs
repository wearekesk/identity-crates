//! The C ABI, exercised the way the plugin calls it.
//!
//! The JSON writer is hand-rolled, so these parse the output rather than matching on
//! substrings: a writer that emits *almost* valid JSON would pass a substring check
//! and fail on the Dart side, which is a miserable place to discover it.

use std::ffi::{CStr, CString};

use identity_mobile::ffi::{
    identity_mobile_read_passport, identity_mobile_string_free, identity_mobile_verify_mdl,
    identity_mobile_verify_passport, Bytes,
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
            NOTHING,
            anchors.as_ptr(),
            anchors.len(),
        )
    });

    let identity = &value["identity"];
    assert_eq!(identity["familyName"], "SHARMA");
    assert_eq!(identity["givenName"], "PRIYA");
    assert_eq!(identity["dateOfBirth"], "1988-03-14");
    assert_eq!(identity["nationality"], "FRA");

    assert_eq!(identity["authenticity"]["dataAuthentic"], true);
    assert_eq!(identity["authenticity"]["issuerTrusted"], true);
    // Not attempted, and it has to arrive as null rather than false.
    assert!(identity["authenticity"]["holderBound"].is_null());

    assert_eq!(identity["source"]["kind"], "passport");
    // The issuing state, which the fixture deliberately sets apart from the holder's
    // nationality above.
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
            NOTHING,
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
        identity_mobile_verify_passport(
            bytes(SOD),
            bytes(DG1),
            bytes(DG2),
            NOTHING,
            std::ptr::null(),
            0,
        )
    });

    assert_eq!(value["identity"]["authenticity"]["dataAuthentic"], true);
    assert_eq!(value["identity"]["authenticity"]["issuerTrusted"], false);
}

#[test]
fn garbage_reaches_the_host_as_an_error_not_a_crash() {
    let junk = b"not an mdoc";
    let value = take(unsafe {
        identity_mobile_verify_mdl(bytes(junk), std::ptr::null(), 0, NOTHING, NOTHING)
    });

    assert_eq!(value["error"]["kind"], "unreadable");
}

/// A reader key that is not 32 bytes is a caller mistake, and has to be named as one
/// rather than producing a puzzling verification failure later.
#[test]
fn a_wrong_sized_reader_key_is_rejected_by_name() {
    let transcript = [0x83, 0xf6, 0xf6, 0x80];
    let short_key = [0u8; 8];

    let value = take(unsafe {
        identity_mobile_verify_mdl(
            bytes(b"irrelevant"),
            std::ptr::null(),
            0,
            bytes(&transcript),
            bytes(&short_key),
        )
    });

    assert_eq!(value["error"]["kind"], "unreadable");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("32 bytes"),
        "{}",
        value["error"]["message"]
    );
}

/// A transport failure is reported by a negative code. Casting that to a length before
/// checking the sign wraps it to something enormous, which is how it briefly came back
/// as "you reported 18446744073709551615 bytes".
///
/// This goes through the C entry point with a real `TransceiveFn`, because the bug was
/// in the code that interprets that callback's return value — a test that returns a
/// Rust `Err` instead would exercise a different path and prove nothing about it.
#[test]
fn a_negative_transceive_code_is_a_transport_failure_not_an_overflow() {
    extern "C" fn refuse(
        _context: *mut std::ffi::c_void,
        _apdu: *const u8,
        _apdu_len: usize,
        _response: *mut u8,
        _capacity: usize,
    ) -> std::ffi::c_int {
        -1
    }

    let number = CString::new("123456789").unwrap();
    let birth = CString::new("1988-03-14").unwrap();
    let expiry = CString::new("2030-01-01").unwrap();

    let value = take(unsafe {
        identity_mobile_read_passport(
            number.as_ptr(),
            birth.as_ptr(),
            expiry.as_ptr(),
            std::ptr::null(),
            0,
            false,
            false,
            false,
            refuse,
            std::ptr::null_mut(),
        )
    });

    let message = value["error"]["message"].as_str().expect("a message");
    assert!(
        !message.contains("byte buffer"),
        "a refused exchange must not be described as an oversized response: {message}"
    );
    assert_eq!(value["error"]["kind"], "nfc");
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
