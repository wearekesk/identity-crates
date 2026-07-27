//! What the holder gets told when a read fails.
//!
//! A session that will not start looks the same from the protocol's side whether the
//! phone moved or the document number was mistyped — and those need opposite
//! responses. These tests pin the distinction, which is the part of the read path that
//! can be exercised without a chip.

use identity_mobile::passport::{self, ApduChannel, MrzKey, PassportOptions};
use identity_mobile::IdentityError;

/// The tag went away mid-read.
struct DeadTag;

impl ApduChannel for DeadTag {
    fn transceive(&mut self, _apdu: &[u8]) -> Result<Vec<u8>, String> {
        Err("tag was lost".to_string())
    }
}

/// A chip that is present and answering, but refuses everything —
/// `6982 security status not satisfied`, which is what a wrong access key looks like.
struct RefusingChip;

impl ApduChannel for RefusingChip {
    fn transceive(&mut self, _apdu: &[u8]) -> Result<Vec<u8>, String> {
        Ok(vec![0x69, 0x82])
    }
}

fn key() -> MrzKey {
    MrzKey::new("123456789", "1988-03-14", "2030-01-01").expect("a well-formed key")
}

#[test]
fn a_lost_tag_is_reported_as_an_nfc_problem() {
    let result =
        passport::read_passport(Box::new(DeadTag), &key(), &[], &PassportOptions::default());

    assert!(
        matches!(result, Err(IdentityError::Nfc(_))),
        "a transport failure must not be blamed on the access key: {result:?}"
    );
}

/// The opposite case, and the reason the distinction is worth carrying: the chip is
/// talking, it just will not accept the key. Telling this holder to "hold still" would
/// send them in a circle.
#[test]
fn a_refused_key_is_reported_as_an_access_problem() {
    let result = passport::read_passport(
        Box::new(RefusingChip),
        &key(),
        &[],
        &PassportOptions::default(),
    );

    assert!(
        matches!(result, Err(IdentityError::Access)),
        "a chip that answers but refuses is a key problem: {result:?}"
    );
}

#[test]
fn the_access_error_says_what_to_check() {
    let message = IdentityError::Access.to_string();

    assert!(message.contains("document number"), "{message}");
    assert!(message.contains("date of birth"), "{message}");
}

#[test]
fn a_malformed_date_is_rejected_before_any_nfc_happens() {
    let result = MrzKey::new("123456789", "14/03/1988", "2030-01-01");

    assert!(
        matches!(result, Err(IdentityError::Unreadable(_))),
        "{result:?}"
    );
}
