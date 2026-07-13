//! Legacy **ZipCrypto** offline e-KYC packs must keep decrypting.
//!
//! The in-crate tests build their sample archive with AES-256, so on their own they
//! would not catch a `zip` feature set that dropped ZipCrypto support. UIDAI packs
//! in the wild are ZipCrypto (deflate + the classic PKWARE cipher), so this fixture
//! is a real `zip -P`-produced archive: encrypted bit set, compression method 8 —
//! not AES (which would be method 99).
//!
//! Note ZipCrypto needs no `zip` feature: `zip`'s `mod zipcrypto` is unconditional.
//! Only AES sits behind `aes-crypto`.

use aadhaar::decrypt_offline_zip;

const ZIPCRYPTO_PACK: &[u8] = include_bytes!("fixtures/zipcrypto_offline_ekyc.zip");
const SHARE_PHRASE: &str = "Share@1234";

#[test]
fn decrypts_legacy_zipcrypto_pack() {
    let xml = decrypt_offline_zip(ZIPCRYPTO_PACK, SHARE_PHRASE).expect("ZipCrypto pack decrypts");
    assert!(xml.contains("OfflinePaperlessKyc"), "unexpected payload: {xml}");
    assert!(xml.contains("Test User"));
}

#[test]
fn wrong_share_phrase_fails() {
    assert!(decrypt_offline_zip(ZIPCRYPTO_PACK, "Wrong@0000").is_err());
}
