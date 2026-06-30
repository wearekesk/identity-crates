//! Constant values used while decoding a PAN Secure QR.
//!
//! The character-set alphabets, the whitelisted version sets, the WebP
//! image-header markers, and the two embedded ECC public keys.

use crate::enums::CharacterSets;

/// Returns the alphabet string for a character set, or `None` for `Text`
/// (which has no fixed alphabet).
pub fn character_set(set: CharacterSets) -> Option<&'static str> {
    Some(match set {
        CharacterSets::Numeric1 => "0123456789+-.%/*",
        CharacterSets::Numeric2 => "0123456789-.%<>/",
        CharacterSets::Text => return None,
        CharacterSets::AlphaNumericUpperCase => {
            r"01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ ~!@#$%^&*()+-={[}]\\;:/?<.>"
        }
        CharacterSets::AlphaNumericLowerCase => {
            r"01234567890abcdefghijklmnopqrstuvwxyz ~!@#$%^&*()+-={[}]\\;:/?<.>"
        }
        CharacterSets::AlphaNumeric => {
            r"01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ~!@#$%^&*()+-={[}]\\;:/?<.>\',|`"
        }
        CharacterSets::AlphabetsUpperCase => r"ABCDEFGHIJKLMNOPQRSTUVWXYZ .\\-/\'",
        CharacterSets::AlphabetsLowerCase => r"abcdefghijklmnopqrstuvwxyz .\\-/\'",
        CharacterSets::Alphabets => {
            r"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz .,-@\'*!|?_="
        }
        CharacterSets::HexaDecimal => "0123456789ABCDEF",
    })
}

/// `WHITELISTED_VERSION_1` — accepted `reserved_1` version codes (set 1).
pub const WHITELISTED_VERSION_1: [u32; 2] = [0x9990, 0x998F];

/// `WHITELISTED_VERSION_2` — accepted `reserved_1` version codes, verified with
/// [`ECC_KEY_1`].
pub const WHITELISTED_VERSION_2: [u32; 2] = [0x1E, 0x20];

/// `WHITELISTED_VERSION_3` — accepted `reserved_1` version codes (set 3).
pub const WHITELISTED_VERSION_3: [u32; 2] = [0x998E, 0x998D];

/// `WHITELISTED_VERSION_4` — accepted `reserved_1` version codes, verified with
/// [`ECC_KEY_2`].
pub const WHITELISTED_VERSION_4: [u32; 2] = [0x1F, 0x21];

/// WebP container magic (`RIFF`).
pub const IMAGE_HEADER_RIFF: &[u8; 4] = b"RIFF";

/// WebP form-type magic (`WEBP`).
pub const IMAGE_HEADER_WEBP: &[u8; 4] = b"WEBP";

/// WebP lossy chunk magic (`VP8 `, with a trailing space `0x20`).
pub const IMAGE_HEADER_VP8: &[u8; 4] = b"VP8 ";

/// Embedded ECC public key #1 (base64, used for [`WHITELISTED_VERSION_2`]).
pub const ECC_KEY_1: &str = "AwEAA0VDQ1UAAAABAAwxLjMuMTMyLjAuMzQAYwRhBI1vbBVnA1KE/T1UpdQYzG6LLot++cuCP5DdEdeKtedw5G8RKAhU0KbNXVUwym8CSwUyzdAPC98DAgvkJGOZA/x+cnJOWhVvYTqJvy+IlcOgjSe9kqs0O7zEBy26UmvlIw==";

/// Embedded ECC public key #2 (base64, used for [`WHITELISTED_VERSION_4`]).
pub const ECC_KEY_2: &str = "AwEAA0VDQ1UAAAABAAwxLjMuMTMyLjAuMzQAYwRhBJ+fsFQNaIohp5JnCmGArWA5i25WAKHqFYnOEpRYsVmxK/O2W7iIy2T9x3vkZHaZm661w93VNc/99coCSzL92c1x9y5zxQPJCUztH2kT/EwGphLgvKKe2tK/rKMjNDMpSA==";

/// `true` if `reserved_1` is in any of the four whitelisted version sets.
pub fn is_whitelisted_version(reserved_1: u32) -> bool {
    WHITELISTED_VERSION_1.contains(&reserved_1)
        || WHITELISTED_VERSION_2.contains(&reserved_1)
        || WHITELISTED_VERSION_3.contains(&reserved_1)
        || WHITELISTED_VERSION_4.contains(&reserved_1)
}
