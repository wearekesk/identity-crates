//! ISO/IEC 7816-4 APDU protocol types.
//!

pub mod command_apdu; // CommandAPDU (CLA/INS/P1/P2/data/Ne)

// Not ported from the Dart original: `icc.dart` (the ICC interface).

// `iso7816::iso7816` holds the basic inter-industry command constants, distinct from
// the APDU types beside it. Renaming would change a public path in a published crate.
#[allow(clippy::module_inception)]
pub mod iso7816;
pub mod response_apdu; // ResponseAPDU + StatusWord
pub mod sm;
pub mod smcipher;
