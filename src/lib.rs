//! # dmrtd — eMRTD (ICAO 9303) reader core (pure Rust)
//!
//! BAC / PACE (ECDH-GM P-256), MRZ, LDS (DG1..DG16, SOD) parsing, secure
//! messaging, and the high-level [`passport::Passport`] API. Transport-agnostic:
//! NFC plugs in via the [`com::Transceiver`] trait. No async, no NFC deps.
//!
//! Extracted from `wearekesk/kyc-rs`.

//! DMRTD — eMRTD (ICAO 9303) reader core.

pub mod com;
pub mod crypto;
pub mod extension;
pub mod lds;
pub mod passport;
pub mod proto;
pub mod types;
pub mod utils;
