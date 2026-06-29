//! DMRTD protocol layer.

pub mod access_key;
pub mod bac_session;
pub mod can_key;
pub mod dba_key;
pub mod iso7816;
pub mod pace_session;

pub mod ssc;

pub(crate) mod aes_smcipher;
pub(crate) mod bac;
pub(crate) mod des_smcipher;
// `dh_pace` is the classical-DH PACE backend: fully implemented and covered by
// its own tests, but not yet wired into the synchronous session (which runs
// ECDH-GM today). `ecdh_pace`, `pace` and `public_key_pace` likewise expose a
// fuller engine/protocol API than the session currently drives. Allow the
// not-yet-reachable items rather than dropping intentional, tested API.
#[allow(dead_code)]
pub(crate) mod dh_pace;
pub(crate) mod domain_parameter;
#[allow(dead_code)]
pub(crate) mod ecdh_pace;
pub(crate) mod mrtd_api;
pub(crate) mod mrtd_sm;
#[allow(dead_code)]
pub(crate) mod pace;
#[allow(dead_code)]
pub(crate) mod public_key_pace;
