//! DF1 (Dedicated File 1) – Elementary Files for ICAO 9303 Machine Readable Travel Documents.

// `df1::df1` holds the application's own constants (its AID and name) while the
// siblings hold the elementary files inside it, so the nesting says something real.
// Renaming it would change a public path in a published crate to satisfy a naming
// convention.
#[allow(clippy::module_inception)]
pub mod df1;
pub mod dg;
pub mod efcom;
pub mod efdg1;
pub mod efdg10;
pub mod efdg11;
pub mod efdg12;
pub mod efdg13;
pub mod efdg14;
pub mod efdg15;
pub mod efdg16;
pub mod efdg2;
pub mod efdg3;
pub mod efdg4;
pub mod efdg5;
pub mod efdg6;
pub mod efdg7;
pub mod efdg8;
pub mod efdg9;
pub mod efsod;
