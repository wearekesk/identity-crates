//! Transceiver — the I/O boundary between this crate and the NFC transport.
//!
//! The crate is deliberately synchronous. For Flutter apps using
//! Dart FFI the real NFC I/O lives on the Dart side; a Dart `Transceiver`
//! implementation marshals bytes through `ffi.NativeCallable` (or a
//! `flutter_rust_bridge` stream) and blocks the Rust call until the Dart
//! future resolves.

use thiserror::Error;

/// Error returned by [`Transceiver::transceive`].
#[derive(Debug, Error)]
#[error("TransceiveError: {0}")]
pub struct TransceiveError(pub String);

impl TransceiveError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Sends an APDU to the chip and returns the full response (data || SW).
pub trait Transceiver {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransceiveError>;
}
