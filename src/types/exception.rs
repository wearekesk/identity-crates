//! DMRTD exception types.

use thiserror::Error;

/// General-purpose DMRTD error.
#[derive(Debug, Error)]
#[error("DMRTDException: {message}")]
pub struct DMRTDException {
    pub message: String,
}

impl DMRTDException {
    /// Creates a new [`DMRTDException`] with the given `message`.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the exception name (for compatibility with the reference API).
    pub fn exception_name(&self) -> &'static str {
        "DMRTDException"
    }
}

/// Convenience alias used when callers only care about the message string.
pub type DmrtdError = DMRTDException;
