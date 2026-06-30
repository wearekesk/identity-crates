//! Sensitive-data logging helpers.
//!
//! The version extended the `Logger` class with helpers like:
//!   - `trace` / `sdTrace`  (FINEST level)
//!   - `verbose` / `sdVerbose` (FINER level)
//!   - `debug` / `sdDebug`  (FINE level)
//!   - `sdInfo`, `sdWarning`, `sdError`, `sdShout`
//!   - `logSensitiveData` flag (hierarchical)
//!
//! In Rust we use the standard `log` crate.  There is no class hierarchy to
//! extend, so we provide:
//!
//! 1. A thread-local / global **`LOG_SENSITIVE_DATA`** flag that can be set at
//!    runtime to enable or disable sensitive-data log lines.
//! 2. A [`SensitiveLogger`] struct that wraps a target name and exposes the
//!    same surface as the reference extension.
//! 3. Convenience free-function macros (`sd_trace!`, `sd_debug!`, …) that
//!    emit log records only when the flag is set.

use std::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Global sensitive-data logging flag
// ---------------------------------------------------------------------------

/// Global flag controlling whether sensitive-data log calls actually emit
/// records.  Defaults to `false` (disabled).
///
/// Set with [`set_log_sensitive_data`] and read with [`log_sensitive_data`].
static LOG_SENSITIVE_DATA: AtomicBool = AtomicBool::new(false);

/// Returns `true` if sensitive-data logging is currently enabled.
pub fn log_sensitive_data() -> bool {
    LOG_SENSITIVE_DATA.load(Ordering::Relaxed)
}

/// Enables or disables sensitive-data logging globally.
pub fn set_log_sensitive_data(enable: bool) {
    LOG_SENSITIVE_DATA.store(enable, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// SensitiveLogger
// ---------------------------------------------------------------------------

/// A thin wrapper around a log *target* string that exposes the same logging
/// surface as the `LogApis` extension.
///
/// Log levels map as follows:
///
/// | Log level  | Rust `log` level |
/// |-------------|-----------------|
/// | FINEST      | `trace!`        |
/// | FINER       | `trace!`        |
/// | FINE        | `debug!`        |
/// | INFO        | `info!`         |
/// | WARNING     | `warn!`         |
/// | SEVERE      | `error!`        |
/// | SHOUT       | `error!`        |
///
/// Sensitive-data variants (`sd_*`) only emit records when
/// [`log_sensitive_data()`] returns `true`.
///
/// # Example
/// ```
/// use dmrtd::extension::logging::{SensitiveLogger, set_log_sensitive_data};
///
/// let log = SensitiveLogger::new("MyModule");
/// log.debug("Starting process");
///
/// // Sensitive data is suppressed by default
/// log.sd_debug("Secret value: 42");
///
/// // Enable and try again
/// set_log_sensitive_data(true);
/// log.sd_debug("Secret value: 42"); // now actually logged
/// set_log_sensitive_data(false);    // reset
/// ```
#[derive(Clone)]
pub struct SensitiveLogger {
    target: &'static str,
}

impl SensitiveLogger {
    /// Creates a new [`SensitiveLogger`] with the given log target name.
    pub const fn new(target: &'static str) -> Self {
        Self { target }
    }

    // -----------------------------------------------------------------------
    // Normal log methods (always emit)
    // -----------------------------------------------------------------------

    /// Log at `trace` level.
    pub fn trace(&self, message: &str) {
        log::trace!(target: self.target, "{}", message);
    }

    /// Log at `trace` level.
    pub fn verbose(&self, message: &str) {
        log::trace!(target: self.target, "{}", message);
    }

    /// Log at `debug` level.
    pub fn debug(&self, message: &str) {
        log::debug!(target: self.target, "{}", message);
    }

    /// Log at `info` level.
    pub fn info(&self, message: &str) {
        log::info!(target: self.target, "{}", message);
    }

    /// Log at `warn` level.
    pub fn warning(&self, message: &str) {
        log::warn!(target: self.target, "{}", message);
    }

    /// Log at `error` level.
    pub fn error(&self, message: &str) {
        log::error!(target: self.target, "{}", message);
    }

    // -----------------------------------------------------------------------
    // Sensitive-data log methods (only emit when flag is set)
    // -----------------------------------------------------------------------

    /// Log at `trace` level **only** when sensitive-data logging is enabled.
    pub fn sd_trace(&self, message: &str) {
        if log_sensitive_data() {
            log::trace!(target: self.target, "[SD] {}", message);
        }
    }

    /// Log at `trace` level **only** when sensitive-data logging is enabled.
    pub fn sd_verbose(&self, message: &str) {
        if log_sensitive_data() {
            log::trace!(target: self.target, "[SD] {}", message);
        }
    }

    /// Log at `debug` level **only** when sensitive-data logging is enabled.
    pub fn sd_debug(&self, message: &str) {
        if log_sensitive_data() {
            log::debug!(target: self.target, "[SD] {}", message);
        }
    }

    /// Log at `info` level **only** when sensitive-data logging is enabled.
    pub fn sd_info(&self, message: &str) {
        if log_sensitive_data() {
            log::info!(target: self.target, "[SD] {}", message);
        }
    }

    /// Log at `warn` level **only** when sensitive-data logging is enabled.
    pub fn sd_warning(&self, message: &str) {
        if log_sensitive_data() {
            log::warn!(target: self.target, "[SD] {}", message);
        }
    }

    /// Log at `error` level **only** when sensitive-data logging is enabled.
    pub fn sd_error(&self, message: &str) {
        if log_sensitive_data() {
            log::error!(target: self.target, "[SD] {}", message);
        }
    }

    /// Log at `error` level **only** when sensitive-data logging is enabled.
    pub fn sd_shout(&self, message: &str) {
        if log_sensitive_data() {
            log::error!(target: self.target, "[SD] {}", message);
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience macros
// ---------------------------------------------------------------------------

/// Emits a `trace`-level log record **only** when sensitive-data logging is
/// enabled (i.e. [`log_sensitive_data()`] returns `true`).
///
/// Usage mirrors the standard `log::trace!` macro.
///
/// ```
/// use dmrtd::sd_trace;
/// sd_trace!("sensitive value: {}", 42);
/// ```
#[macro_export]
macro_rules! sd_trace {
    ($($arg:tt)*) => {
        if $crate::extension::logging::log_sensitive_data() {
            log::trace!($($arg)*);
        }
    };
}

/// Emits a `debug`-level log record **only** when sensitive-data logging is
/// enabled.
#[macro_export]
macro_rules! sd_debug {
    ($($arg:tt)*) => {
        if $crate::extension::logging::log_sensitive_data() {
            log::debug!($($arg)*);
        }
    };
}

/// Emits an `info`-level log record **only** when sensitive-data logging is
/// enabled.
#[macro_export]
macro_rules! sd_info {
    ($($arg:tt)*) => {
        if $crate::extension::logging::log_sensitive_data() {
            log::info!($($arg)*);
        }
    };
}

/// Emits a `warn`-level log record **only** when sensitive-data logging is
/// enabled.
#[macro_export]
macro_rules! sd_warn {
    ($($arg:tt)*) => {
        if $crate::extension::logging::log_sensitive_data() {
            log::warn!($($arg)*);
        }
    };
}

/// Emits an `error`-level log record **only** when sensitive-data logging is
/// enabled.
#[macro_export]
macro_rules! sd_error {
    ($($arg:tt)*) => {
        if $crate::extension::logging::log_sensitive_data() {
            log::error!($($arg)*);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialises tests that read/write the process-global sensitive-data flag,
    /// which would otherwise race under cargo's parallel test runner. Poisoning
    /// is recovered from so one failing test doesn't cascade into the rest.
    static FLAG_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn default_sensitive_logging_is_disabled() {
        let _guard = FLAG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Reset to known state
        set_log_sensitive_data(false);
        assert!(!log_sensitive_data());
    }

    #[test]
    fn set_log_sensitive_data_toggles_flag() {
        let _guard = FLAG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_log_sensitive_data(false);
        assert!(!log_sensitive_data());

        set_log_sensitive_data(true);
        assert!(log_sensitive_data());

        // Restore
        set_log_sensitive_data(false);
        assert!(!log_sensitive_data());
    }

    #[test]
    fn sensitive_logger_construction() {
        let logger = SensitiveLogger::new("test_module");
        assert_eq!(logger.target, "test_module");
    }

    #[test]
    fn sensitive_logger_clone() {
        let logger = SensitiveLogger::new("test_module");
        let cloned = logger.clone();
        assert_eq!(cloned.target, "test_module");
    }

    #[test]
    fn normal_log_calls_do_not_panic() {
        let logger = SensitiveLogger::new("test");
        // These just call the log crate; no subscriber installed so they're no-ops.
        logger.trace("trace msg");
        logger.verbose("verbose msg");
        logger.debug("debug msg");
        logger.info("info msg");
        logger.warning("warning msg");
        logger.error("error msg");
    }

    #[test]
    fn sensitive_log_calls_do_not_panic_when_disabled() {
        let _guard = FLAG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_log_sensitive_data(false);
        let logger = SensitiveLogger::new("test");
        logger.sd_trace("secret trace");
        logger.sd_verbose("secret verbose");
        logger.sd_debug("secret debug");
        logger.sd_info("secret info");
        logger.sd_warning("secret warning");
        logger.sd_error("secret error");
        logger.sd_shout("secret shout");
    }

    #[test]
    fn sensitive_log_calls_do_not_panic_when_enabled() {
        let _guard = FLAG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_log_sensitive_data(true);
        let logger = SensitiveLogger::new("test");
        logger.sd_trace("secret trace");
        logger.sd_debug("secret debug");
        // Restore
        set_log_sensitive_data(false);
    }
}
