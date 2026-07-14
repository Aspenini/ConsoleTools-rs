//! Output control mirroring the C tool's -q / -Q flags:
//! -q suppresses informational output (stdout), -Q additionally
//! suppresses error output (stderr).

use std::sync::atomic::{AtomicBool, Ordering};

pub static QUIET: AtomicBool = AtomicBool::new(false);
pub static REAL_QUIET: AtomicBool = AtomicBool::new(false);
/// Set when a non-fatal warning was issued; main prints a notice at the end.
pub static WARNED: AtomicBool = AtomicBool::new(false);

pub fn quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

pub fn real_quiet() -> bool {
    REAL_QUIET.load(Ordering::Relaxed)
}

pub fn set_quiet() {
    QUIET.store(true, Ordering::Relaxed);
}

pub fn set_real_quiet() {
    QUIET.store(true, Ordering::Relaxed);
    REAL_QUIET.store(true, Ordering::Relaxed);
}

pub fn warn_issued() {
    WARNED.store(true, Ordering::Relaxed);
}

pub fn was_warned() -> bool {
    WARNED.load(Ordering::Relaxed)
}

/// Informational output (suppressed by -q and -Q).
macro_rules! exiso_log {
    ($($arg:tt)*) => {
        if !$crate::logging::quiet() { print!($($arg)*); }
    };
}

/// Error/warning output (suppressed only by -Q).
macro_rules! log_err {
    ($($arg:tt)*) => {
        if !$crate::logging::real_quiet() { eprintln!($($arg)*); }
    };
}

/// Flush stdout so progress lines ending in '\r' become visible.
macro_rules! flush {
    () => {
        if !$crate::logging::quiet() {
            use std::io::Write as _;
            let _ = std::io::stdout().flush();
        }
    };
}

pub(crate) use {exiso_log, flush, log_err};
