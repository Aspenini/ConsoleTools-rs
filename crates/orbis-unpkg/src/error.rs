// SPDX-FileCopyrightText: Copyright 2026 Aspenini (orbis-unpkg)
// SPDX-License-Identifier: GPL-2.0-or-later

//! Error and result types for the crate.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Errors that can occur while reading or extracting a PKG.
#[derive(Debug)]
pub enum Error {
    /// An underlying I/O operation failed.
    Io(io::Error),
    /// The file does not start with the PKG magic (`\x7FCNT`).
    NotAPkg,
    /// A structural problem was found in the PKG.
    Malformed(String),
    /// RSA key construction or decryption failed.
    Crypto(String),
    /// The PSF (`param.sfo`) buffer could not be parsed.
    Psf(String),
    /// An extraction step referenced a path that was never resolved.
    UnresolvedPath(PathBuf),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::NotAPkg => write!(f, "file is not a valid PKG"),
            Error::Malformed(m) => write!(f, "malformed PKG: {m}"),
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
            Error::Psf(m) => write!(f, "invalid PSF: {m}"),
            Error::UnresolvedPath(p) => write!(f, "unresolved extraction path: {}", p.display()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// Convenience result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
