//! Library error type.

use std::fmt;
use std::io;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong while reading or writing an XISO image.
///
/// The [`Display`](fmt::Display) messages match the diagnostics of the
/// original `extract-xiso` C tool, so the command-line frontend can print
/// errors verbatim. I/O-related variants expose the underlying
/// [`io::Error`] through [`std::error::Error::source`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error from a general filesystem operation.
    Io(io::Error),
    /// Reading from an image or source file failed.
    Read(io::Error),
    /// Writing to an image or output file failed.
    Write(io::Error),
    /// Seeking within an image failed.
    Seek(io::Error),
    /// A file could not be opened or created.
    Open {
        /// The path that failed to open.
        path: String,
        /// The underlying I/O error.
        source: io::Error,
    },
    /// A directory could not be created during extraction.
    CreateDir {
        /// The path that failed to be created.
        path: String,
        /// The underlying I/O error.
        source: io::Error,
    },
    /// A local directory could not be read while building an image.
    ReadDir {
        /// The directory that failed to be read.
        path: String,
        /// The underlying I/O error.
        source: io::Error,
    },
    /// No XDVDFS header was found at any of the known disc layouts.
    NotAnXiso {
        /// Image name used in the message.
        name: String,
    },
    /// The header was found but its trailing magic does not match.
    CorruptImage {
        /// Image name used in the message.
        name: String,
    },
    /// A directory table contains duplicate entries.
    CorruptDirectoryTree,
    /// An entry name in the image is empty, ".", "..", or contains a path
    /// separator (a path-traversal attempt).
    InvalidFilename {
        /// The offending name.
        name: String,
    },
    /// Two files in a source directory collide under the image's
    /// case-insensitive name ordering.
    DuplicateFilename {
        /// The path of the colliding file.
        path: String,
    },
    /// A directory holds so many entries that its table exceeds what the
    /// on-disc format can address.
    DirectoryTableTooLarge,
    /// The input data does not fit in an XISO image.
    ImageTooLarge,
    /// Rewriting an image over its own source file was requested.
    SameInputAndOutput {
        /// Path used as both the input and output.
        path: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Read(e) => write!(f, "read error: {e}"),
            Error::Write(e) => write!(f, "write error: {e}"),
            Error::Seek(e) => write!(f, "seek error: {e}"),
            Error::Open { path, source } => write!(f, "open error: {path} {source}"),
            Error::CreateDir { path, source } => {
                write!(f, "unable to create directory {path}: {source}")
            }
            Error::ReadDir { path, source } => {
                write!(f, "unable to change to directory {path}: {source}")
            }
            Error::NotAnXiso { name } => {
                write!(f, "{name} does not appear to be a valid xbox iso image")
            }
            Error::CorruptImage { name } => write!(f, "{name} appears to be corrupt"),
            Error::CorruptDirectoryTree => write!(f, "this iso appears to be corrupt"),
            Error::InvalidFilename { name } => {
                write!(
                    f,
                    "filename '{name}' contains invalid character(s), aborting."
                )
            }
            Error::DuplicateFilename { path } => {
                write!(
                    f,
                    "error inserting file {path} into tree (duplicate filename?)"
                )
            }
            Error::DirectoryTableTooLarge => write!(f, "directory table too large for xiso"),
            Error::ImageTooLarge => write!(f, "input too large for an xiso image"),
            Error::SameInputAndOutput { path } => {
                write!(f, "input and output refer to the same file: {path}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) | Error::Read(e) | Error::Write(e) | Error::Seek(e) => Some(e),
            Error::Open { source, .. }
            | Error::CreateDir { source, .. }
            | Error::ReadDir { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}
