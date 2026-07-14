//! Progress and warning events emitted during long-running operations.
//!
//! Library operations never print anything; instead they report progress
//! through an event callback (`&mut dyn FnMut(Event<'_>)`). Pass
//! `&mut |_| {}` to ignore events entirely.
//!
//! Paths carried by events are relative to the image root and use the
//! platform path separator, matching the output of the original tool.

use std::path::Path;

/// A progress notification from [`create_image`](crate::create_image),
/// [`XisoImage::extract_to`](crate::XisoImage::extract_to), or
/// [`XisoImage::rewrite_to`](crate::XisoImage::rewrite_to).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Event<'a> {
    /// A local directory scan is starting (create mode).
    ScanBegin,
    /// The local directory scan finished.
    ScanEnd {
        /// Whether the scan succeeded.
        ok: bool,
    },
    /// A directory's contents are being written to a new image.
    AddingDirectory {
        /// Image path of the directory, ending in a separator ("\\" is the
        /// root).
        path: &'a str,
    },
    /// A file is about to be written to a new image.
    AddingFileBegin {
        /// Image path of the containing directory (ends in a separator).
        dir: &'a str,
        /// The file's name.
        name: &'a str,
        /// The file's size in bytes.
        size: u32,
    },
    /// The file announced by the last
    /// [`AddingFileBegin`](Event::AddingFileBegin) finished writing.
    AddingFileEnd {
        /// Whether the copy succeeded (an error follows when false).
        ok: bool,
    },
    /// A directory was created during extraction.
    CreatingDirectory {
        /// Path of the directory relative to the extraction root, ending
        /// in a separator.
        path: &'a str,
    },
    /// A chunk of a file was extracted. Emitted once with `done == 0` for
    /// empty files, and once per copied chunk otherwise.
    ExtractProgress {
        /// Directory of the file relative to the extraction root ("" for
        /// the root, otherwise ending in a separator).
        dir: &'a str,
        /// The file's name.
        name: &'a str,
        /// The file's total size in bytes.
        size: u32,
        /// Bytes extracted so far.
        done: u64,
    },
    /// The file reported by the preceding
    /// [`ExtractProgress`](Event::ExtractProgress) events is complete.
    ExtractFileEnd,
    /// A non-fatal problem was encountered; the operation continues.
    Warning(Warning<'a>),
}

/// Non-fatal problems reported through [`Event::Warning`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Warning<'a> {
    /// The image records a larger size for this file than could be read
    /// from it; the extracted file is truncated to what was available.
    ImageFileTruncated {
        /// The file's name.
        name: &'a str,
        /// The size recorded in the image.
        expected: u32,
        /// The number of bytes actually extracted.
        actual: u64,
    },
    /// A source file shrank while an image was being written; the entry
    /// was truncated to the data actually read.
    SourceFileTruncated {
        /// The file's name.
        name: &'a str,
        /// The size recorded when the directory was scanned.
        expected: u32,
        /// The number of bytes actually written.
        actual: u32,
    },
    /// A source file exceeds the format's 4 GiB file-size limit and was
    /// skipped.
    FileTooLarge {
        /// Path of the skipped file.
        path: &'a Path,
    },
    /// A source file's name exceeds the format's 255-byte limit and was
    /// skipped.
    FilenameTooLong {
        /// Path of the skipped file.
        path: &'a Path,
    },
}

/// Type of the event callback accepted by library operations.
pub type EventSink<'a> = dyn FnMut(Event<'_>) + 'a;
