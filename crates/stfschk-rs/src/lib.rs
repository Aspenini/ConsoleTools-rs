//! Parse and verify Xbox 360 STFS/XContent packages.
//!
//! The crate owns the package bytes, so parsed metadata and directory entries
//! can be inspected without keeping an input stream alive. Use
//! [`StfsPackage::open`] for files or [`StfsPackage::parse`] for in-memory data.

mod crypto;
mod error;
mod format;
mod package;
mod verify;

pub use error::Error;
pub use format::{
    ConsoleCertificate, DirectoryEntry, ExecutionId, Header, InstallerMetadata, License, Metadata,
    PackageKind, Version, VolumeDescriptor,
};
pub use package::{BLOCK_SIZE, FileRecord, StfsPackage, is_package};
pub use verify::{
    DirectoryBlockStatus, EntryVerification, InvalidDataBlock, SignatureStatus, VerificationReport,
};

/// The crate and command version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
