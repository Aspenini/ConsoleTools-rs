// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-FileCopyrightText: Copyright 2026 Aspenini (orbis-unpkg)
// SPDX-License-Identifier: GPL-2.0-or-later

//! `orbis-unpkg` — a library for inspecting and extracting PlayStation 4 PKG
//! files.
//!
//! It is an idiomatic Rust port of the PKG extractor that used to ship with the
//! shadPS4 emulator. The high-level entry point is [`Pkg`]:
//!
//! ```no_run
//! use orbis_unpkg::{Pkg, detect_file_type, FileType};
//! # fn main() -> orbis_unpkg::Result<()> {
//! let path = "game.pkg";
//! assert_eq!(detect_file_type(path)?, FileType::Pkg);
//!
//! let mut pkg = Pkg::open(path)?;
//! println!("title id: {}", pkg.title_id());
//!
//! pkg.extract("out")?;
//! for i in 0..pkg.num_files() {
//!     pkg.extract_file(i)?;
//! }
//! # Ok(())
//! # }
//! ```

mod crypto;
mod entry_names;
mod keys;
mod pfs;
mod pkg;
mod psf;
mod reader;

pub mod error;

pub use crypto::verify_embedded_keys;
pub use error::{Error, Result};
pub use pkg::Pkg;
pub use psf::{Psf, Value as PsfValue};

/// Category of a file, as far as this crate can recognise it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// A PlayStation 4 PKG container.
    Pkg,
    /// Anything else.
    Unknown,
}

/// Magic value at the start of a PKG file (`\x7FCNT`), stored big-endian.
const PKG_MAGIC: u32 = 0x7F43_4E54;

/// Detects the type of the file at `path` by inspecting its 4-byte magic.
///
/// An empty path or a file that cannot be read yields [`FileType::Unknown`],
/// matching the lenient behaviour of the original `DetectFileType`.
pub fn detect_file_type(path: impl AsRef<std::path::Path>) -> Result<FileType> {
    use std::io::Read;

    let path = path.as_ref();
    if path.as_os_str().is_empty() {
        return Ok(FileType::Unknown);
    }
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(FileType::Unknown),
    };
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return Ok(FileType::Unknown);
    }
    // The loader compares the little-endian read against 0x544E437F, which is
    // the same four bytes as the big-endian PKG magic.
    if u32::from_be_bytes(magic) == PKG_MAGIC {
        Ok(FileType::Pkg)
    } else {
        Ok(FileType::Unknown)
    }
}

/// The classification the CLI uses to decide where a PKG should be installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgCategory {
    /// A base game.
    Base,
    /// A game update / patch.
    Patch,
    /// Downloadable content (an add-on).
    Dlc,
}

impl PkgCategory {
    /// Classifies a PKG from its content-flag string and `param.sfo` `CATEGORY`.
    ///
    /// Mirrors the original `main.cpp`: a "PATCH" content flag means a patch,
    /// a `CATEGORY` of `"ac"` means DLC, and everything else is a base game.
    #[must_use]
    pub fn classify(flags: &str, sfo_category: Option<&str>) -> Self {
        if flags.contains("PATCH") {
            PkgCategory::Patch
        } else if sfo_category == Some("ac") {
            PkgCategory::Dlc
        } else {
            PkgCategory::Base
        }
    }

    /// A human-readable label for the category.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            PkgCategory::Base => "Base game",
            PkgCategory::Patch => "Game update",
            PkgCategory::Dlc => "DLC / add-on",
        }
    }

    /// The process exit code the install scripts expect for this category.
    #[must_use]
    pub fn exit_code(self) -> u8 {
        match self {
            PkgCategory::Base => 101,
            PkgCategory::Patch => 102,
            PkgCategory::Dlc => 103,
        }
    }
}
