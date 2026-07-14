//! Create, extract, list, and rewrite XISO images — the XDVDFS format
//! used by original Xbox discs.
//!
//! This crate is the library behind the `extract-xiso` command-line
//! tool, a from-scratch Rust rewrite of the classic `extract-xiso`
//! utility. It has no dependencies outside the standard
//! library and forbids `unsafe` code.
//!
//! # Reading images
//!
//! [`XisoImage::open`] verifies an image and detects its disc layout
//! (plain game partition, redump-style full dump, XGD1, or XGD3), after
//! which the image can be listed or extracted:
//!
//! ```no_run
//! use extract_xiso::{ExtractOptions, XisoImage};
//!
//! # fn main() -> Result<(), extract_xiso::Error> {
//! let mut image = XisoImage::open("halo.iso")?;
//!
//! // List
//! for entry in image.entries()? {
//!     println!("{} ({} bytes)", entry.path_with_separator('/'), entry.size);
//! }
//!
//! // Extract, with progress reporting
//! std::fs::create_dir_all("halo")?;
//! let summary = image.extract_to(
//!     "halo".as_ref(),
//!     &ExtractOptions::default(),
//!     &mut |event| {
//!         if let extract_xiso::Event::ExtractProgress { name, done, size, .. } = event {
//!             eprintln!("{name}: {done}/{size}");
//!         }
//!     },
//! )?;
//! println!("extracted {} files ({} bytes)", summary.files, summary.bytes);
//! # Ok(())
//! # }
//! ```
//!
//! # Writing images
//!
//! [`create_image`] packs a local directory into a new image, laying the
//! directory tables out as the balanced trees the Xbox expects and
//! patching the media check in `.xbe` executables (see
//! [`CreateOptions`]). [`XisoImage::rewrite_to`] does the same using an
//! existing image as the source, producing an optimized copy:
//!
//! ```no_run
//! use extract_xiso::{CreateOptions, create_image};
//!
//! # fn main() -> Result<(), extract_xiso::Error> {
//! create_image(
//!     "halo".as_ref(),      // source directory
//!     "halo.iso".as_ref(),  // output image
//!     &CreateOptions::default(),
//!     &mut |_| {},          // ignore progress events
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! # Events and errors
//!
//! Library operations never touch stdout/stderr. Progress and non-fatal
//! warnings are delivered through an event callback ([`Event`],
//! [`Warning`]); failures are returned as [`Error`], whose `Display`
//! messages match the original tool's diagnostics.
//!
//! # Format notes
//!
//! Low-level format constants live in [`mod@format`]. Images created by this
//! crate are byte-identical to those of the original `extract-xiso`
//! (apart from the creation timestamp and version tag), and the two
//! recognize each other's optimized-image tag.

#![warn(missing_docs)]

mod avl;
mod error;
mod event;
pub mod format;
pub mod media;
mod read;
mod write;

pub use error::{Error, Result};
pub use event::{Event, EventSink, Warning};
pub use read::{
    ExtractOptions, ExtractSummary, FileEntry, SYSTEM_UPDATE, XisoImage, is_image_optimized,
};
pub use write::{CreateOptions, WriteSummary, create_image};
