//! Safe, platform-independent tools for inspecting and modifying original Xbox
//! executable (XBE) images.
//!
//! [`Xbe`] is the main entry point. It parses an image into public, typed metadata
//! while retaining the original bytes for verification and lossless write-back.

#![forbid(unsafe_code)]

mod crypto;
mod kernel_exports;
mod model;
mod render;

pub use model::{
    Certificate, Check, DumpOptions, Error, Header, KeyKind, Library, RepairOptions, Result,
    Section, ValidationReport, Xbe,
};
