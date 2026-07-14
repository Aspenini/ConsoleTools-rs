//! XDVDFS (Xbox ISO) on-disk format constants.
//!
//! These describe the layout this crate reads and writes; they are
//! exposed for consumers that want to inspect images at a lower level.

use std::fs::File;
use std::io::{self, Read};

/// Version string written into the optimized-image tag and reported by
/// the CLI banner.
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-rs");

/// Sector size of an XDVDFS image.
pub const SECTOR_SIZE: u64 = 2048;
/// Byte offset of the XDVDFS header within the game partition.
pub const HEADER_OFFSET: u64 = 0x10000;
/// Magic bytes opening and closing the XDVDFS header sector.
pub const HEADER_DATA: &[u8; 20] = b"MICROSOFT*XBOX*MEDIA";
/// Images are padded to a multiple of this size.
pub const FILE_MODULUS: u64 = 0x10000;
/// Sector at which this tool places the root directory table.
pub const ROOT_DIRECTORY_SECTOR: u32 = 0x108;

/// Game-partition offset of redump-style full disc dumps.
pub const GLOBAL_LSEEK_OFFSET: u64 = 0x0FD9_0000;
/// Game-partition offset of XGD3 dumps.
pub const XGD3_LSEEK_OFFSET: u64 = 0x0208_0000;
/// Game-partition offset of XGD1 dumps.
pub const XGD1_LSEEK_OFFSET: u64 = 0x1830_0000;

/// Byte offset of the "optimized image" tag written by this tool.
pub const OPTIMIZED_TAG_OFFSET: u64 = 31337;
/// Total length of the optimized tag ("in!xiso!" + 16-character version).
pub const OPTIMIZED_TAG_LENGTH: usize = 24;
/// Prefix that identifies an optimized image regardless of the version
/// that wrote it.
pub const OPTIMIZED_TAG_PREFIX: &[u8] = b"in!xiso";

/// Size of the fixed part of a directory entry preceding the filename.
pub const FILENAME_OFFSET: u32 = 14;
/// Maximum length of an entry name in bytes.
pub const FILENAME_MAX_CHARS: usize = 255;

/// Directory entry offsets are expressed in dwords.
pub const DWORD_SIZE: u64 = 4;
/// Size of the FILETIME field in the header.
pub const FILETIME_SIZE: usize = 8;
/// Size of the unused area between the header fields and trailing magic.
pub const UNUSED_SIZE: usize = 0x7c8;

/// Directory attribute bit.
pub const ATTRIBUTE_DIR: u8 = 0x10;
/// Archive attribute bit (used for files).
pub const ATTRIBUTE_ARC: u8 = 0x20;

/// Byte used to pad directory tables and file tails.
pub const PAD_BYTE: u8 = 0xff;
/// A directory table word of this value marks sector padding.
pub const PAD_SHORT: u16 = 0xffff;

/// x86 code sequence of the .xbe media check.
pub const MEDIA_ENABLE_PATTERN: &[u8; 8] = b"\xe8\xca\xfd\xff\xff\x85\xc0\x7d";
/// Byte the check's conditional jump is replaced with (JMP short).
pub const MEDIA_ENABLE_BYTE: u8 = 0xeb;
/// Offset of the patched byte within the pattern.
pub const MEDIA_ENABLE_BYTE_POS: usize = 7;

/// Copy buffer size used for file transfers.
pub const READWRITE_BUFFER_SIZE: usize = 0x0020_0000; // 2 MiB

pub(crate) const PATH_CHAR: char = std::path::MAIN_SEPARATOR;

/// The tag written at [`OPTIMIZED_TAG_OFFSET`] by this build.
pub fn optimized_tag() -> [u8; OPTIMIZED_TAG_LENGTH] {
    let mut tag = [b' '; OPTIMIZED_TAG_LENGTH];
    tag[..8].copy_from_slice(b"in!xiso!");
    let v = VERSION.as_bytes();
    let n = v.len().min(16);
    tag[8..8 + n].copy_from_slice(&v[..n]);
    tag
}

/// Number of sectors needed to hold `size` bytes.
pub fn n_sectors(size: u64) -> u64 {
    size.div_ceil(SECTOR_SIZE)
}

/// Read until `buf` is full or EOF; returns the number of bytes read.
pub(crate) fn read_full(f: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        match f.read(&mut buf[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}
