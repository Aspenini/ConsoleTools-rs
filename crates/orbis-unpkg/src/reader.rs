// SPDX-FileCopyrightText: Copyright 2026 Aspenini (orbis-unpkg)
// SPDX-License-Identifier: GPL-2.0-or-later

//! Small helpers for reading fixed-width integers out of byte buffers and
//! streams. Kept dependency-free; the PKG format mixes big-endian (header and
//! entry table) and little-endian (PFS structures) fields.

use std::io::{self, Read};

/// Reads a big-endian `u32` from `buf` at `off`.
#[inline]
pub(crate) fn be_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(buf[off..off + 4].try_into().unwrap())
}

/// Reads a big-endian `u64` from `buf` at `off`.
#[inline]
pub(crate) fn be_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(buf[off..off + 8].try_into().unwrap())
}

/// Reads a little-endian `u16` from `buf` at `off`.
#[inline]
pub(crate) fn le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}

/// Reads a little-endian `u32` from `buf` at `off`.
#[inline]
pub(crate) fn le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

/// Reads a little-endian `i32` from `buf` at `off`.
#[inline]
pub(crate) fn le_i32(buf: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

/// Reads a little-endian `i64` from `buf` at `off`.
#[inline]
pub(crate) fn le_i64(buf: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

/// Fills `buf` with as many bytes as are available, returning the count read.
///
/// Unlike [`Read::read_exact`], hitting end-of-file is not an error: the tail
/// of `buf` is left untouched. This mirrors the original C++ code, which read
/// fixed-size windows near the end of the file and only consumed the valid
/// prefix.
pub(crate) fn read_fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}
