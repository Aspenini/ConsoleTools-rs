// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-FileCopyrightText: Copyright 2026 Aspenini (orbis-unpkg)
// SPDX-License-Identifier: GPL-2.0-or-later

//! PlayStation File System (PFS) on-disk structures used during extraction.
//!
//! All PFS fields are little-endian. The on-disk record strides differ from the
//! meaningful struct sizes (an inode slot is 0xA8 bytes but only the first 0x68
//! are parsed), so the parsers below read explicit offsets rather than mapping
//! raw memory.

use crate::reader::{le_i32, le_i64, le_u16, le_u32};

/// Directory-entry type: a regular file.
pub const PFS_FILE: u32 = 2;
/// Directory-entry type: a directory.
pub const PFS_DIR: u32 = 3;
/// Directory-entry type: the "current directory" marker.
pub const PFS_CURRENT_DIR: u32 = 4;

/// On-disk stride of a single inode record within a PFS block.
pub const INODE_STRIDE: usize = 0xA8;
/// Size of a decompressed PFS block.
pub const BLOCK_SIZE: usize = 0x10000;

/// Header of the PFSC (compressed PFS) container.
#[derive(Debug, Clone, Copy)]
pub struct PfscHeader {
    pub block_sz2: i64,
    pub block_offsets: i64,
    pub data_length: i64,
}

impl PfscHeader {
    /// Parses a PFSC header from the start of `buf`.
    pub fn parse(buf: &[u8]) -> Self {
        Self {
            // magic (0), unk4 (4), unk8 (8), block_sz (12) are unused here.
            block_sz2: le_i64(buf, 16),
            block_offsets: le_i64(buf, 24),
            // data_start (32) is unused here.
            data_length: le_i64(buf, 40),
        }
    }
}

/// A parsed PFS inode. Only the fields required by the extractor are retained.
#[derive(Debug, Clone, Copy, Default)]
pub struct Inode {
    pub mode: u16,
    pub size: i64,
    pub blocks: u32,
    pub loc: u32,
}

impl Inode {
    /// Parses an inode from a 0x68-byte (or larger) slice.
    pub fn parse(buf: &[u8]) -> Self {
        // Field offsets within the meaningful 0x68-byte inode struct:
        //   mode @ 0x00, size @ 0x08, blocks @ 0x60, loc @ 0x64
        Self {
            mode: le_u16(buf, 0x00),
            size: le_i64(buf, 0x08),
            blocks: le_u32(buf, 0x60),
            loc: le_u32(buf, 0x64),
        }
    }
}

/// A parsed directory entry.
#[derive(Debug, Clone)]
pub struct Dirent {
    pub ino: i32,
    pub ty: u32,
    pub entsize: u32,
    pub name: String,
}

impl Dirent {
    /// Fixed header size preceding the inline name.
    pub const HEADER_SIZE: usize = 16;

    /// Parses a directory entry starting at `buf[0]`. The name is read from the
    /// inline `name[512]` field bounded by `namelen`.
    pub fn parse(buf: &[u8]) -> Self {
        let ino = le_i32(buf, 0);
        let ty = le_u32(buf, 4);
        let namelen = le_i32(buf, 8).max(0) as usize;
        let entsize = le_u32(buf, 12);

        let name_start = Self::HEADER_SIZE;
        let name_end = (name_start + namelen).min(buf.len());
        let name = String::from_utf8_lossy(&buf[name_start..name_end]).into_owned();

        Self {
            ino,
            ty,
            entsize,
            name,
        }
    }
}

/// A resolved filesystem-table entry (name, inode, type) discovered while
/// walking the PFS directory tree.
#[derive(Debug, Clone)]
pub struct FsTableEntry {
    pub name: String,
    pub inode: u32,
    pub ty: u32,
}
