// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-FileCopyrightText: Copyright 2026 Aspenini (orbis-unpkg)
// SPDX-License-Identifier: GPL-2.0-or-later

//! Parser for the PS4 `param.sfo` (PSF) key/value container.
//!
//! This is a read-only port of the original shadPS4 `PSF` class, sufficient for
//! the extractor's needs (`CATEGORY`, `CONTENT_ID`, ...). Encoding is not
//! implemented because the extractor never writes PSF files.

use crate::error::{Error, Result};
use crate::reader::{be_u32, le_i32, le_u16, le_u32};

const PSF_MAGIC: u32 = 0x0050_5346;
const PSF_VERSION_1_0: u32 = 0x0000_0100;
const PSF_VERSION_1_1: u32 = 0x0000_0101;

const HEADER_SIZE: usize = 0x14;
const RAW_ENTRY_SIZE: usize = 0x10;

/// A single decoded PSF value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Raw binary payload (format `0x0004`).
    Binary(Vec<u8>),
    /// NUL-terminated UTF-8 text (format `0x0204`).
    Text(String),
    /// Signed 32-bit integer (format `0x0404`).
    Integer(i32),
}

/// A parsed `param.sfo` document.
#[derive(Debug, Clone, Default)]
pub struct Psf {
    entries: Vec<(String, Value)>,
}

impl Psf {
    /// Parses a PSF document from an in-memory buffer.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(Error::Psf("buffer smaller than PSF header".into()));
        }
        if be_u32(buf, 0) != PSF_MAGIC {
            return Err(Error::Psf("invalid PSF magic number".into()));
        }
        let version = le_u32(buf, 4);
        if version != PSF_VERSION_1_0 && version != PSF_VERSION_1_1 {
            return Err(Error::Psf(format!(
                "unsupported PSF version 0x{version:08x}"
            )));
        }
        let key_table_offset = le_u32(buf, 8) as usize;
        let data_table_offset = le_u32(buf, 12) as usize;
        let index_entries = le_u32(buf, 16) as usize;

        let mut entries = Vec::with_capacity(index_entries);
        for i in 0..index_entries {
            let raw = HEADER_SIZE + i * RAW_ENTRY_SIZE;
            if raw + RAW_ENTRY_SIZE > buf.len() {
                return Err(Error::Psf("index table truncated".into()));
            }
            let key_offset = le_u16(buf, raw) as usize;
            // The format tag is stored little-endian in practice (the original
            // reads it via the raw, un-swapped 16-bit value).
            let param_fmt = le_u16(buf, raw + 2);
            let param_len = le_u32(buf, raw + 4) as usize;
            let data_offset = le_u32(buf, raw + 12) as usize;

            let key = read_cstr(buf, key_table_offset + key_offset)?;
            let data_start = data_table_offset + data_offset;

            let value = match param_fmt {
                0x0004 => {
                    let end = data_start
                        .checked_add(param_len)
                        .filter(|&e| e <= buf.len())
                        .ok_or_else(|| Error::Psf("binary value out of bounds".into()))?;
                    Value::Binary(buf[data_start..end].to_vec())
                }
                0x0204 => Value::Text(read_cstr(buf, data_start)?),
                0x0404 => {
                    if data_start + 4 > buf.len() {
                        return Err(Error::Psf("integer value out of bounds".into()));
                    }
                    Value::Integer(le_i32(buf, data_start))
                }
                other => {
                    return Err(Error::Psf(format!(
                        "unknown PSF entry format 0x{other:04x}"
                    )));
                }
            };
            entries.push((key, value));
        }
        Ok(Self { entries })
    }

    /// Returns all parsed entries in file order.
    #[must_use]
    pub fn entries(&self) -> &[(String, Value)] {
        &self.entries
    }

    fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Returns the text value for `key`, if present and of text type.
    #[must_use]
    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Value::Text(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Returns the integer value for `key`, if present and of integer type.
    #[must_use]
    pub fn get_integer(&self, key: &str) -> Option<i32> {
        match self.get(key) {
            Some(Value::Integer(v)) => Some(*v),
            _ => None,
        }
    }

    /// Returns the binary value for `key`, if present and of binary type.
    #[must_use]
    pub fn get_binary(&self, key: &str) -> Option<&[u8]> {
        match self.get(key) {
            Some(Value::Binary(b)) => Some(b.as_slice()),
            _ => None,
        }
    }
}

fn read_cstr(buf: &[u8], start: usize) -> Result<String> {
    if start > buf.len() {
        return Err(Error::Psf("string offset out of bounds".into()));
    }
    let end = buf[start..]
        .iter()
        .position(|&b| b == 0)
        .map_or(buf.len(), |p| start + p);
    Ok(String::from_utf8_lossy(&buf[start..end]).into_owned())
}
