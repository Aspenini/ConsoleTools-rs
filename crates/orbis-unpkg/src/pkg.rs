// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-FileCopyrightText: Copyright 2026 Aspenini (orbis-unpkg)
// SPDX-License-Identifier: GPL-2.0-or-later

//! PKG container parsing and extraction.
//!
//! Faithful port of the original shadPS4 `PKG` class. [`Pkg::open`] reads the
//! header, entry table, and embedded `param.sfo`; [`Pkg::extract`] writes the
//! `sce_sys` metadata, derives the PFS keys, and walks the PFS directory tree;
//! [`Pkg::extract_file`] then decrypts and inflates each catalogued file.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::crypto;
use crate::entry_names;
use crate::error::{Error, Result};
use crate::pfs::{self, Dirent, FsTableEntry, Inode, PfscHeader};
use crate::reader::{be_u32, be_u64, le_u32, read_fill};

const PKG_MAGIC: u32 = 0x7F43_4E54;
const PFSC_MAGIC: u32 = 0x4353_4650;
const HEADER_SIZE: usize = 0x1000;
const ENTRY_SIZE: usize = 32;

/// Content-flag bits, ordered as in the original `flagNames` table.
const CONTENT_FLAGS: &[(u32, &str)] = &[
    (0x0010_0000, "FIRST_PATCH"),
    (0x0020_0000, "PATCHGO"),
    (0x0040_0000, "REMASTER"),
    (0x0080_0000, "PS_CLOUD"),
    (0x0200_0000, "GD_AC"),
    (0x0400_0000, "NON_GAME"),
    (0x0800_0000, "UNKNOWN_0x8000000"),
    (0x4000_0000, "SUBSEQUENT_PATCH"),
    (0x4100_0000, "DELTA_PATCH"),
    (0x6000_0000, "CUMULATIVE_PATCH"),
];

/// Selected fields of the 0x1000-byte PKG header.
#[derive(Debug, Clone)]
struct PkgHeader {
    content_flags: u32,
    table_entry_offset: u32,
    table_entry_count: u32,
    content_offset: u64,
    content_size: u64,
    pfs_image_offset: u64,
    pfs_cache_size: u32,
    pkg_size: u64,
    content_id: [u8; 36],
}

impl PkgHeader {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(Error::Malformed("header shorter than 0x1000".into()));
        }
        if be_u32(buf, 0) != PKG_MAGIC {
            return Err(Error::NotAPkg);
        }
        let mut content_id = [0u8; 36];
        content_id.copy_from_slice(&buf[0x40..0x40 + 36]);
        Ok(Self {
            content_flags: be_u32(buf, 0x78),
            table_entry_offset: be_u32(buf, 0x18),
            table_entry_count: be_u32(buf, 0x10),
            content_offset: be_u64(buf, 0x30),
            content_size: be_u64(buf, 0x38),
            pfs_image_offset: be_u64(buf, 0x410),
            pfs_cache_size: be_u32(buf, 0x43C),
            pkg_size: be_u64(buf, 0x430),
            content_id,
        })
    }

    fn title_id(&self) -> String {
        // Title id is the 9-byte field embedded at content_id offset 7.
        String::from_utf8_lossy(&self.content_id[7..16]).into_owned()
    }
}

/// A single 32-byte entry-table record.
#[derive(Debug, Clone, Copy)]
struct PkgEntry {
    id: u32,
    offset: u32,
    size: u32,
    /// The first 24 raw big-endian bytes as they appear on disk, used verbatim
    /// as part of the AES IV/key derivation.
    raw24: [u8; 24],
}

impl PkgEntry {
    fn parse(bytes: &[u8]) -> Self {
        let mut raw24 = [0u8; 24];
        raw24.copy_from_slice(&bytes[0..24]);
        Self {
            id: be_u32(bytes, 0),
            offset: be_u32(bytes, 16),
            size: be_u32(bytes, 20),
            raw24,
        }
    }
}

/// A parsed PKG file, ready to be inspected or extracted.
pub struct Pkg {
    path: PathBuf,
    header: PkgHeader,
    title_id: String,
    flags: String,
    sfo: Vec<u8>,

    // Populated by `extract`.
    ekpfs: [u8; 32],
    dk3: [u8; 32],
    data_key: [u8; 16],
    tweak_key: [u8; 16],
    pfsc_offset: u64,
    sector_map: Vec<u64>,
    inodes: Vec<Inode>,
    fs_table: Vec<FsTableEntry>,
    extract_paths: HashMap<u32, PathBuf>,
    extract_path: PathBuf,
}

impl Pkg {
    /// Opens a PKG, reading its header, entry table, and embedded `param.sfo`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = File::open(&path)?;
        let file_size = file.metadata()?.len();

        let mut header_buf = vec![0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf)?;
        let header = PkgHeader::parse(&header_buf)?;

        let flags = flags_string(header.content_flags);
        let title_id = header.title_id();

        let table = read_entry_table(&mut file, &header, file_size)?;

        // Recover the embedded param.sfo, if present.
        let mut sfo = Vec::new();
        for chunk in table.chunks_exact(ENTRY_SIZE) {
            let entry = PkgEntry::parse(chunk);
            if entry.id == entry_names::ids::PARAM_SFO {
                sfo = read_at(&mut file, entry.offset as u64, entry.size as usize)?;
                break;
            }
        }

        Ok(Self {
            path,
            header,
            title_id,
            flags,
            sfo,
            ekpfs: [0; 32],
            dk3: [0; 32],
            data_key: [0; 16],
            tweak_key: [0; 16],
            pfsc_offset: 0,
            sector_map: Vec::new(),
            inodes: Vec::new(),
            fs_table: Vec::new(),
            extract_paths: HashMap::new(),
            extract_path: PathBuf::new(),
        })
    }

    /// The 9-character title id (e.g. `CUSA01234`).
    #[must_use]
    pub fn title_id(&self) -> &str {
        &self.title_id
    }

    /// Human-readable, comma-separated list of set content flags.
    #[must_use]
    pub fn flags(&self) -> &str {
        &self.flags
    }

    /// The raw `param.sfo` bytes, or an empty slice if the PKG had none.
    #[must_use]
    pub fn param_sfo(&self) -> &[u8] {
        &self.sfo
    }

    /// Number of catalogued files discovered by [`Pkg::extract`].
    #[must_use]
    pub fn num_files(&self) -> usize {
        self.fs_table.len()
    }

    /// The leaf name of the catalogued entry at `index`, if it exists.
    #[must_use]
    pub fn file_name(&self, index: usize) -> Option<&str> {
        self.fs_table.get(index).map(|e| e.name.as_str())
    }

    /// Writes `sce_sys` metadata, derives PFS keys, and walks the PFS directory
    /// tree so that [`Pkg::extract_file`] can be called for each file.
    pub fn extract(&mut self, out_dir: impl AsRef<Path>) -> Result<()> {
        self.extract_path = out_dir.as_ref().to_path_buf();
        let mut file = File::open(&self.path)?;
        let file_size = file.metadata()?.len();

        let mut header_buf = vec![0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf)?;
        self.header = PkgHeader::parse(&header_buf)?;

        if self.header.pkg_size > file_size {
            return Err(Error::Malformed("PKG file size is different".into()));
        }
        if self.header.content_size + self.header.content_offset > self.header.pkg_size {
            return Err(Error::Malformed(
                "content size is bigger than pkg size".into(),
            ));
        }

        let sce_sys = self.extract_path.join("sce_sys");
        let table = read_entry_table(&mut file, &self.header, file_size)?;

        for chunk in table.chunks_exact(ENTRY_SIZE) {
            let entry = PkgEntry::parse(chunk);
            let name = entry_names::name_for(entry.id);

            if name.is_empty() {
                // No known name: dump the raw payload under its numeric id.
                let data = read_at(&mut file, entry.offset as u64, entry.size as usize)?;
                write_file(&sce_sys.join(entry.id.to_string()), &data)?;
                continue;
            }

            self.process_key_entry(&mut file, &entry)?;

            let out_path = sce_sys.join(name);
            let data = read_at(&mut file, entry.offset as u64, entry.size as usize)?;
            write_file(&out_path, &data)?;

            if entry_names::ids::NP_RANGE.contains(&entry.id) {
                let decrypted = self.decrypt_np_entry(&entry, &data);
                write_file(&out_path, &decrypted)?;
            }
        }

        self.build_pfs(&mut file)?;
        Ok(())
    }

    /// Handles the special key-bearing entries (`entry_keys`, `image_key`).
    fn process_key_entry(&mut self, file: &mut File, entry: &PkgEntry) -> Result<()> {
        match entry.id {
            id if id == entry_names::ids::ENTRY_KEYS => {
                // seed_digest[32] + digest1[7][32] + key1[7][256] = 2048 bytes.
                let blob = read_at(file, entry.offset as u64, 2048)?;
                let key1_3: &[u8; 256] = blob[1024..1280].try_into().unwrap();
                self.dk3 = crypto::rsa2048_decrypt(key1_3, true)?;
            }
            id if id == entry_names::ids::IMAGE_KEY => {
                let img_key_data = read_at(file, entry.offset as u64, 256)?;
                let iv_key = self.iv_key_for(entry);

                let mut img_key = [0u8; 256];
                img_key.copy_from_slice(&img_key_data);
                crypto::aes_cbc128_decrypt(&iv_key, &mut img_key);

                self.ekpfs = crypto::rsa2048_decrypt(&img_key, false)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Re-derives the per-entry IV/key: SHA-256 of `entry.raw24 || 0^8 || dk3`.
    fn iv_key_for(&self, entry: &PkgEntry) -> [u8; 32] {
        let mut concat = [0u8; 64];
        concat[0..24].copy_from_slice(&entry.raw24);
        // concat[24..32] intentionally left zero (the struct padding field).
        concat[32..64].copy_from_slice(&self.dk3);
        crypto::iv_key_hash256(&concat)
    }

    /// Decrypts an NP entry (`license.dat`, `nptitle.dat`, ...) in place.
    fn decrypt_np_entry(&self, entry: &PkgEntry, data: &[u8]) -> Vec<u8> {
        let rsize = data.len();
        // Round up to a whole AES block; the tail is zero-padded (see README).
        let msize = rsize.div_ceil(16) * 16;
        let mut buf = vec![0u8; msize];
        buf[..rsize].copy_from_slice(data);

        let iv_key = self.iv_key_for(entry);
        crypto::aes_cbc128_decrypt(&iv_key, &mut buf);

        buf.truncate(rsize);
        buf
    }

    /// Reads the PFS seed, derives data/tweak keys, decrypts the PFS image, and
    /// walks its inodes and directory entries to build the file table.
    fn build_pfs(&mut self, file: &mut File) -> Result<()> {
        // Read the PFS seed and derive the data/tweak keys.
        let seed = read_at(file, self.header.pfs_image_offset + 0x370, 16)?;
        let seed: [u8; 16] = seed.try_into().unwrap();
        let (data_key, tweak_key) = crypto::pfs_gen_crypto_key(&self.ekpfs, &seed);
        self.data_key = data_key;
        self.tweak_key = tweak_key;

        let length = self.header.pfs_cache_size as usize * 2;
        if length == 0 {
            return Ok(());
        }

        // Read and decrypt the whole (small) PFS image cache.
        let encrypted = read_at(file, self.header.pfs_image_offset, length)?;
        let mut decrypted = vec![0u8; length];
        crypto::decrypt_pfs(
            &self.data_key,
            &self.tweak_key,
            &encrypted,
            &mut decrypted,
            0,
        );

        // Locate the PFSC container inside the decrypted image.
        let pfsc_offset = find_pfsc_offset(&decrypted)
            .ok_or_else(|| Error::Malformed("PFSC magic not found".into()))?;
        self.pfsc_offset = pfsc_offset as u64;

        let mut pfsc = vec![0u8; length];
        pfsc[..length - pfsc_offset].copy_from_slice(&decrypted[pfsc_offset..]);

        let hdr = PfscHeader::parse(&pfsc);
        let num_blocks = (hdr.data_length / hdr.block_sz2) as usize;

        self.sector_map = vec![0u64; num_blocks + 1];
        for (i, slot) in self.sector_map.iter_mut().enumerate() {
            let at = hdr.block_offsets as usize + i * 8;
            *slot = u64::from_le_bytes(pfsc[at..at + 8].try_into().unwrap());
        }

        self.walk_pfs(&pfsc, num_blocks)?;
        Ok(())
    }

    /// Iterates the PFSC blocks, decompressing each and collecting inodes,
    /// directory entries, and their resolved output paths.
    fn walk_pfs(&mut self, pfsc: &[u8], num_blocks: usize) -> Result<()> {
        let mut ndinode: u32 = 0;
        let mut ndinode_counter: u32 = 0;
        let mut dinode_reached = false;
        let mut uroot_reached = false;
        let mut current_dir = PathBuf::new();

        // Reused across iterations so stale bytes persist exactly as in the
        // original C++ (which never clears the decompression buffer).
        let mut decompressed = vec![0u8; pfs::BLOCK_SIZE];

        for i in 0..num_blocks {
            let sector_offset = self.sector_map[i] as usize;
            let sector_end = self.sector_map[i + 1] as usize;
            if sector_end < sector_offset || sector_end > pfsc.len() {
                break;
            }
            let sector_size = sector_end - sector_offset;

            let compressed = &pfsc[sector_offset..sector_end];
            if sector_size == pfs::BLOCK_SIZE {
                decompressed.copy_from_slice(compressed);
            } else if sector_size < pfs::BLOCK_SIZE {
                decompress_pfsc(compressed, &mut decompressed);
            }

            if i == 0 {
                ndinode = le_u32(&decompressed, 0x30);
            }

            // Blocks occupied by the inode table.
            let mut occupied_blocks = (ndinode as usize * pfs::INODE_STRIDE) / pfs::BLOCK_SIZE;
            if (ndinode as usize * pfs::INODE_STRIDE) % pfs::BLOCK_SIZE != 0 {
                occupied_blocks += 1;
            }

            if i >= 1 && i <= occupied_blocks {
                let mut p = 0;
                while p + pfs::INODE_STRIDE <= pfs::BLOCK_SIZE {
                    let node = Inode::parse(&decompressed[p..]);
                    if node.mode == 0 {
                        break;
                    }
                    self.inodes.push(node);
                    p += pfs::INODE_STRIDE;
                }
            }

            // Detect the flat_path_table (uroot) block.
            if &decompressed[0x10..0x1F] == b"flat_path_table" {
                uroot_reached = true;
            }

            if uroot_reached {
                let mut off = 0usize;
                while off + Dirent::HEADER_SIZE <= pfs::BLOCK_SIZE {
                    let dirent = Dirent::parse(&decompressed[off..]);
                    let ent_size = dirent.entsize as usize;
                    if dirent.ino != 0 {
                        ndinode_counter += 1;
                    } else {
                        let parent_path = self.extract_path.parent().unwrap_or(Path::new(""));
                        let is_dlc_or_patch = parent_path.file_name().map(|f| f.to_string_lossy())
                            == Some(std::borrow::Cow::Borrowed(self.title_id.as_str()))
                            || self.extract_path.to_string_lossy().ends_with("-patch");
                        let resolved = if !is_dlc_or_patch {
                            parent_path.join(&self.title_id)
                        } else {
                            self.extract_path.clone()
                        };
                        self.extract_paths.insert(ndinode_counter, resolved);
                        uroot_reached = false;
                        break;
                    }
                    if ent_size == 0 {
                        break;
                    }
                    off += ent_size;
                }
            }

            // Detect the first "." / ".." directory block.
            let dot = decompressed[0x10];
            if dot == b'.' && &decompressed[0x28..0x2A] == b".." {
                dinode_reached = true;
            }

            if dinode_reached {
                let mut end_reached = false;
                let mut off = 0usize;
                while off + Dirent::HEADER_SIZE <= pfs::BLOCK_SIZE {
                    let dirent = Dirent::parse(&decompressed[off..]);
                    if dirent.ino == 0 {
                        break;
                    }
                    let ent_size = dirent.entsize as usize;

                    let inode = dirent.ino as u32;
                    let ty = dirent.ty;
                    self.fs_table.push(FsTableEntry {
                        name: dirent.name.clone(),
                        inode,
                        ty,
                    });

                    if ty == pfs::PFS_CURRENT_DIR {
                        current_dir = self
                            .extract_paths
                            .get(&inode)
                            .cloned()
                            .unwrap_or_else(|| self.extract_path.clone());
                    }
                    self.extract_paths
                        .insert(inode, current_dir.join(&dirent.name));

                    if ty == pfs::PFS_FILE || ty == pfs::PFS_DIR {
                        if ty == pfs::PFS_DIR {
                            fs::create_dir_all(&self.extract_paths[&inode])?;
                        }
                        ndinode_counter += 1;
                        if ndinode_counter + 1 == ndinode {
                            end_reached = true;
                        }
                    }
                    if ent_size == 0 {
                        break;
                    }
                    off += ent_size;
                }
                if end_reached {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Decrypts and inflates the file at `index` in the file table, writing it
    /// to its resolved output path. No-op for non-file entries.
    pub fn extract_file(&mut self, index: usize) -> Result<()> {
        self.extract_file_with_progress(index, |_, _| {})
    }

    /// Like [`Pkg::extract_file`] but reports per-block progress as
    /// `(blocks_done, blocks_total)`.
    pub fn extract_file_with_progress<F: FnMut(u64, u64)>(
        &mut self,
        index: usize,
        mut on_block: F,
    ) -> Result<()> {
        let entry = &self.fs_table[index];
        if entry.ty != pfs::PFS_FILE {
            return Ok(());
        }
        let inode_number = entry.inode as usize;
        let out_path = self
            .extract_paths
            .get(&entry.inode)
            .cloned()
            .ok_or_else(|| Error::UnresolvedPath(PathBuf::from(&entry.name)))?;

        let inode = self.inodes[inode_number];
        let sector_loc = inode.loc as usize;
        let nblocks = inode.blocks as u64;
        let bsize = inode.size;

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = File::create(&out_path)?;
        let mut pkg_file = File::open(&self.path)?;

        let mut size_decompressed: i64 = 0;
        let mut decompressed = vec![0u8; pfs::BLOCK_SIZE];
        let pfsc_buf_size = 0x11000usize; // one 0x1000 block of slack.
        let mut pfsc = vec![0u8; pfsc_buf_size];
        let mut pfs_decrypted = vec![0u8; pfsc_buf_size];

        for j in 0..nblocks {
            on_block(j + 1, nblocks);

            let sector_offset = self.sector_map[sector_loc + j as usize];
            let sector_size =
                (self.sector_map[sector_loc + j as usize + 1] - sector_offset) as usize;

            let combined = self.pfsc_offset + sector_offset;
            let previous_data = (combined & 0xFFF) as usize;
            let current_sector = combined / 0x1000;
            let file_offset = self.header.pfs_image_offset + self.pfsc_offset + sector_offset;

            pkg_file.seek(SeekFrom::Start(file_offset - previous_data as u64))?;
            for b in pfsc.iter_mut() {
                *b = 0;
            }
            read_fill(&mut pkg_file, &mut pfsc)?;

            crypto::decrypt_pfs(
                &self.data_key,
                &self.tweak_key,
                &pfsc,
                &mut pfs_decrypted,
                current_sector,
            );

            let window = &pfs_decrypted[previous_data..previous_data + sector_size];
            if sector_size == pfs::BLOCK_SIZE {
                decompressed.copy_from_slice(window);
            } else if sector_size < pfs::BLOCK_SIZE {
                decompress_pfsc(window, &mut decompressed);
            }

            size_decompressed += pfs::BLOCK_SIZE as i64;

            if j < nblocks - 1 {
                out.write_all(&decompressed)?;
            } else {
                // Trim the zero padding at the end of the final block.
                let write_size = pfs::BLOCK_SIZE as i64 - (size_decompressed - bsize);
                let write_size = write_size.clamp(0, pfs::BLOCK_SIZE as i64) as usize;
                out.write_all(&decompressed[..write_size])?;
            }
        }
        Ok(())
    }
}

/// Reads the entry table into memory, validating that it fits in the file.
fn read_entry_table(file: &mut File, header: &PkgHeader, file_size: u64) -> Result<Vec<u8>> {
    let offset = header.table_entry_offset as u64;
    let count = header.table_entry_count as usize;
    let bytes = count
        .checked_mul(ENTRY_SIZE)
        .ok_or_else(|| Error::Malformed("entry table size overflow".into()))?;
    if offset + bytes as u64 > file_size {
        return Err(Error::Malformed(
            "entry table extends past end of file".into(),
        ));
    }
    read_at(file, offset, bytes)
}

/// Reads exactly `len` bytes starting at `offset`.
fn read_at(file: &mut File, offset: u64, len: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// Writes `data` to `path`, creating parent directories as needed.
fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data)?;
    Ok(())
}

/// Scans a decrypted PFS image for the PFSC container magic.
fn find_pfsc_offset(image: &[u8]) -> Option<usize> {
    let mut i = 0x20000usize;
    while i + 4 <= image.len() {
        if le_u32(image, i) == PFSC_MAGIC {
            return Some(i);
        }
        i += 0x10000;
    }
    None
}

/// Inflates a zlib-wrapped PFSC block into `dst` (best effort, matching the
/// original which ignores inflate errors).
fn decompress_pfsc(src: &[u8], dst: &mut [u8]) {
    use flate2::{Decompress, FlushDecompress};
    let mut inflater = Decompress::new(true);
    let _ = inflater.decompress(src, dst, FlushDecompress::Finish);
}

/// Builds the comma-separated content-flag description.
fn flags_string(flags: u32) -> String {
    let mut parts = Vec::new();
    for &(bit, name) in CONTENT_FLAGS {
        if flags & bit != 0 {
            parts.push(name);
        }
    }
    parts.join(", ")
}
