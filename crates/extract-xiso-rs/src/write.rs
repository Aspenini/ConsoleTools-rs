//! The write side: building a new image from a local directory tree
//! (create mode) or from an existing image (rewrite mode).

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::avl::{self, Node, Subdir, Tree};
use crate::error::{Error, Result};
use crate::event::{Event, Warning};
use crate::format::{
    ATTRIBUTE_ARC, ATTRIBUTE_DIR, DWORD_SIZE, FILE_MODULUS, FILENAME_MAX_CHARS, FILENAME_OFFSET,
    HEADER_DATA, HEADER_OFFSET, MEDIA_ENABLE_PATTERN, OPTIMIZED_TAG_OFFSET, PAD_BYTE, PATH_CHAR,
    READWRITE_BUFFER_SIZE, ROOT_DIRECTORY_SECTOR, SECTOR_SIZE, UNUSED_SIZE, n_sectors,
    optimized_tag, read_full,
};
use crate::media;
use crate::read::SYSTEM_UPDATE;
use crate::read::XisoImage;

/// Options for [`create_image`] and [`XisoImage::rewrite_to`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CreateOptions {
    /// Automatically patch the media check in `.xbe` files (defaults to
    /// true; the CLI's `-m` flag disables it).
    pub media_enable_patching: bool,
    /// Skip directories whose name contains `$SystemUpdate`.
    pub skip_system_update: bool,
}

impl Default for CreateOptions {
    fn default() -> Self {
        CreateOptions {
            media_enable_patching: true,
            skip_system_update: false,
        }
    }
}

impl CreateOptions {
    /// Return options with `.xbe` media-check patching set to `enabled`.
    pub fn with_media_enable_patching(mut self, enabled: bool) -> Self {
        self.media_enable_patching = enabled;
        self
    }

    /// Return options with `$SystemUpdate` skipping set to `enabled`.
    pub fn with_skip_system_update(mut self, enabled: bool) -> Self {
        self.skip_system_update = enabled;
        self
    }
}

/// Totals reported by [`create_image`] and [`XisoImage::rewrite_to`].
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteSummary {
    /// Number of files written into the image.
    pub files: u32,
    /// Number of file bytes written into the image.
    pub bytes: u64,
}

/// Difference between the Unix and Windows FILETIME epochs, in seconds.
const FILETIME_EPOCH_OFFSET: u64 = 11_644_473_600;

fn filetime_now() -> [u8; 8] {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ((secs + FILETIME_EPOCH_OFFSET) * 10_000_000).to_le_bytes()
}

/// Pack the contents of `source_dir` into a new XISO image at `output`.
///
/// `output` is created (or truncated) unconditionally and removed again
/// if the operation fails. Progress is reported through `on_event`.
///
/// ```no_run
/// use extract_xiso::{CreateOptions, create_image};
///
/// # fn main() -> Result<(), extract_xiso::Error> {
/// let summary = create_image(
///     "halo".as_ref(),
///     "halo.iso".as_ref(),
///     &CreateOptions::default(),
///     &mut |_| {},
/// )?;
/// println!("added {} files ({} bytes)", summary.files, summary.bytes);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Fails on I/O errors, on duplicate filenames under the image's
/// case-insensitive ordering, or if a directory's table would exceed
/// what the format can address.
pub fn create_image(
    source_dir: &Path,
    output: &Path,
    options: &CreateOptions,
    on_event: &mut dyn FnMut(Event<'_>),
) -> Result<WriteSummary> {
    (on_event)(Event::ScanBegin);
    let scanned = generate_avl_tree_local(source_dir, options.skip_system_update, on_event);
    (on_event)(Event::ScanEnd {
        ok: scanned.is_ok(),
    });
    let subdir = scanned?;

    write_image_file(output, subdir, Some(source_dir), None, options, on_event)
}

impl XisoImage {
    /// Rewrite this image as a new, optimized image at `output`.
    ///
    /// The directory tree is captured from this image and laid out
    /// afresh; file data is copied over (patching `.xbe` media checks
    /// unless disabled) and the source image's timestamp is preserved.
    ///
    /// # Errors
    ///
    /// Fails on I/O errors or if the source image's directory tables are
    /// corrupt.
    pub fn rewrite_to(
        &mut self,
        output: &Path,
        options: &CreateOptions,
        on_event: &mut dyn FnMut(Event<'_>),
    ) -> Result<WriteSummary> {
        if output.exists()
            && fs::canonicalize(output).is_ok_and(|output| output == self.source_path())
        {
            return Err(Error::SameInputAndOutput {
                path: output.display().to_string(),
            });
        }

        let tree = self.capture_tree(options.skip_system_update)?;
        let subdir = match tree {
            Some(node) => Subdir::Tree(node),
            None => Subdir::Empty,
        };
        let disc_offset = self.disc_offset;
        write_image_file(
            output,
            subdir,
            None,
            Some((&mut self.file, disc_offset)),
            options,
            on_event,
        )
    }
}

/// Shared implementation: lay out the tree and write the image,
/// removing the output file on failure.
fn write_image_file(
    output: &Path,
    subdir: Subdir,
    source_dir: Option<&Path>,
    from: Option<(&mut File, u64)>,
    options: &CreateOptions,
    on_event: &mut dyn FnMut(Event<'_>),
) -> Result<WriteSummary> {
    let mut root = Node::new(String::new());
    root.start_sector = ROOT_DIRECTORY_SECTOR;
    root.subdir = subdir;

    calculate_directory_requirements(&mut root);
    let mut sector = root.start_sector;
    calculate_directory_offsets(&mut root, &mut sector)?;

    let mut out = File::create(output).map_err(|e| Error::Open {
        path: output.display().to_string(),
        source: e,
    })?;

    let mut summary = WriteSummary::default();
    let result = write_image(
        &mut out,
        &mut root,
        source_dir.unwrap_or(Path::new("")),
        from,
        options,
        &mut summary,
        on_event,
    );

    match result {
        Ok(()) => Ok(summary),
        Err(e) => {
            drop(out);
            let _ = fs::remove_file(output);
            Err(e)
        }
    }
}

/// Scan a local directory into an AVL tree.
fn generate_avl_tree_local(
    dir: &Path,
    skip_system_update: bool,
    on_event: &mut dyn FnMut(Event<'_>),
) -> Result<Subdir> {
    let mut root: Tree = None;

    let entries = fs::read_dir(dir).map_err(|e| Error::ReadDir {
        path: dir.display().to_string(),
        source: e,
    })?;

    for entry in entries {
        let entry = entry.map_err(Error::Read)?;
        let filename = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let meta = fs::metadata(&path).map_err(Error::Read)?; // follows symlinks

        if skip_system_update && meta.is_dir() && filename.contains(SYSTEM_UPDATE) {
            continue;
        }

        if filename.len() > FILENAME_MAX_CHARS {
            (on_event)(Event::Warning(Warning::FilenameTooLong { path: &path }));
            continue;
        }

        let mut node = Node::new(filename);
        if meta.is_dir() {
            node.subdir = generate_avl_tree_local(&path, skip_system_update, on_event)?;
        } else if meta.is_file() {
            if meta.len() > u64::from(u32::MAX) {
                (on_event)(Event::Warning(Warning::FileTooLarge { path: &path }));
                continue;
            }
            node.file_size = meta.len() as u32;
        } else {
            continue;
        }

        if avl::insert(&mut root, node).is_err() {
            return Err(Error::DuplicateFilename {
                path: path.display().to_string(),
            });
        }
    }

    Ok(match root {
        Some(node) => Subdir::Tree(node),
        None => Subdir::Empty,
    })
}

/// Compute the byte size of every directory table (stored in the directory
/// node's file_size) and every entry's offset within its table.
fn calculate_directory_requirements(node: &mut Node) {
    match &mut node.subdir {
        Subdir::Tree(sub) => {
            let mut size = 0u32;
            calculate_directory_size(sub, &mut size);
            node.file_size = size;
            calculate_directory_requirements(sub);
        }
        Subdir::Empty => node.file_size = SECTOR_SIZE as u32,
        Subdir::File => {}
    }
    if let Some(l) = &mut node.left {
        calculate_directory_requirements(l);
    }
    if let Some(r) = &mut node.right {
        calculate_directory_requirements(r);
    }
}

/// Prefix walk over one directory's tree, packing entries into the table.
/// Entries are dword-aligned and never span a sector boundary.
fn calculate_directory_size(node: &mut Node, size: &mut u32) {
    let mut length = FILENAME_OFFSET + node.filename.len() as u32;
    length += (DWORD_SIZE as u32 - length % DWORD_SIZE as u32) % DWORD_SIZE as u32;

    if n_sectors(u64::from(*size) + u64::from(length)) > n_sectors(u64::from(*size)) {
        *size += (SECTOR_SIZE as u32 - *size % SECTOR_SIZE as u32) % SECTOR_SIZE as u32;
    }
    node.offset = *size;
    *size += length;

    if let Some(l) = &mut node.left {
        calculate_directory_size(l, size);
    }
    if let Some(r) = &mut node.right {
        calculate_directory_size(r, size);
    }
}

/// Assign start sectors: each directory gets sectors for its table followed
/// by its files, then its subdirectories are laid out depth-first.
fn calculate_directory_offsets(node: &mut Node, sector: &mut u32) -> Result<()> {
    match &mut node.subdir {
        Subdir::Empty => {
            node.start_sector = *sector;
            *sector = checked_add_sectors(*sector, 1)?;
        }
        Subdir::Tree(sub) => {
            node.start_sector = *sector;
            let dir_start = u64::from(*sector) * SECTOR_SIZE;
            *sector = checked_add_sectors(*sector, n_sectors(u64::from(node.file_size)))?;
            write_dir_start_and_file_positions(sub, dir_start, sector)?;
            calculate_directory_offsets(sub, sector)?;
        }
        Subdir::File => {}
    }
    if let Some(l) = &mut node.left {
        calculate_directory_offsets(l, sector)?;
    }
    if let Some(r) = &mut node.right {
        calculate_directory_offsets(r, sector)?;
    }
    Ok(())
}

fn write_dir_start_and_file_positions(
    node: &mut Node,
    dir_start: u64,
    sector: &mut u32,
) -> Result<()> {
    node.dir_start = dir_start;
    if matches!(node.subdir, Subdir::File) {
        node.start_sector = *sector;
        *sector = checked_add_sectors(*sector, n_sectors(u64::from(node.file_size)))?;
    }
    if let Some(l) = &mut node.left {
        write_dir_start_and_file_positions(l, dir_start, sector)?;
    }
    if let Some(r) = &mut node.right {
        write_dir_start_and_file_positions(r, dir_start, sector)?;
    }
    Ok(())
}

fn checked_add_sectors(sector: u32, add: u64) -> Result<u32> {
    u64::from(sector)
        .checked_add(add)
        .filter(|&s| s <= u64::from(u32::MAX))
        .map(|s| s as u32)
        .ok_or(Error::ImageTooLarge)
}

struct WriteContext<'a, 'e> {
    out: &'a mut File,
    /// Source image for rewrite mode; None means files come from disk.
    from: Option<(&'a mut File, u64)>,
    /// Current local directory (create mode).
    local_dir: PathBuf,
    media_enable: bool,
    summary: &'a mut WriteSummary,
    sink: &'a mut (dyn FnMut(Event<'_>) + 'e),
    buf: Vec<u8>,
}

fn write_image(
    out: &mut File,
    root: &mut Node,
    root_path: &Path,
    mut from: Option<(&mut File, u64)>,
    options: &CreateOptions,
    summary: &mut WriteSummary,
    on_event: &mut dyn FnMut(Event<'_>),
) -> Result<()> {
    // Header sector block: zero the whole area up to the header, then the
    // magic, root directory sector + size, file time, unused area, and the
    // trailing magic.
    out.write_all(&vec![0u8; HEADER_OFFSET as usize])
        .map_err(Error::Write)?;
    out.write_all(HEADER_DATA).map_err(Error::Write)?;
    out.write_all(&root.start_sector.to_le_bytes())
        .map_err(Error::Write)?;
    out.write_all(&root.file_size.to_le_bytes())
        .map_err(Error::Write)?;

    let filetime: [u8; 8] = match &mut from {
        Some((src, disc_offset)) => {
            // Preserve the source image's timestamp.
            src.seek(SeekFrom::Start(
                HEADER_OFFSET + HEADER_DATA.len() as u64 + 4 + 4 + *disc_offset,
            ))
            .map_err(Error::Seek)?;
            let mut ft = [0u8; 8];
            src.read_exact(&mut ft).map_err(Error::Read)?;
            ft
        }
        None => filetime_now(),
    };
    out.write_all(&filetime).map_err(Error::Write)?;
    out.write_all(&[0u8; UNUSED_SIZE]).map_err(Error::Write)?;
    out.write_all(HEADER_DATA).map_err(Error::Write)?;

    {
        let mut ctx = WriteContext {
            out,
            from,
            local_dir: root_path.to_path_buf(),
            media_enable: options.media_enable_patching,
            summary,
            sink: on_event,
            buf: vec![0u8; READWRITE_BUFFER_SIZE],
        };
        write_tree(root, &mut ctx, None)?;
    }

    // Pad the image to the xbox's 64 KiB file modulus.
    let pos = out.seek(SeekFrom::End(0)).map_err(Error::Seek)?;
    let pad = (FILE_MODULUS - pos % FILE_MODULUS) % FILE_MODULUS;
    if pad > 0 {
        out.write_all(&vec![0u8; pad as usize])
            .map_err(Error::Write)?;
    }

    write_volume_descriptors(out, ((pos + pad) / SECTOR_SIZE) as u32)?;

    out.seek(SeekFrom::Start(OPTIMIZED_TAG_OFFSET))
        .map_err(Error::Seek)?;
    out.write_all(&optimized_tag()).map_err(Error::Write)?;

    Ok(())
}

/// Write one directory: its files, its subdirectories, then its table.
/// `parent_path` is None only for the (synthetic) root node.
fn write_tree(node: &mut Node, ctx: &mut WriteContext, parent_path: Option<&str>) -> Result<()> {
    if !node.is_dir() {
        return Ok(());
    }

    let path = match parent_path {
        Some(p) => format!("{p}{}{PATH_CHAR}", node.filename),
        None => PATH_CHAR.to_string(),
    };
    (ctx.sink)(Event::AddingDirectory { path: &path });

    let is_root = parent_path.is_none();
    let start = u64::from(node.start_sector) * SECTOR_SIZE;

    match &mut node.subdir {
        Subdir::Tree(sub) => {
            let enter_local = ctx.from.is_none() && !is_root;
            if enter_local {
                ctx.local_dir.push(&node.filename);
            }

            write_files(sub, ctx, &path)?;
            write_subtrees(sub, ctx, &path)?;

            ctx.out.seek(SeekFrom::Start(start)).map_err(Error::Seek)?;
            write_directory(sub, ctx.out)?;
            let pos = ctx.out.stream_position().map_err(Error::Seek)?;
            write_pad(ctx.out, (SECTOR_SIZE - pos % SECTOR_SIZE) % SECTOR_SIZE)?;

            if enter_local {
                ctx.local_dir.pop();
            }
        }
        Subdir::Empty => {
            // An empty directory is a single padding sector.
            ctx.out.seek(SeekFrom::Start(start)).map_err(Error::Seek)?;
            write_pad(ctx.out, SECTOR_SIZE)?;
        }
        Subdir::File => unreachable!(),
    }

    Ok(())
}

/// Prefix walk calling write_file on every file node of one directory.
fn write_files(node: &mut Node, ctx: &mut WriteContext, dir_path: &str) -> Result<()> {
    write_file(node, ctx, dir_path)?;
    if let Some(l) = &mut node.left {
        write_files(l, ctx, dir_path)?;
    }
    if let Some(r) = &mut node.right {
        write_files(r, ctx, dir_path)?;
    }
    Ok(())
}

/// Prefix walk calling write_tree on every directory node of one directory.
fn write_subtrees(node: &mut Node, ctx: &mut WriteContext, dir_path: &str) -> Result<()> {
    write_tree(node, ctx, Some(dir_path))?;
    if let Some(l) = &mut node.left {
        write_subtrees(l, ctx, dir_path)?;
    }
    if let Some(r) = &mut node.right {
        write_subtrees(r, ctx, dir_path)?;
    }
    Ok(())
}

fn write_file(node: &mut Node, ctx: &mut WriteContext, dir_path: &str) -> Result<()> {
    if node.is_dir() {
        return Ok(());
    }

    ctx.out
        .seek(SeekFrom::Start(u64::from(node.start_sector) * SECTOR_SIZE))
        .map_err(Error::Seek)?;

    (ctx.sink)(Event::AddingFileBegin {
        dir: dir_path,
        name: &node.filename,
        size: node.file_size,
    });

    let is_xbe = ctx.media_enable
        && node.filename.len() >= 4
        && node.filename[node.filename.len() - 4..].eq_ignore_ascii_case(".xbe");

    let written = copy_file_data(node, ctx, is_xbe);
    (ctx.sink)(Event::AddingFileEnd {
        ok: written.is_ok(),
    });
    let written = written?;

    if written != node.file_size {
        (ctx.sink)(Event::Warning(Warning::SourceFileTruncated {
            name: &node.filename,
            expected: node.file_size,
            actual: written,
        }));
        node.file_size = written;
    }

    // Pad the final sector.
    let pad = (SECTOR_SIZE - u64::from(node.file_size) % SECTOR_SIZE) % SECTOR_SIZE;
    write_pad(ctx.out, pad)?;

    ctx.summary.files += 1;
    ctx.summary.bytes += u64::from(node.file_size);

    Ok(())
}

/// Copy the file's data into the image, patching the media check in .xbe
/// files. The patcher keeps a 7-byte carry between chunks so the 8-byte
/// pattern is found even when it straddles a buffer boundary. Returns the
/// number of bytes actually written.
fn copy_file_data(node: &Node, ctx: &mut WriteContext, is_xbe: bool) -> Result<u32> {
    let mut src_local;
    let src: &mut File = match &mut ctx.from {
        None => {
            let path = ctx.local_dir.join(&node.filename);
            src_local = File::open(&path).map_err(|e| Error::Open {
                path: path.display().to_string(),
                source: e,
            })?;
            &mut src_local
        }
        Some((src, disc_offset)) => {
            src.seek(SeekFrom::Start(
                u64::from(node.old_start_sector) * SECTOR_SIZE + *disc_offset,
            ))
            .map_err(Error::Seek)?;
            src
        }
    };

    let mut remaining = node.file_size as usize;
    let mut carry = 0usize;

    while remaining > 0 {
        let want = remaining.min(ctx.buf.len() - carry);
        let n = read_full(src, &mut ctx.buf[carry..carry + want]).map_err(Error::Read)?;
        if n == 0 {
            break; // source shorter than expected
        }
        remaining -= n;
        let total = carry + n;

        if is_xbe {
            media::patch_media_enable(&mut ctx.buf[..total]);
            if remaining > 0 {
                // Hold back the last pattern-length - 1 bytes for the next
                // round so a straddling match is still found.
                let keep = (MEDIA_ENABLE_PATTERN.len() - 1).min(total);
                ctx.out
                    .write_all(&ctx.buf[..total - keep])
                    .map_err(Error::Write)?;
                ctx.buf.copy_within(total - keep..total, 0);
                carry = keep;
                continue;
            }
        }
        ctx.out.write_all(&ctx.buf[..total]).map_err(Error::Write)?;
        carry = 0;
    }

    if carry > 0 {
        ctx.out.write_all(&ctx.buf[..carry]).map_err(Error::Write)?;
    }

    Ok((node.file_size as usize - remaining) as u32)
}

/// Prefix walk writing one directory's table entries, with 0xff padding
/// between entries where sector-boundary alignment left gaps.
fn write_directory(node: &mut Node, out: &mut File) -> Result<()> {
    let table_pad = (SECTOR_SIZE as u32 - node.file_size % SECTOR_SIZE as u32) % SECTOR_SIZE as u32;
    let file_size = if node.is_dir() {
        node.file_size + table_pad
    } else {
        node.file_size
    };
    let attributes = if node.is_dir() {
        ATTRIBUTE_DIR
    } else {
        ATTRIBUTE_ARC
    };

    let l_offset = child_offset(&node.left)?;
    let r_offset = child_offset(&node.right)?;

    let pos = out.stream_position().map_err(Error::Seek)?;
    let target = node.dir_start + u64::from(node.offset);
    write_pad(out, target - pos)?;

    out.write_all(&l_offset.to_le_bytes())
        .map_err(Error::Write)?;
    out.write_all(&r_offset.to_le_bytes())
        .map_err(Error::Write)?;
    out.write_all(&node.start_sector.to_le_bytes())
        .map_err(Error::Write)?;
    out.write_all(&file_size.to_le_bytes())
        .map_err(Error::Write)?;
    out.write_all(&[attributes, node.filename.len() as u8])
        .map_err(Error::Write)?;
    out.write_all(node.filename.as_bytes())
        .map_err(Error::Write)?;

    if let Some(l) = &mut node.left {
        write_directory(l, out)?;
    }
    if let Some(r) = &mut node.right {
        write_directory(r, out)?;
    }
    Ok(())
}

fn child_offset(child: &Tree) -> Result<u16> {
    match child {
        None => Ok(0),
        Some(n) => {
            u16::try_from(n.offset / DWORD_SIZE as u32).map_err(|_| Error::DirectoryTableTooLarge)
        }
    }
}

fn write_pad(out: &mut File, len: u64) -> Result<()> {
    const CHUNK: [u8; SECTOR_SIZE as usize] = [PAD_BYTE; SECTOR_SIZE as usize];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(CHUNK.len() as u64) as usize;
        out.write_all(&CHUNK[..n]).map_err(Error::Write)?;
        remaining -= n as u64;
    }
    Ok(())
}

// ECMA-119 volume descriptors so burning software auto-detects the format.
const ECMA_119_DATA_AREA_START: u64 = 0x8000;
const ECMA_119_VOLUME_SPACE_SIZE: u64 = ECMA_119_DATA_AREA_START + 80;
const ECMA_119_VOLUME_SET_SIZE: u64 = ECMA_119_DATA_AREA_START + 120;
const ECMA_119_VOLUME_SET_IDENTIFIER: u64 = ECMA_119_DATA_AREA_START + 190;
const ECMA_119_VOLUME_CREATION_DATE: u64 = ECMA_119_DATA_AREA_START + 813;

/// Assumes the image block from 0x8000 to 0x8808 was zeroed beforehand
/// (the header write takes care of that).
fn write_volume_descriptors(out: &mut File, total_sectors: u32) -> Result<()> {
    // 17-byte ECMA-119 date-time field: 16 ASCII digits + a zero offset byte.
    const DATE: [u8; 17] = *b"0000000000000000\0";

    out.seek(SeekFrom::Start(ECMA_119_DATA_AREA_START))
        .map_err(Error::Seek)?;
    out.write_all(b"\x01CD001\x01").map_err(Error::Write)?;

    out.seek(SeekFrom::Start(ECMA_119_VOLUME_SPACE_SIZE))
        .map_err(Error::Seek)?;
    out.write_all(&total_sectors.to_le_bytes())
        .map_err(Error::Write)?;
    out.write_all(&total_sectors.to_be_bytes())
        .map_err(Error::Write)?;

    out.seek(SeekFrom::Start(ECMA_119_VOLUME_SET_SIZE))
        .map_err(Error::Seek)?;
    out.write_all(b"\x01\x00\x00\x01\x01\x00\x00\x01\x00\x08\x08\x00")
        .map_err(Error::Write)?;

    out.seek(SeekFrom::Start(ECMA_119_VOLUME_SET_IDENTIFIER))
        .map_err(Error::Seek)?;
    let spaces =
        vec![0x20u8; (ECMA_119_VOLUME_CREATION_DATE - ECMA_119_VOLUME_SET_IDENTIFIER) as usize];
    out.write_all(&spaces).map_err(Error::Write)?;
    for _ in 0..4 {
        out.write_all(&DATE).map_err(Error::Write)?;
    }
    out.write_all(&[0x01]).map_err(Error::Write)?;

    out.seek(SeekFrom::Start(ECMA_119_DATA_AREA_START + SECTOR_SIZE))
        .map_err(Error::Seek)?;
    out.write_all(b"\xffCD001\x01").map_err(Error::Write)?;

    Ok(())
}
