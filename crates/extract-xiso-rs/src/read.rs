//! The read side: opening and verifying images, walking directory tables,
//! listing and extraction.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::avl::{self, Node, Subdir, Tree};
use crate::error::{Error, Result};
use crate::event::{Event, Warning};
use crate::format::{
    ATTRIBUTE_DIR, DWORD_SIZE, FILENAME_OFFSET, GLOBAL_LSEEK_OFFSET, HEADER_DATA, HEADER_OFFSET,
    OPTIMIZED_TAG_LENGTH, OPTIMIZED_TAG_OFFSET, OPTIMIZED_TAG_PREFIX, PAD_SHORT, PATH_CHAR,
    READWRITE_BUFFER_SIZE, SECTOR_SIZE, XGD1_LSEEK_OFFSET, XGD3_LSEEK_OFFSET, read_full,
};

/// Name of the folder skipped by
/// [`ExtractOptions::skip_system_update`].
pub const SYSTEM_UPDATE: &str = "$SystemUpdate";

/// Check whether the file at `path` carries the optimized-image tag
/// written by this tool (or the original `extract-xiso`).
///
/// # Errors
///
/// Fails if the file cannot be opened or is shorter than the tag offset.
pub fn is_image_optimized(path: impl AsRef<Path>) -> Result<bool> {
    let path = path.as_ref();
    let mut f = File::open(path).map_err(|e| Error::Open {
        path: path.display().to_string(),
        source: e,
    })?;
    f.seek(SeekFrom::Start(OPTIMIZED_TAG_OFFSET))
        .map_err(Error::Seek)?;
    let mut tag = [0u8; OPTIMIZED_TAG_LENGTH];
    f.read_exact(&mut tag).map_err(Error::Read)?;
    Ok(tag.starts_with(OPTIMIZED_TAG_PREFIX))
}

/// One entry of an image's directory tree, as returned by
/// [`XisoImage::entries`].
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Names of the directories containing this entry, from the root down
    /// (empty for entries in the root directory).
    pub dir_components: Vec<String>,
    /// The entry's own name.
    pub name: String,
    /// File size in bytes. For directories this is the size of the
    /// directory table.
    pub size: u32,
    /// Whether the entry is a directory.
    pub is_directory: bool,
    /// First sector of the entry's data within the game partition.
    pub start_sector: u32,
}

impl FileEntry {
    /// The entry's full path within the image, joined with `sep`.
    pub fn path_with_separator(&self, sep: char) -> String {
        let mut out = String::new();
        for c in &self.dir_components {
            out.push_str(c);
            out.push(sep);
        }
        out.push_str(&self.name);
        out
    }
}

/// Options for [`XisoImage::extract_to`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ExtractOptions {
    /// Skip the `$SystemUpdate` folder (the CLI's `-s` flag).
    pub skip_system_update: bool,
}

impl ExtractOptions {
    /// Return options with `$SystemUpdate` skipping set to `enabled`.
    pub fn with_skip_system_update(mut self, enabled: bool) -> Self {
        self.skip_system_update = enabled;
        self
    }
}

/// Totals reported by [`XisoImage::extract_to`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ExtractSummary {
    /// Number of files extracted.
    pub files: u32,
    /// Number of bytes extracted.
    pub bytes: u64,
}

/// An open, verified XDVDFS image.
///
/// Opening probes the four known disc layouts (plain game partition,
/// redump-style full dump, XGD3, XGD1) and remembers the resulting
/// global offset, so all other methods work on any of them.
///
/// ```no_run
/// use extract_xiso::XisoImage;
///
/// # fn main() -> Result<(), extract_xiso::Error> {
/// let mut image = XisoImage::open("halo.iso")?;
/// for entry in image.entries()? {
///     println!("{} ({} bytes)", entry.path_with_separator('/'), entry.size);
/// }
/// # Ok(())
/// # }
/// ```
pub struct XisoImage {
    pub(crate) file: File,
    pub(crate) disc_offset: u64,
    root_dir_sector: u32,
    root_dir_size: u32,
    optimized: bool,
    name: String,
    source_path: std::path::PathBuf,
}

impl XisoImage {
    /// Open and verify an image.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be opened, no XDVDFS header is found at
    /// any known layout ([`Error::NotAnXiso`]), or the header's trailing
    /// magic is damaged ([`Error::CorruptImage`]).
    pub fn open(path: impl AsRef<Path>) -> Result<XisoImage> {
        let path = path.as_ref();
        let source_path = fs::canonicalize(path).map_err(|e| Error::Open {
            path: path.display().to_string(),
            source: e,
        })?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());

        let mut file = File::open(path).map_err(|e| Error::Open {
            path: path.display().to_string(),
            source: e,
        })?;

        let mut magic = [0u8; HEADER_DATA.len()];
        let mut disc_offset = None;
        for offset in [0, GLOBAL_LSEEK_OFFSET, XGD3_LSEEK_OFFSET, XGD1_LSEEK_OFFSET] {
            file.seek(SeekFrom::Start(HEADER_OFFSET + offset))
                .map_err(Error::Seek)?;
            if file.read_exact(&mut magic).is_ok() && magic == *HEADER_DATA {
                disc_offset = Some(offset);
                break;
            }
        }
        let Some(disc_offset) = disc_offset else {
            return Err(Error::NotAnXiso { name });
        };

        // The root directory sector and size follow the header magic.
        let mut dword = [0u8; 4];
        file.read_exact(&mut dword).map_err(Error::Read)?;
        let root_dir_sector = u32::from_le_bytes(dword);
        file.read_exact(&mut dword).map_err(Error::Read)?;
        let root_dir_size = u32::from_le_bytes(dword);

        // Skip the file time and unused area, then check the trailing magic.
        file.seek(SeekFrom::Current(
            (crate::format::FILETIME_SIZE + crate::format::UNUSED_SIZE) as i64,
        ))
        .map_err(Error::Seek)?;
        file.read_exact(&mut magic).map_err(Error::Read)?;
        if magic != *HEADER_DATA {
            return Err(Error::CorruptImage { name });
        }

        // The optimized tag decides whether the linked-list compatibility
        // heuristic is needed when walking directory tables. Like the
        // original tool, the tag is always at the start of the file.
        file.seek(SeekFrom::Start(OPTIMIZED_TAG_OFFSET))
            .map_err(Error::Seek)?;
        let mut tag = [0u8; OPTIMIZED_TAG_LENGTH];
        let optimized = file.read_exact(&mut tag).is_ok() && tag.starts_with(OPTIMIZED_TAG_PREFIX);

        Ok(XisoImage {
            file,
            disc_offset,
            root_dir_sector,
            root_dir_size,
            optimized,
            name,
            source_path,
        })
    }

    /// The image file's name (used in error messages).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Global byte offset of the game partition within the file
    /// (0 for plain images; nonzero for redump/XGD1/XGD3 dumps).
    pub fn disc_offset(&self) -> u64 {
        self.disc_offset
    }

    /// Whether the image carries the optimized tag written by this tool.
    pub fn is_optimized(&self) -> bool {
        self.optimized
    }

    /// Whether the image contains no files at all.
    pub fn is_empty(&self) -> bool {
        self.root_dir_sector == 0 && self.root_dir_size == 0
    }

    fn root_dir_start(&self) -> u64 {
        u64::from(self.root_dir_sector) * SECTOR_SIZE + self.disc_offset
    }

    /// Whether the root directory should be walked at all (mirrors the
    /// original tool, which skips traversal when either root field is 0).
    fn has_root(&self) -> bool {
        self.root_dir_sector != 0 && self.root_dir_size != 0
    }

    /// List every entry in the image, in the on-disc traversal order
    /// (case-insensitive alphabetical within each directory, parents
    /// before children).
    pub fn entries(&mut self) -> Result<Vec<FileEntry>> {
        if !self.has_root() {
            return Ok(Vec::new());
        }
        let mut noop = |_: Event<'_>| {};
        let mut ctx = TraverseCtx {
            file: &mut self.file,
            disc_offset: self.disc_offset,
            skip_systemupdate: false,
            sink: &mut noop,
            buf: Vec::new(),
            files: 0,
            bytes: 0,
            entries: Vec::new(),
            components: Vec::new(),
            tables: HashSet::new(),
        };
        let dir_start = u64::from(self.root_dir_sector) * SECTOR_SIZE + self.disc_offset;
        traverse_dir(
            &mut ctx,
            dir_start,
            self.root_dir_size,
            "",
            None,
            TraverseState {
                mode: TraverseMode::Collect,
                ll_compat: !self.optimized,
                depth: 0,
            },
        )?;
        Ok(ctx.entries)
    }

    /// Extract the image's contents into `dir` (which must already
    /// exist). Subdirectories are created as encountered; progress is
    /// reported through `on_event`.
    ///
    /// Returns the number of files and bytes extracted.
    ///
    /// ```no_run
    /// use extract_xiso::{ExtractOptions, XisoImage};
    ///
    /// # fn main() -> Result<(), extract_xiso::Error> {
    /// let mut image = XisoImage::open("halo.iso")?;
    /// std::fs::create_dir_all("halo")?;
    /// let summary =
    ///     image.extract_to("halo".as_ref(), &ExtractOptions::default(), &mut |_| {})?;
    /// println!("{} files, {} bytes", summary.files, summary.bytes);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Fails on I/O errors, when a directory to be created already
    /// exists, or when the image contains entry names that would escape
    /// the destination directory ([`Error::InvalidFilename`]).
    pub fn extract_to(
        &mut self,
        dir: &Path,
        options: &ExtractOptions,
        on_event: &mut dyn FnMut(Event<'_>),
    ) -> Result<ExtractSummary> {
        if !self.has_root() {
            return Ok(ExtractSummary::default());
        }
        let dir_start = self.root_dir_start();
        let ll_compat = !self.optimized;
        let mut ctx = TraverseCtx {
            file: &mut self.file,
            disc_offset: self.disc_offset,
            skip_systemupdate: options.skip_system_update,
            sink: on_event,
            buf: vec![0u8; READWRITE_BUFFER_SIZE],
            files: 0,
            bytes: 0,
            entries: Vec::new(),
            components: Vec::new(),
            tables: HashSet::new(),
        };
        traverse_dir(
            &mut ctx,
            dir_start,
            self.root_dir_size,
            "",
            Some(dir),
            TraverseState {
                mode: TraverseMode::Extract,
                ll_compat,
                depth: 0,
            },
        )?;
        Ok(ExtractSummary {
            files: ctx.files,
            bytes: ctx.bytes,
        })
    }

    /// Capture the image's directory tree for rewriting.
    pub(crate) fn capture_tree(&mut self, skip_system_update: bool) -> Result<Tree> {
        if !self.has_root() {
            return Ok(None);
        }
        let dir_start = self.root_dir_start();
        let mut noop = |_: Event<'_>| {};
        let mut ctx = TraverseCtx {
            file: &mut self.file,
            disc_offset: self.disc_offset,
            skip_systemupdate: skip_system_update,
            sink: &mut noop,
            buf: Vec::new(),
            files: 0,
            bytes: 0,
            entries: Vec::new(),
            components: Vec::new(),
            tables: HashSet::new(),
        };
        traverse_dir(
            &mut ctx,
            dir_start,
            self.root_dir_size,
            "",
            None,
            TraverseState {
                mode: TraverseMode::Generate,
                ll_compat: !self.optimized,
                depth: 0,
            },
        )
    }

    pub(crate) fn source_path(&self) -> &Path {
        &self.source_path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraverseMode {
    Extract,
    Collect,
    /// Build an AVL tree of the image contents (rewrite mode).
    Generate,
}

#[derive(Debug, Clone, Copy)]
struct TraverseState {
    mode: TraverseMode,
    ll_compat: bool,
    depth: usize,
}

struct TraverseCtx<'a, 'e> {
    file: &'a mut File,
    disc_offset: u64,
    skip_systemupdate: bool,
    sink: &'a mut (dyn FnMut(Event<'_>) + 'e),
    buf: Vec<u8>,
    files: u32,
    bytes: u64,
    entries: Vec<FileEntry>,
    components: Vec<String>,
    /// Directory-table starts already traversed, used to reject cycles and
    /// aliasing between crafted directory entries.
    tables: HashSet<u64>,
}

/// One parsed directory entry.
struct RawEntry {
    l_offset: u16,
    r_offset: u16,
    start_sector: u32,
    file_size: u32,
    attributes: u8,
    name: String,
    /// Absolute stream position just past this entry (used by the
    /// linked-list compatibility heuristic).
    pos_after: u64,
}

/// In-order traversal of one directory table. In Generate mode the entries
/// are returned as an AVL tree (None meaning the directory is empty).
///
/// The traversal is iterative over the binary tree encoded in the table
/// (an explicit stack instead of the C original's goto/parent-pointer
/// scheme), so hostile images with degenerate trees cannot overflow the
/// call stack; recursion only happens per directory nesting level.
fn traverse_dir(
    ctx: &mut TraverseCtx,
    dir_start: u64,
    dir_size: u32,
    prefix: &str,
    local_dir: Option<&Path>,
    mut state: TraverseState,
) -> Result<Tree> {
    const MAX_DIRECTORY_DEPTH: usize = 256;
    if state.depth > MAX_DIRECTORY_DEPTH || dir_size < 2 {
        return Err(Error::CorruptDirectoryTree);
    }
    if !ctx.tables.insert(dir_start) {
        return Err(Error::CorruptDirectoryTree);
    }

    let mut tree: Tree = None;
    let mut stack: Vec<RawEntry> = Vec::new();
    let mut visited = HashSet::new();
    let mut offset: u64 = 0; // byte offset of the next entry within the table

    'read: loop {
        // Read the entry at dir_start + offset, skipping sector padding.
        let entry = loop {
            if offset >= u64::from(dir_size) || !visited.insert(offset) {
                return Err(Error::CorruptDirectoryTree);
            }
            ctx.file
                .seek(SeekFrom::Start(
                    dir_start
                        .checked_add(offset)
                        .ok_or(Error::CorruptDirectoryTree)?,
                ))
                .map_err(Error::Seek)?;
            let mut hdr = [0u8; FILENAME_OFFSET as usize];
            ctx.file.read_exact(&mut hdr[..2]).map_err(Error::Read)?;
            let l_offset = u16::from_le_bytes([hdr[0], hdr[1]]);

            if l_offset == PAD_SHORT {
                if offset == 0 {
                    // The table starts with padding: the directory is empty.
                    return Ok(None);
                }
                // Entries never span sectors; skip to the next sector.
                offset += SECTOR_SIZE - offset % SECTOR_SIZE;
                if offset >= u64::from(dir_size) {
                    return Err(Error::CorruptDirectoryTree);
                }
                continue;
            }

            ctx.file.read_exact(&mut hdr[2..]).map_err(Error::Read)?;
            let r_offset = u16::from_le_bytes([hdr[2], hdr[3]]);
            let start_sector = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
            let file_size = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
            let attributes = hdr[12];
            let name_len = hdr[13] as usize;

            let entry_end = offset
                .checked_add(FILENAME_OFFSET as u64)
                .and_then(|v| v.checked_add(name_len as u64))
                .ok_or(Error::CorruptDirectoryTree)?;
            if entry_end > u64::from(dir_size) {
                return Err(Error::CorruptDirectoryTree);
            }

            let mut name_buf = vec![0u8; name_len];
            ctx.file.read_exact(&mut name_buf).map_err(Error::Read)?;
            let name = String::from_utf8_lossy(&name_buf).into_owned();

            // Security check (path traversal via crafted images).
            if name.is_empty()
                || name == "."
                || name == ".."
                || name.contains('/')
                || name.contains('\\')
            {
                return Err(Error::InvalidFilename { name });
            }

            break RawEntry {
                l_offset,
                r_offset,
                start_sector,
                file_size,
                attributes,
                name,
                pos_after: dir_start
                    .checked_add(entry_end)
                    .ok_or(Error::CorruptDirectoryTree)?,
            };
        };

        if entry.l_offset != 0 {
            // A real tree: disable the linked-list workaround.
            state.ll_compat = false;
            offset = u64::from(entry.l_offset) * DWORD_SIZE;
            if offset >= u64::from(dir_size) {
                return Err(Error::CorruptDirectoryTree);
            }
            stack.push(entry);
            continue 'read;
        }

        let mut cur = entry;
        loop {
            process_entry(ctx, &cur, prefix, local_dir, &mut tree, state)?;

            if cur.r_offset != 0 {
                let mut target = u64::from(cur.r_offset) * DWORD_SIZE;
                if state.ll_compat {
                    // Some tools emit tables that are simple linked lists
                    // with bogus forward offsets; clamp jumps to the next
                    // sector boundary.
                    let cur_sector = (cur.pos_after - dir_start) / SECTOR_SIZE;
                    if target / SECTOR_SIZE > cur_sector {
                        target = (cur_sector + 1) * SECTOR_SIZE;
                    }
                }
                if target >= u64::from(dir_size) {
                    return Err(Error::CorruptDirectoryTree);
                }
                offset = target;
                continue 'read;
            }

            match stack.pop() {
                Some(parent) => cur = parent,
                None => break 'read,
            }
        }
    }

    Ok(tree)
}

fn process_entry(
    ctx: &mut TraverseCtx,
    entry: &RawEntry,
    prefix: &str,
    local_dir: Option<&Path>,
    tree: &mut Tree,
    state: TraverseState,
) -> Result<()> {
    let is_dir = entry.attributes & ATTRIBUTE_DIR != 0;
    let sub_start = u64::from(entry.start_sector) * SECTOR_SIZE + ctx.disc_offset;

    if state.mode == TraverseMode::Generate
        && is_dir
        && ctx.skip_systemupdate
        && entry.name.contains(SYSTEM_UPDATE)
    {
        return Ok(());
    }

    match state.mode {
        TraverseMode::Generate => {
            let subdir = if is_dir {
                if entry.file_size > 0 {
                    match traverse_dir(
                        ctx,
                        sub_start,
                        entry.file_size,
                        prefix,
                        None,
                        TraverseState {
                            depth: state.depth + 1,
                            ..state
                        },
                    )? {
                        Some(root) => Subdir::Tree(root),
                        None => Subdir::Empty,
                    }
                } else {
                    Subdir::Empty
                }
            } else {
                Subdir::File
            };
            let mut node = Node::new(entry.name.clone());
            node.file_size = entry.file_size;
            node.old_start_sector = entry.start_sector;
            node.subdir = subdir;
            if avl::insert(tree, node).is_err() {
                return Err(Error::CorruptDirectoryTree);
            }
        }

        TraverseMode::Collect => {
            ctx.entries.push(FileEntry {
                dir_components: ctx.components.clone(),
                name: entry.name.clone(),
                size: entry.file_size,
                is_directory: is_dir,
                start_sector: entry.start_sector,
            });
            if is_dir && entry.file_size > 0 {
                ctx.components.push(entry.name.clone());
                let child_prefix = format!("{prefix}{}{PATH_CHAR}", entry.name);
                traverse_dir(
                    ctx,
                    sub_start,
                    entry.file_size,
                    &child_prefix,
                    None,
                    TraverseState {
                        depth: state.depth + 1,
                        ..state
                    },
                )?;
                ctx.components.pop();
            }
        }

        TraverseMode::Extract => {
            if is_dir {
                if ctx.skip_systemupdate && entry.name.contains(SYSTEM_UPDATE) {
                    return Ok(());
                }
                let child_prefix = format!("{prefix}{}{PATH_CHAR}", entry.name);
                let dir = local_dir
                    .expect("extract mode always has a target directory")
                    .join(&entry.name);
                fs::create_dir(&dir).map_err(|e| Error::CreateDir {
                    path: dir.display().to_string(),
                    source: e,
                })?;
                (ctx.sink)(Event::CreatingDirectory {
                    path: &child_prefix,
                });
                if entry.file_size > 0 {
                    traverse_dir(
                        ctx,
                        sub_start,
                        entry.file_size,
                        &child_prefix,
                        Some(&dir),
                        TraverseState {
                            depth: state.depth + 1,
                            ..state
                        },
                    )?;
                }
            } else {
                if ctx.skip_systemupdate && prefix.contains(SYSTEM_UPDATE) {
                    return Ok(());
                }
                let extracted = extract_file(
                    ctx,
                    entry,
                    local_dir.expect("extract mode always has a target directory"),
                    prefix,
                )?;
                ctx.files += 1;
                ctx.bytes += extracted;
            }
        }
    }

    Ok(())
}

/// Copy one file out of the image. Returns the number of bytes actually
/// extracted (less than the recorded size if the image is truncated).
fn extract_file(
    ctx: &mut TraverseCtx,
    entry: &RawEntry,
    local_dir: &Path,
    prefix: &str,
) -> Result<u64> {
    let out_path = local_dir.join(&entry.name);
    let mut out = File::create(&out_path).map_err(|e| Error::Open {
        path: out_path.display().to_string(),
        source: e,
    })?;

    ctx.file
        .seek(SeekFrom::Start(
            u64::from(entry.start_sector) * SECTOR_SIZE + ctx.disc_offset,
        ))
        .map_err(Error::Seek)?;

    let size = u64::from(entry.file_size);
    let mut done: u64 = 0;

    if size == 0 {
        (ctx.sink)(Event::ExtractProgress {
            dir: prefix,
            name: &entry.name,
            size: 0,
            done: 0,
        });
    } else {
        while done < size {
            let want = (size - done).min(ctx.buf.len() as u64) as usize;
            let n = read_full(ctx.file, &mut ctx.buf[..want]).map_err(Error::Read)?;
            if n == 0 {
                break;
            }
            out.write_all(&ctx.buf[..n]).map_err(Error::Write)?;
            done += n as u64;
            (ctx.sink)(Event::ExtractProgress {
                dir: prefix,
                name: &entry.name,
                size: entry.file_size,
                done,
            });
        }
        if done < size {
            (ctx.sink)(Event::Warning(Warning::ImageFileTruncated {
                name: &entry.name,
                expected: entry.file_size,
                actual: done,
            }));
        }
    }
    (ctx.sink)(Event::ExtractFileEnd);

    Ok(done)
}
