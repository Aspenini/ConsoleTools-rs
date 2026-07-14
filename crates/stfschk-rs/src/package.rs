use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs,
    io::Read,
    path::Path,
};

use sha1::{Digest, Sha1};

use crate::{
    DirectoryEntry, Error, Header, InstallerMetadata, Metadata, PackageKind, VolumeDescriptor,
    error::slice,
    format::{METADATA_OFFSET, hex, u24_be},
};

pub const BLOCK_SIZE: u64 = 0x1000;
const HASH_ENTRIES_PER_BLOCK: u32 = 0xAA;
const DATA_BLOCKS_PER_HASH_LEVEL: [u32; 3] = [0xAA, 0x70E4, 0x4AF768];

/// Returns whether the first four bytes contain a supported XContent magic.
pub fn is_package(data: &[u8]) -> bool {
    data.get(..4)
        .and_then(|magic| magic.try_into().ok())
        .is_some_and(|magic| PackageKind::parse(magic).is_ok())
}

/// A directory entry plus its location and resolved path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileRecord {
    pub entry: DirectoryEntry,
    pub directory_offset: u64,
    pub path: String,
}

impl FileRecord {
    pub fn is_directory(&self) -> bool {
        self.entry.is_directory()
    }

    pub fn size(&self) -> u64 {
        u64::from(self.entry.file_size)
    }
}

/// An owned, parsed STFS/XContent package.
#[derive(Clone, Debug)]
pub struct StfsPackage {
    data: Vec<u8>,
    pub header: Header,
    pub metadata: Metadata,
    pub installer_metadata: Option<InstallerMetadata>,
    pub volume_descriptor: VolumeDescriptor,
    pub content_id_valid: bool,
    pub files: Vec<FileRecord>,
    position: u64,
    aligned_header_size: u64,
    blocks_per_hash_table: u64,
    block_steps: [u64; 2],
}

impl StfsPackage {
    /// Reads and parses a package from disk.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::parse(fs::read(path)?)
    }

    /// Reads and parses a package from an arbitrary reader.
    pub fn from_reader(mut reader: impl Read) -> Result<Self, Error> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Self::parse(data)
    }

    /// Parses an owned XContent package image.
    pub fn parse(data: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let data = data.into();
        let header = Header::parse(&data)?;
        if header.size_of_headers == 0 {
            return Err(Error::NotStfs);
        }
        let (metadata, volume_descriptor) = Metadata::parse(&data)?;
        if metadata.volume_type != 0 {
            return Err(Error::UnsupportedSvod);
        }
        if volume_descriptor.descriptor_length != 0x24 {
            return Err(Error::InvalidDescriptorLength(
                volume_descriptor.descriptor_length,
            ));
        }

        let aligned_header_size = u64::from(header.size_of_headers)
            .checked_add(BLOCK_SIZE - 1)
            .ok_or(Error::ArithmeticOverflow("aligned header size"))?
            / BLOCK_SIZE
            * BLOCK_SIZE;
        let blocks_per_hash_table = if volume_descriptor.read_only_format() {
            1
        } else {
            2
        };
        let block_steps = if volume_descriptor.read_only_format() {
            [0xAB, 0x718F]
        } else {
            [0xAC, 0x723A]
        };

        let metadata_end = usize::try_from(aligned_header_size)
            .map_err(|_| Error::ArithmeticOverflow("metadata end"))?;
        let mut metadata_raw = vec![0; metadata_end.saturating_sub(METADATA_OFFSET)];
        if let Some(source) = data.get(METADATA_OFFSET..) {
            let copied = source.len().min(metadata_raw.len());
            metadata_raw[..copied].copy_from_slice(&source[..copied]);
        }
        let content_id_valid = Sha1::digest(&metadata_raw).as_slice() == header.content_id;
        let installer_metadata = (header.size_of_headers > 0x971A)
            .then(|| InstallerMetadata::parse(&data))
            .flatten();

        let mut package = Self {
            data,
            header,
            metadata,
            installer_metadata,
            volume_descriptor,
            content_id_valid,
            files: Vec::new(),
            position: 0,
            aligned_header_size,
            blocks_per_hash_table,
            block_steps,
        };
        package.files = package.parse_directory()?;
        Ok(package)
    }

    /// Returns the complete package image.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the package length in bytes.
    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Converts an STFS backing-block number into a package byte offset.
    pub fn backing_block_offset(&self, block: u64) -> Result<u64, Error> {
        self.position
            .checked_add(self.aligned_header_size)
            .and_then(|value| value.checked_add(block.checked_mul(BLOCK_SIZE)?))
            .ok_or(Error::ArithmeticOverflow("backing-block offset"))
    }

    /// Converts a logical STFS data-block number into a package byte offset.
    pub fn data_block_offset(&self, block: u32) -> Result<u64, Error> {
        self.backing_block_offset(self.compute_backing_data_block(block))
    }

    /// Number of backing blocks according to the original STFS calculation.
    pub fn number_of_backing_blocks(&self) -> u64 {
        let total = self.volume_descriptor.total_blocks;
        let remainder = u64::from(total % DATA_BLOCKS_PER_HASH_LEVEL[0]);
        self.compute_level_hash_backing_block(total, 0) + remainder + 1
    }

    /// Expected package length according to its volume descriptor.
    pub fn expected_size(&self) -> Result<u64, Error> {
        self.backing_block_offset(self.number_of_backing_blocks())
    }

    /// Resolves a data-block chain. A `limit` prevents malformed packages from
    /// causing unbounded traversal.
    pub fn data_block_chain(&self, first_block: u32, limit: usize) -> Result<Vec<u32>, Error> {
        let mut resolver = HashResolver::new(self);
        resolver.block_chain(first_block, limit)
    }

    /// Extracts the bytes described by one file record.
    pub fn read_file(&self, file: &FileRecord) -> Result<Vec<u8>, Error> {
        if file.is_directory() {
            return Ok(Vec::new());
        }
        let size = usize::try_from(file.size())
            .map_err(|_| Error::ArithmeticOverflow("file allocation"))?;
        let block_count = size.div_ceil(BLOCK_SIZE as usize);
        let chain = self.data_block_chain(file.entry.first_block, block_count.saturating_add(1))?;
        if chain.len() < block_count {
            return Err(Error::InvalidBlock(file.entry.first_block));
        }
        let mut output = Vec::with_capacity(size);
        for block in chain.into_iter().take(block_count) {
            let offset = usize::try_from(self.data_block_offset(block)?)
                .map_err(|_| Error::ArithmeticOverflow("file block offset"))?;
            let remaining = size - output.len();
            let length = remaining.min(BLOCK_SIZE as usize);
            output.extend_from_slice(slice(&self.data, offset, length, "file data")?);
        }
        Ok(output)
    }

    /// Produces the metadata text shown by the legacy CLI's `-h` flag.
    pub fn metadata_text(&self) -> String {
        const LANGUAGES: [&str; 12] = [
            "English",
            "Japanese",
            "German",
            "French",
            "Spanish",
            "Italian",
            "Korean",
            "Chinese",
            "Portuguese",
            "Polish",
            "Russian",
            "Swedish",
        ];
        let mut output = String::new();
        if let Some(certificate) = self
            .header
            .console_certificate
            .as_ref()
            .filter(|certificate| certificate.is_structurally_valid())
        {
            output.push_str("[ConsoleSignature]\n");
            output.push_str(&format!(
                "ConsoleId = {}\nConsolePartNumber = {}\nPrivileges = 0x{:X}\nConsoleType = 0x{:08X} ({})\nManufacturingDate = {}\n\n",
                hex(&certificate.console_id, "-"),
                certificate.console_part_number,
                certificate.privileges,
                certificate.console_type,
                certificate.console_type_name(),
                certificate.manufacturing_date,
            ));
        }

        let execution = &self.metadata.execution_id;
        output.push_str("[ExecutionId]\n");
        if execution.media_id != 0 {
            output.push_str(&format!("MediaId = 0x{:08X}\n", execution.media_id));
        }
        if execution.version.is_valid() {
            output.push_str(&format!("Version = v{}\n", execution.version));
        }
        if execution.base_version.is_valid() {
            output.push_str(&format!("BaseVersion = v{}\n", execution.base_version));
        }
        if execution.title_id != 0 {
            output.push_str(&format!("TitleId = 0x{:08X}\n", execution.title_id));
        }
        output.push_str(&format!(
            "Platform = {}\nExecutableType = {}\nDiscNum = {}\nDiscsInSet = {}\n",
            execution.platform,
            execution.executable_type,
            execution.disc_number,
            execution.discs_in_set
        ));
        if execution.save_game_id != 0 {
            output.push_str(&format!("SaveGameId = 0x{:08X}\n", execution.save_game_id));
        }

        output.push_str("\n[XContentHeader]\n");
        output.push_str(&format!(
            "SignatureType = {}\nContentId = {}\nSizeOfHeaders = 0x{:X}\n",
            self.header.kind,
            hex(&self.header.content_id, "-"),
            self.header.size_of_headers
        ));
        for (index, license) in self.header.licenses.iter().enumerate() {
            if license.is_valid() {
                output.push_str(&format!(
                    "\n[XContentLicensee{index}]\nLicenseeId = 0x{:016X} ({})\nLicenseBits = 0x{:08X}\nLicenseFlags = 0x{:08X}\n",
                    license.licensee_id,
                    license.kind(),
                    license.license_bits,
                    license.license_flags
                ));
            }
        }

        output.push_str("\n[XContentMetadata]\n");
        output.push_str(&format!(
            "ContentType = 0x{:08X}\nContentMetadataVersion = {}\nContentSize = 0x{:X}\n",
            self.metadata.content_type,
            self.metadata.content_metadata_version,
            self.metadata.content_size
        ));
        if self.metadata.console_id.iter().any(|value| *value != 0) {
            output.push_str(&format!(
                "ConsoleId = {}\n",
                hex(&self.metadata.console_id, "-")
            ));
        }
        if self.metadata.creator != 0 {
            output.push_str(&format!("Creator = 0x{:016X}\n", self.metadata.creator));
        }
        if self.metadata.online_creator != 0 {
            output.push_str(&format!(
                "OnlineCreator = 0x{:016X}\n",
                self.metadata.online_creator
            ));
        }
        if self.metadata.category != 0 {
            output.push_str(&format!("Category = {}\n", self.metadata.category));
        }
        if self.metadata.device_id.iter().any(|value| *value != 0) {
            output.push_str(&format!(
                "DeviceId = {}\n",
                hex(&self.metadata.device_id, "-")
            ));
        }
        append_localized(
            &mut output,
            "DisplayName",
            &self.metadata.display_names,
            &LANGUAGES,
        );
        append_localized(
            &mut output,
            "DisplayNameEx",
            &self.metadata.display_names_extended,
            &LANGUAGES[9..],
        );
        append_localized(
            &mut output,
            "Description",
            &self.metadata.descriptions,
            &LANGUAGES,
        );
        append_localized(
            &mut output,
            "DescriptionEx",
            &self.metadata.descriptions_extended,
            &LANGUAGES[9..],
        );
        if !self.metadata.publisher.is_empty() {
            output.push_str(&format!("Publisher = {}\n", self.metadata.publisher));
        }
        if !self.metadata.title_name.is_empty() {
            output.push_str(&format!("TitleName = {}\n", self.metadata.title_name));
        }
        if self.metadata.flags != 0 {
            output.push_str(&format!("Flags = 0x{:02X}\n", self.metadata.flags));
        }
        output.push_str(&format!(
            "ThumbnailSize = 0x{:X}\nTitleThumbnailSize = 0x{:X}\n",
            self.metadata.thumbnail_size, self.metadata.title_thumbnail_size
        ));

        if let Some(installer) = &self.installer_metadata {
            output.push_str(&format!(
                "\n[XContentMetadataInstaller]\nMetaDataType = 0x{:08X} ({})\n",
                installer.metadata_type,
                installer.kind().unwrap_or("Unknown")
            ));
            if installer.current_version.is_valid() {
                output.push_str(&format!(
                    "CurrentVersion = v{}\n",
                    installer.current_version
                ));
            }
            if installer.new_version.is_valid() {
                output.push_str(&format!("NewVersion = v{}\n", installer.new_version));
            }
        }

        let descriptor = &self.volume_descriptor;
        let mut flags = String::new();
        if descriptor.read_only_format() {
            flags.push_str("(ReadOnlyFormat) ");
        }
        if descriptor.root_active_index() {
            flags.push_str("(RootActiveIndex) ");
        }
        output.push_str("\n[VolumeDescriptor]\nVolumeType = 0 (STFS)\n");
        output.push_str(&format!(
            "Stfs.DescriptorLength = 0x{:X}\nStfs.Version = {}\nStfs.Flags = {} {}\nStfs.DirectoryAllocationBlocks = 0x{:X}\nStfs.DirectoryFirstBlockNumber = 0x{:X}\nStfs.RootHash = {}\nStfs.NumberOfTotalBlocks = 0x{:X}\nStfs.NumberOfFreeBlocks = 0x{:X}\n",
            descriptor.descriptor_length,
            descriptor.version,
            descriptor.flags,
            flags,
            descriptor.directory_allocation_blocks,
            descriptor.directory_first_block,
            hex(&descriptor.root_hash, "-"),
            descriptor.total_blocks,
            descriptor.free_blocks
        ));
        output
    }

    fn parse_directory(&self) -> Result<Vec<FileRecord>, Error> {
        let mut resolver = HashResolver::new(self);
        let mut directory_block = self.volume_descriptor.directory_first_block;
        let mut records = Vec::<(DirectoryEntry, u64)>::new();
        for _ in 0..self.volume_descriptor.directory_allocation_blocks {
            if directory_block == 0xFF_FFFF {
                break;
            }
            let directory_offset = self.data_block_offset(directory_block)?;
            let offset = usize::try_from(directory_offset)
                .map_err(|_| Error::ArithmeticOverflow("directory offset"))?;
            let block = slice(&self.data, offset, BLOCK_SIZE as usize, "directory block")?;
            let mut no_more_entries = false;
            for raw in block.chunks_exact(64) {
                let Some(entry) = DirectoryEntry::parse(raw) else {
                    no_more_entries = true;
                    break;
                };
                records.push((entry, directory_offset));
            }
            let hash = resolver.level0_entry(directory_block);
            directory_block = hash.next_block;
            if no_more_entries {
                break;
            }
        }

        let paths = (0..records.len())
            .map(|index| resolve_path(index, &records))
            .collect::<Vec<_>>();
        Ok(records
            .into_iter()
            .zip(paths)
            .map(|((entry, directory_offset), path)| FileRecord {
                entry,
                directory_offset,
                path,
            })
            .collect())
    }

    pub(crate) fn compute_backing_data_block(&self, block: u32) -> u64 {
        let source = u64::from(block);
        let mut backing = source;
        let mut base = u64::from(HASH_ENTRIES_PER_BLOCK);
        for _ in 0..3 {
            backing += self.blocks_per_hash_table * ((source + base) / base);
            if source < base {
                break;
            }
            base *= u64::from(HASH_ENTRIES_PER_BLOCK);
        }
        backing
    }

    pub(crate) fn compute_level_hash_backing_block(&self, block: u32, level: usize) -> u64 {
        let block = u64::from(block);
        match level {
            0 => {
                let mut value = (block / 0xAA) * self.block_steps[0];
                if block / 0xAA == 0 {
                    return value;
                }
                value += (block / 0x70E4 + 1) * self.blocks_per_hash_table;
                if block / 0x70E4 == 0 {
                    return value;
                }
                value + self.blocks_per_hash_table
            }
            1 => {
                let value = (block / 0x70E4) * self.block_steps[1];
                if block / 0x70E4 == 0 {
                    value + self.block_steps[0]
                } else {
                    value + self.blocks_per_hash_table
                }
            }
            _ => self.block_steps[1],
        }
    }
}

fn append_localized(output: &mut String, label: &str, values: &[String], languages: &[&str]) {
    for (value, language) in values.iter().zip(languages) {
        if !value.is_empty() {
            output.push_str(&format!("{label}[{language}] = {value}\n"));
        }
    }
}

fn resolve_path(index: usize, entries: &[(DirectoryEntry, u64)]) -> String {
    let mut names = vec![entries[index].0.name.clone()];
    let mut parent = entries[index].0.directory_index;
    let mut seen = HashSet::new();
    while parent >= 0 {
        let parent_index = parent as usize;
        if parent_index >= entries.len() || !seen.insert(parent_index) {
            break;
        }
        names.push(entries[parent_index].0.name.clone());
        parent = entries[parent_index].0.directory_index;
    }
    names.reverse();
    names.join("\\")
}

#[derive(Clone, Debug)]
pub(crate) struct HashEntry {
    pub hash: Option<[u8; 20]>,
    pub flags: u8,
    pub next_block: u32,
}

pub(crate) struct HashResolver<'a> {
    package: &'a StfsPackage,
    tables: HashMap<u64, Box<[u8; BLOCK_SIZE as usize]>>,
    invalid_tables: BTreeSet<u64>,
}

impl<'a> HashResolver<'a> {
    pub(crate) fn new(package: &'a StfsPackage) -> Self {
        Self {
            package,
            tables: HashMap::new(),
            invalid_tables: BTreeSet::new(),
        }
    }

    pub(crate) fn cached_table_count(&self) -> usize {
        self.tables.len()
    }

    pub(crate) fn invalid_tables(&self) -> Vec<u64> {
        self.invalid_tables.iter().copied().collect()
    }

    fn level_entry(
        &mut self,
        block: u32,
        level: usize,
        expected_hash: &mut [u8; 20],
        secondary: bool,
    ) -> HashEntry {
        let mut record = block;
        if level > 0 {
            record /= DATA_BLOCKS_PER_HASH_LEVEL[level - 1];
        }
        record %= DATA_BLOCKS_PER_HASH_LEVEL[0];

        let backing = self.package.compute_level_hash_backing_block(block, level);
        let mut offset = self
            .package
            .backing_block_offset(backing)
            .unwrap_or(u64::MAX);
        if secondary && !self.package.volume_descriptor.read_only_format() {
            offset = offset.saturating_add(BLOCK_SIZE);
        }

        if !self.tables.contains_key(&offset) {
            let mut table = Box::new([0; BLOCK_SIZE as usize]);
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            if let Some(source) = self.package.data.get(start..) {
                let copied = source.len().min(table.len());
                table[..copied].copy_from_slice(&source[..copied]);
            }
            if start >= self.package.data.len()
                || Sha1::digest(table.as_ref()).as_slice() != expected_hash
            {
                self.invalid_tables.insert(offset);
            }
            self.tables.insert(offset, table);
        }

        if self.invalid_tables.contains(&offset) {
            return HashEntry {
                hash: None,
                flags: 0,
                next_block: block.saturating_add(1),
            };
        }

        let table = &self.tables[&offset];
        let entry_offset = record as usize * 24;
        let raw = &table[entry_offset..entry_offset + 24];
        let hash: [u8; 20] = raw[..20].try_into().unwrap();
        *expected_hash = hash;
        HashEntry {
            hash: Some(hash),
            flags: raw[20],
            next_block: u24_be(&raw[21..24]),
        }
    }

    pub(crate) fn level0_entry(&mut self, block: u32) -> HashEntry {
        let mut secondary = self.package.volume_descriptor.root_active_index();
        let mut expected = self.package.volume_descriptor.root_hash;
        let total = self.package.volume_descriptor.total_blocks;
        if total > DATA_BLOCKS_PER_HASH_LEVEL[1] {
            secondary = self.level_entry(block, 2, &mut expected, secondary).flags & 0x40 != 0;
        }
        if total > DATA_BLOCKS_PER_HASH_LEVEL[0] {
            secondary = self.level_entry(block, 1, &mut expected, secondary).flags & 0x40 != 0;
        }
        self.level_entry(block, 0, &mut expected, secondary)
    }

    pub(crate) fn block_chain(&mut self, first: u32, limit: usize) -> Result<Vec<u32>, Error> {
        let mut block = first;
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        while block != 0xFF_FFFF && chain.len() < limit {
            if !seen.insert(block) {
                return Err(Error::BlockChainCycle(block));
            }
            chain.push(block);
            block = self.level0_entry(block).next_block;
        }
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_xcontent_magic() {
        assert!(is_package(b"CON rest"));
        assert!(is_package(b"LIVErest"));
        assert!(is_package(b"PIRSrest"));
        assert!(!is_package(b"Joshrest"));
        assert!(!is_package(b"CON"));
    }
}
