use std::{collections::HashSet, fmt::Write as _};

use sha1::{Digest, Sha1};

use crate::{
    Error, FileRecord, StfsPackage,
    crypto::verify_header,
    format::hex,
    package::{BLOCK_SIZE, HashResolver},
};

/// Result of checking an XContent header signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureStatus {
    ConsoleSigned,
    Valid { signer: &'static str },
    Invalid,
}

impl SignatureStatus {
    pub fn is_valid(&self) -> bool {
        !matches!(self, Self::Invalid)
    }
}

impl std::fmt::Display for SignatureStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConsoleSigned => f.write_str("console signed"),
            Self::Valid { signer } => write!(f, "valid ({signer} signed)"),
            Self::Invalid => f.write_str("invalid!"),
        }
    }
}

/// Details for one data block whose SHA-1 does not match its level-zero entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidDataBlock {
    pub offset: u64,
    pub block: u32,
    pub expected_hash: [u8; 20],
    pub actual_hash: [u8; 20],
    pub flags: u8,
}

/// Integrity status of one block in the directory chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryBlockStatus {
    pub index: usize,
    pub block: u32,
    pub offset: u64,
    pub valid: bool,
}

/// Validation findings for one file directory entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryVerification {
    pub path: String,
    pub size: u64,
    pub first_block: u32,
    pub issues: Vec<String>,
}

/// Structured verification output used by both library consumers and the CLI.
#[derive(Clone, Debug)]
pub struct VerificationReport {
    pub valid: bool,
    pub signature: SignatureStatus,
    pub content_id_valid: bool,
    pub invalid_tables: Vec<u64>,
    pub cached_table_count: usize,
    pub invalid_data_blocks: Vec<InvalidDataBlock>,
    pub missing_blocks: Vec<u32>,
    pub directory_blocks: Vec<DirectoryBlockStatus>,
    /// All file-entry findings, including non-fatal CON valid-data-count notes.
    pub entry_findings: Vec<EntryVerification>,
    pub invalid_entries: Vec<EntryVerification>,
    pub total_entries: usize,
    pub total_blocks: u32,
    pub free_blocks_observed: u32,
    pub expected_free_blocks: u32,
    pub package_size: u64,
    pub expected_package_size: u64,
    pub metadata_warnings: Vec<String>,
    pub directory_chain_warning: Option<String>,
    pub hdd_path: String,
}

impl StfsPackage {
    /// Performs all signature, metadata, hash-table, data-block, directory, and
    /// package-size checks implemented by the original application.
    pub fn verify(&self) -> Result<VerificationReport, Error> {
        let header_hash: [u8; 20] = Sha1::digest(&self.bytes()[0x22C..0x344]).into();
        let signature = match verify_header(&self.header, &header_hash)? {
            Some("console signed") => SignatureStatus::ConsoleSigned,
            Some(signer) => SignatureStatus::Valid { signer },
            None => SignatureStatus::Invalid,
        };

        let mut resolver = HashResolver::new(self);
        let hash_entries = (0..self.volume_descriptor.total_blocks)
            .map(|block| resolver.level0_entry(block))
            .collect::<Vec<_>>();

        let mut invalid_data_blocks = Vec::new();
        let mut missing_blocks = Vec::new();
        let mut free_blocks_observed = 0_u32;
        for (block, entry) in hash_entries.iter().enumerate() {
            let block = block as u32;
            let offset = self.data_block_offset(block)?;
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            let Some(data) = self
                .bytes()
                .get(start..start.saturating_add(BLOCK_SIZE as usize))
            else {
                missing_blocks.push(block);
                continue;
            };
            let Some(expected_hash) = entry.hash else {
                continue;
            };
            if entry.flags == 0 {
                free_blocks_observed += 1;
                continue;
            }
            let actual_hash: [u8; 20] = Sha1::digest(data).into();
            if actual_hash != expected_hash {
                invalid_data_blocks.push(InvalidDataBlock {
                    offset,
                    block,
                    expected_hash,
                    actual_hash,
                    flags: entry.flags,
                });
            }
        }

        let invalid_offsets = invalid_data_blocks
            .iter()
            .map(|block| block.offset)
            .collect::<HashSet<_>>();
        let mut directory_blocks = Vec::new();
        let mut directory_block = self.volume_descriptor.directory_first_block;
        for index in 0..usize::from(self.volume_descriptor.directory_allocation_blocks) {
            if directory_block == 0xFF_FFFF {
                break;
            }
            let offset = self.data_block_offset(directory_block)?;
            directory_blocks.push(DirectoryBlockStatus {
                index,
                block: directory_block,
                offset,
                valid: !invalid_offsets.contains(&offset),
            });
            directory_block = resolver.level0_entry(directory_block).next_block;
        }

        let mut entry_findings = Vec::new();
        let mut invalid_entries = Vec::new();
        for file in self.files.iter().filter(|file| !file.is_directory()) {
            let (issues, invalid) = verify_file(self, file, &invalid_offsets, &mut resolver);
            if !issues.is_empty() {
                let finding = EntryVerification {
                    path: file.path.clone(),
                    size: file.size(),
                    first_block: file.entry.first_block,
                    issues,
                };
                entry_findings.push(finding.clone());
                if invalid {
                    invalid_entries.push(finding);
                }
            }
        }

        let expected_read_only = self.header.kind.is_live_or_pirs();
        let expected_header_size = if expected_read_only { 0xAD0E } else { 0x971A };
        let expected_free_blocks = if expected_read_only {
            0
        } else {
            free_blocks_observed
        };
        let expected_package_size = self.expected_size()?;
        let mut metadata_warnings = Vec::new();
        let content_size_expected = i128::from(expected_package_size) - 0xB000;
        let content_size_difference =
            i128::from(self.metadata.content_size) - content_size_expected;
        if content_size_difference != 0 {
            metadata_warnings.push(format!(
                "Metadata.ContentSize: 0x{:X} (expected 0x{:X}, {content_size_difference} bytes difference)",
                self.metadata.content_size, content_size_expected
            ));
        }
        if self.metadata.content_metadata_version > 2 {
            metadata_warnings.push(format!(
                "Metadata.ContentMetadataVersion: {:X} (expected 0, 1 or 2)",
                self.metadata.content_metadata_version
            ));
        }
        if self.volume_descriptor.read_only_format() != expected_read_only {
            metadata_warnings.push(format!(
                "StfsVolumeDescriptor.ReadOnlyFormat: {} (expected {expected_read_only} for {} package!)",
                self.volume_descriptor.read_only_format(),
                self.header.kind
            ));
        }
        if self.volume_descriptor.free_blocks != expected_free_blocks {
            metadata_warnings.push(format!(
                "StfsVolumeDescriptor.NumberOfFreeBlocks: {} (expected {expected_free_blocks})",
                self.volume_descriptor.free_blocks
            ));
        }
        if self.header.size_of_headers != expected_header_size {
            metadata_warnings.push(format!(
                "Header.SizeOfHeaders: 0x{:X} (expected 0x{expected_header_size:X} for {} package!)",
                self.header.size_of_headers, self.header.kind
            ));
        }

        let directory_chain = resolver.block_chain(
            self.volume_descriptor.directory_first_block,
            usize::from(self.volume_descriptor.directory_allocation_blocks).saturating_add(10),
        );
        let directory_chain_warning = match directory_chain {
            Ok(chain)
                if chain.len()
                    != usize::from(self.volume_descriptor.directory_allocation_blocks) =>
            {
                Some(format!(
                    "DirectoryChain.Length: {} (expected {})",
                    chain.len(),
                    self.volume_descriptor.directory_allocation_blocks
                ))
            }
            Err(error) => Some(format!("DirectoryChain: {error}")),
            _ => None,
        };

        let invalid_tables = resolver.invalid_tables();
        let cached_table_count = resolver.cached_table_count();
        let valid = signature.is_valid()
            && invalid_tables.is_empty()
            && invalid_data_blocks.is_empty()
            && missing_blocks.is_empty()
            && invalid_entries.is_empty()
            && self.len() >= expected_package_size
            && self.volume_descriptor.free_blocks == expected_free_blocks;
        let hdd_path = format!(
            "Content\\{:016X}\\{:08X}\\{:08X}\\{}",
            self.metadata.creator,
            self.metadata.execution_id.title_id,
            self.metadata.content_type,
            hex(&self.header.content_id, "")
        );

        Ok(VerificationReport {
            valid,
            signature,
            content_id_valid: self.content_id_valid,
            invalid_tables,
            cached_table_count,
            invalid_data_blocks,
            missing_blocks,
            directory_blocks,
            entry_findings,
            invalid_entries,
            total_entries: self.files.len(),
            total_blocks: self.volume_descriptor.total_blocks,
            free_blocks_observed,
            expected_free_blocks,
            package_size: self.len(),
            expected_package_size,
            metadata_warnings,
            directory_chain_warning,
            hdd_path,
        })
    }

    /// Renders a report in the established CLI format.
    pub fn render_report(&self, report: &VerificationReport, include_headers: bool) -> String {
        let mut output = String::new();
        if include_headers {
            output.push_str(&self.metadata_text());
            let _ = writeln!(
                output,
                "Stfs.NumberOfBackingBlocks = 0x{:X}\n",
                self.number_of_backing_blocks()
            );
        }
        let _ = writeln!(output, "File Count: {}", self.files.len());
        let _ = writeln!(output, "Block Count: {}", report.total_blocks);
        output.push_str("Verifying hash tables...\n");
        if !report.invalid_tables.is_empty() {
            let _ = writeln!(
                output,
                "\nDetected {} invalid hash tables:",
                report.invalid_tables.len()
            );
            for offset in &report.invalid_tables {
                let _ = writeln!(output, "  0x{offset:X}");
            }
        }
        output.push_str("\nVerifying data hashes...\n");
        if !report.invalid_data_blocks.is_empty() {
            let _ = writeln!(
                output,
                "\nDetected {} invalid data blocks:",
                report.invalid_data_blocks.len()
            );
            for invalid in &report.invalid_data_blocks {
                let _ = writeln!(
                    output,
                    "  0x{:X} (block 0x{:X})\n    Expected hash: {}\n      Actual hash: {}\n      Entry flags: {:X}",
                    invalid.offset,
                    invalid.block,
                    hex(&invalid.expected_hash, ""),
                    hex(&invalid.actual_hash, ""),
                    invalid.flags
                );
            }
        }
        output.push_str("\nVerifying directory entries...\n");
        for directory in &report.directory_blocks {
            let state = if directory.valid {
                "(valid)"
            } else {
                "(invalid)"
            };
            let _ = writeln!(
                output,
                "  Directory #{}\tblock 0x{:X}\t{state}",
                directory.index, directory.block
            );
        }
        for file in self.files.iter().filter(|file| !file.is_directory()) {
            let _ = writeln!(
                output,
                "  {}\t{} bytes\tstart block 0x{:X}",
                file.path,
                file.size(),
                file.entry.first_block
            );
            if let Some(finding) = report
                .entry_findings
                .iter()
                .find(|entry| entry.path == file.path)
            {
                for issue in &finding.issues {
                    let _ = writeln!(output, "  ^ {issue}");
                }
            }
        }

        output.push_str("\nSummary (invalid/total):\n");
        let signature_suffix = if report.signature.is_valid() {
            String::new()
        } else {
            format!(" (expected valid {} signature)", self.header.kind)
        };
        let _ = writeln!(
            output,
            "  Header signature: {}{signature_suffix}",
            report.signature
        );
        let _ = writeln!(
            output,
            "  Metadata hash: {}",
            if report.content_id_valid {
                "valid"
            } else {
                "invalid"
            }
        );
        for warning in &report.metadata_warnings {
            let _ = writeln!(output, "  {warning}");
        }
        if let Some(warning) = &report.directory_chain_warning {
            let _ = writeln!(output, "  {warning}");
        }
        let _ = writeln!(
            output,
            "  Hash tables: {}/{}",
            report.invalid_tables.len(),
            report.cached_table_count
        );
        let table_note = if report.invalid_tables.is_empty() {
            ""
        } else {
            " (bad hash tables prevents checking data blocks, the invalid count may be higher!)"
        };
        let _ = writeln!(
            output,
            "  Data blocks: {}/{}{}",
            report.invalid_data_blocks.len(),
            report.total_blocks,
            table_note
        );
        let _ = writeln!(
            output,
            "  Directory entries: {}/{}",
            report.invalid_entries.len(),
            report.total_entries
        );
        let _ = writeln!(
            output,
            "  Missing blocks: {}/{}",
            report.missing_blocks.len(),
            report.total_blocks
        );
        if report.package_size == report.expected_package_size {
            let _ = writeln!(output, "  Package size: 0x{:X}", report.package_size);
        } else {
            let _ = writeln!(
                output,
                "  Package size: 0x{:X} (expected 0x{:X})",
                report.package_size, report.expected_package_size
            );
            if report.package_size < report.expected_package_size {
                let _ = writeln!(
                    output,
                    "    (file truncated by {} bytes, too small to hold {} backing blocks)",
                    report.expected_package_size - report.package_size,
                    self.number_of_backing_blocks()
                );
            } else {
                let _ = writeln!(
                    output,
                    "    (file oversized, contains {} extra bytes)",
                    report.package_size - report.expected_package_size
                );
            }
        }
        let _ = writeln!(output, "  HDD path: {}", report.hdd_path);
        output
    }
}

fn verify_file(
    package: &StfsPackage,
    file: &FileRecord,
    invalid_offsets: &HashSet<u64>,
    resolver: &mut HashResolver<'_>,
) -> (Vec<String>, bool) {
    let mut issues = Vec::new();
    let mut invalid = false;
    if invalid_offsets.contains(&file.directory_offset) {
        invalid = true;
        issues.push(format!(
            "is inside invalid (bad hash) directory block! (0x{:X})",
            file.directory_offset
        ));
    }
    let expected_blocks = file.size().div_ceil(BLOCK_SIZE) as u32;
    if file.entry.allocation_blocks != expected_blocks {
        invalid = true;
        issues.push(format!(
            "has invalid NumAllocationBlocks! (value 0x{:X}, expected 0x{expected_blocks:X})",
            file.entry.allocation_blocks
        ));
    }
    if file.entry.valid_data_blocks != expected_blocks {
        issues.push(format!(
            "has invalid NumValidDataBlocks! (value 0x{:X}, expected 0x{expected_blocks:X})",
            file.entry.valid_data_blocks
        ));
        if package.header.kind.is_live_or_pirs() {
            invalid = true;
        }
    }
    if file.entry.first_block >= package.volume_descriptor.total_blocks {
        invalid = true;
        issues.push(format!(
            "FirstBlockNumber 0x{:X} out-of-range! (max block number: 0x{:X})",
            file.entry.first_block, package.volume_descriptor.total_blocks
        ));
        return (issues, invalid);
    }

    match resolver.block_chain(file.entry.first_block, expected_blocks as usize + 10) {
        Err(_) => {
            invalid = true;
            issues.push("failed to read complete block chain!".into());
        }
        Ok(chain) => {
            if chain.len() != expected_blocks as usize {
                invalid = true;
                issues.push(format!(
                    "has invalid block chain length! (length {} blocks, expected {expected_blocks})",
                    chain.len()
                ));
            }
            if let Some(block) = chain
                .iter()
                .find(|block| **block >= package.volume_descriptor.total_blocks)
            {
                invalid = true;
                issues.push(format!(
                    "block-chain contains out-of-range block 0x{block:X}! (max block number: 0x{:X})",
                    package.volume_descriptor.total_blocks
                ));
            }
        }
    }
    (issues, invalid)
}
