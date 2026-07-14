use std::error;
use std::fmt;

use crate::{crypto, render};

const HEADER_LEN: usize = 0x178;
const CERTIFICATE_LEN: usize = 0x1d0;
const SECTION_LEN: usize = 0x38;
const LIBRARY_LEN: usize = 0x10;

/// Errors returned while parsing or modifying an XBE image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The input ends before a required structure or data range.
    Truncated { context: &'static str },
    /// A count, address, or size cannot be represented safely.
    InvalidValue { context: &'static str, value: u64 },
    /// The selected operation requires a private key that is not available.
    MissingPrivateKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { context } => write!(f, "truncated XBE while reading {context}"),
            Self::InvalidValue { context, value } => {
                write!(f, "invalid {context}: 0x{value:X}")
            }
            Self::MissingPrivateKey => {
                f.write_str("the Microsoft private signing key is unavailable")
            }
        }
    }
}

impl error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// RSA/XOR key family used to interpret or sign an image.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum KeyKind {
    /// Retail Microsoft key (verification only).
    #[default]
    Microsoft,
    /// Historical xbedump test key.
    Test,
    /// Historical "Habibi" key.
    Habibi,
}

/// Options controlling the textual dump produced by [`Xbe::dump`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DumpOptions {
    pub header: bool,
    pub certificate: bool,
    pub sections: bool,
    pub libraries: bool,
    pub xbgs: bool,
    pub key: KeyKind,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self {
            header: false,
            certificate: false,
            sections: false,
            libraries: false,
            xbgs: false,
            key: KeyKind::Microsoft,
        }
    }
}

impl DumpOptions {
    /// Select every ordinary dump section (equivalent to legacy `-da`).
    #[must_use]
    pub fn all() -> Self {
        Self {
            header: true,
            certificate: true,
            sections: true,
            libraries: true,
            ..Self::default()
        }
    }
}

/// Options for [`Xbe::repair`]. Section hashes are always refreshed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairOptions {
    pub key: KeyKind,
    pub patch_xor_keys: bool,
    pub allow_all_media_and_regions: bool,
    pub generate_signature: bool,
}

impl Default for RepairOptions {
    fn default() -> Self {
        Self {
            key: KeyKind::Microsoft,
            patch_xor_keys: false,
            allow_all_media_and_regions: false,
            generate_signature: false,
        }
    }
}

/// Parsed fixed XBE header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub magic: [u8; 4],
    pub signature: [u8; 256],
    pub base_address: u32,
    pub header_size: u32,
    pub image_size: u32,
    pub xbe_header_size: u32,
    pub timestamp: u32,
    pub certificate_address: u32,
    pub section_count: u32,
    pub sections_address: u32,
    pub init_flags: u32,
    pub entry_point: u32,
    pub tls_directory: u32,
    pub stack_commit: u32,
    pub heap_reserve: u32,
    pub heap_commit: u32,
    pub pe_base_address: u32,
    pub pe_image_size: u32,
    pub pe_checksum: u32,
    pub pe_timestamp: u32,
    pub pc_exe_path: u32,
    pub pc_exe_filename: u32,
    pub pc_exe_filename_unicode: u32,
    pub kernel_thunk_table: u32,
    pub debug_import_table: u32,
    pub library_count: u32,
    pub libraries_address: u32,
    pub kernel_library: u32,
    pub xapi_library: u32,
    pub logo_bitmap: u32,
    pub logo_bitmap_size: u32,
}

/// Parsed XBE certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub size: u32,
    pub timestamp: u32,
    pub title_id: u32,
    pub title_name: String,
    pub alternate_title_ids: [u32; 16],
    pub media_types: u32,
    pub game_region: u32,
    pub game_rating: u32,
    pub disk_number: u32,
    pub version: u32,
    pub lan_key: [u8; 16],
    pub signature_key: [u8; 16],
    pub alternate_signature_keys: [[u8; 16]; 16],
}

/// Parsed XBE section header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub flags: u32,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub file_address: u32,
    pub file_size: u32,
    pub name_address: u32,
    pub name: String,
    pub reference_count: i32,
    pub head_reference_count: u32,
    pub tail_reference_count: u32,
    pub sha1: [u8; 20],
}

/// Parsed linked-library version record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Library {
    pub name: String,
    pub major_version: u16,
    pub middle_version: u16,
    pub minor_version: u16,
    pub flags: u16,
}

/// One integrity check in a [`ValidationReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub actual: Option<String>,
    pub expected: Option<String>,
}

/// Structured validation results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub checks: Vec<Check>,
}

impl ValidationReport {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.checks.iter().all(|check| check.passed)
    }
}

/// An owned, parsed XBE image.
#[derive(Debug, Clone)]
pub struct Xbe {
    data: Vec<u8>,
    header: Header,
    certificate: Certificate,
    sections: Vec<Section>,
    libraries: Vec<Library>,
    certificate_offset: usize,
    sections_offset: usize,
}

impl Xbe {
    /// Parse an XBE image. All address arithmetic and referenced ranges are checked.
    pub fn parse(data: impl Into<Vec<u8>>) -> Result<Self> {
        let data = data.into();
        let header = parse_header(&data)?;
        let certificate_offset = virtual_offset(
            header.certificate_address,
            header.base_address,
            "certificate address",
        )?;
        let certificate = parse_certificate(&data, certificate_offset)?;
        let sections_offset = virtual_offset(
            header.sections_address,
            header.base_address,
            "section headers address",
        )?;
        let section_count = count(header.section_count, "section count")?;
        checked_table(
            &data,
            sections_offset,
            section_count,
            SECTION_LEN,
            "section headers",
        )?;
        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            sections.push(parse_section(
                &data,
                sections_offset + index * SECTION_LEN,
                header.base_address,
            )?);
        }

        let library_count = count(header.library_count, "library count")?;
        let libraries_offset = if library_count == 0 {
            0
        } else {
            virtual_offset(
                header.libraries_address,
                header.base_address,
                "libraries address",
            )?
        };
        checked_table(
            &data,
            libraries_offset,
            library_count,
            LIBRARY_LEN,
            "libraries",
        )?;
        let mut libraries = Vec::with_capacity(library_count);
        for index in 0..library_count {
            libraries.push(parse_library(
                &data,
                libraries_offset + index * LIBRARY_LEN,
            )?);
        }

        Ok(Self {
            data,
            header,
            certificate,
            sections,
            libraries,
            certificate_offset,
            sections_offset,
        })
    }

    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    #[must_use]
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    #[must_use]
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    #[must_use]
    pub fn libraries(&self) -> &[Library] {
        &self.libraries
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Verify structural invariants, section hashes, and the header signature.
    pub fn validate(&self, key: KeyKind) -> Result<ValidationReport> {
        let mut checks = Vec::with_capacity(7 + self.sections.len());
        push_check(
            &mut checks,
            "Magic XBEH value",
            self.header.magic == *b"XBEH",
            hex(&self.header.magic),
            "58424548".into(),
        );
        push_check(
            &mut checks,
            "Image Base Address",
            self.header.base_address == 0x10000,
            format!("0x{:08X}", self.header.base_address),
            "0x00010000".into(),
        );
        let expected_certificate = self.header.xbe_header_size.wrapping_add(0x10000);
        push_check(
            &mut checks,
            "Certificate Address",
            self.header.certificate_address == expected_certificate,
            format!("0x{:08X}", self.header.certificate_address),
            format!("0x{expected_certificate:08X}"),
        );
        push_check(
            &mut checks,
            "Certificate Size",
            self.certificate.size >= CERTIFICATE_LEN as u32,
            format!("0x{:08X}", self.certificate.size),
            ">= 0x000001D0".into(),
        );
        let expected_sections = expected_certificate.wrapping_add(self.certificate.size);
        push_check(
            &mut checks,
            "Section Address",
            self.header.sections_address == expected_sections,
            format!("0x{:08X}", self.header.sections_address),
            format!("0x{expected_sections:08X}"),
        );
        push_check(
            &mut checks,
            "Debug Address",
            self.header.debug_import_table == 0,
            format!("0x{:08X}", self.header.debug_import_table),
            "0x00000000".into(),
        );

        for (index, section) in self.sections.iter().enumerate() {
            let digest = self.section_digest(section)?;
            push_check(
                &mut checks,
                &format!("Section {index:2} Hash"),
                digest == section.sha1,
                hex(&section.sha1),
                hex(&digest),
            );
        }

        let signature_valid = crypto::verify_signature(&self.data, &self.header, key)?;
        push_check(
            &mut checks,
            "2048 RSA Signature",
            signature_valid,
            if signature_valid { "valid" } else { "invalid" }.into(),
            "valid".into(),
        );
        Ok(ValidationReport { checks })
    }

    /// Refresh section hashes and optionally patch key-dependent fields and sign.
    /// Returns a report describing the resulting image.
    pub fn repair(&mut self, options: RepairOptions) -> Result<ValidationReport> {
        if options.generate_signature && options.key == KeyKind::Microsoft {
            return Err(Error::MissingPrivateKey);
        }

        if options.allow_all_media_and_regions {
            self.certificate.media_types = 0x8000_00ff;
            self.certificate.game_region = 0x8000_0007;
            put_u32(
                &mut self.data,
                self.certificate_offset + 0x9c,
                self.certificate.media_types,
            )?;
            put_u32(
                &mut self.data,
                self.certificate_offset + 0xa0,
                self.certificate.game_region,
            )?;
        }

        if options.patch_xor_keys {
            let (entry_delta, thunk_delta) = crypto::xor_patch_delta(options.key);
            self.header.entry_point ^= entry_delta;
            self.header.kernel_thunk_table ^= thunk_delta;
            put_u32(&mut self.data, 0x128, self.header.entry_point)?;
            put_u32(&mut self.data, 0x158, self.header.kernel_thunk_table)?;
        }

        for index in 0..self.sections.len() {
            let digest = self.section_digest(&self.sections[index])?;
            self.sections[index].sha1 = digest;
            let offset = self.sections_offset + index * SECTION_LEN + 0x24;
            put_bytes(&mut self.data, offset, &digest, "section hash")?;
        }

        if options.generate_signature {
            let signature = crypto::sign_header(&self.data, &self.header, options.key)?;
            self.header.signature = signature;
            put_bytes(&mut self.data, 4, &signature, "header signature")?;
        }

        self.validate(options.key)
    }

    /// Render selected information using the traditional xbedump text format.
    pub fn dump(&self, options: &DumpOptions) -> Result<String> {
        render::dump(self, options)
    }

    /// Return the decoded entry point for a key family.
    #[must_use]
    pub fn decoded_entry_point(&self, key: KeyKind) -> u32 {
        self.header.entry_point ^ crypto::entry_xor_key(key)
    }

    /// Return the decoded kernel thunk table address for a key family.
    #[must_use]
    pub fn decoded_kernel_thunk_table(&self, key: KeyKind) -> u32 {
        self.header.kernel_thunk_table ^ crypto::thunk_xor_key(key)
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    pub(crate) fn virtual_offset(&self, address: u32, context: &'static str) -> Result<usize> {
        virtual_offset(address, self.header.base_address, context)
    }

    pub(crate) fn section_digest(&self, section: &Section) -> Result<[u8; 20]> {
        let start = usize::try_from(section.file_address).map_err(|_| Error::InvalidValue {
            context: "section file address",
            value: section.file_address.into(),
        })?;
        let size = usize::try_from(section.file_size).map_err(|_| Error::InvalidValue {
            context: "section file size",
            value: section.file_size.into(),
        })?;
        let bytes = range(&self.data, start, size, "section data")?;
        Ok(crypto::xbe_sha1(bytes))
    }
}

fn push_check(checks: &mut Vec<Check>, name: &str, passed: bool, actual: String, expected: String) {
    checks.push(Check {
        name: name.into(),
        passed,
        actual: Some(actual),
        expected: Some(expected),
    });
}

fn parse_header(data: &[u8]) -> Result<Header> {
    range(data, 0, HEADER_LEN, "XBE header")?;
    let mut signature = [0; 256];
    signature.copy_from_slice(&data[4..0x104]);
    Ok(Header {
        magic: data[0..4].try_into().expect("fixed range"),
        signature,
        base_address: u32_at(data, 0x104, "base address")?,
        header_size: u32_at(data, 0x108, "header size")?,
        image_size: u32_at(data, 0x10c, "image size")?,
        xbe_header_size: u32_at(data, 0x110, "XBE header size")?,
        timestamp: u32_at(data, 0x114, "timestamp")?,
        certificate_address: u32_at(data, 0x118, "certificate address")?,
        section_count: u32_at(data, 0x11c, "section count")?,
        sections_address: u32_at(data, 0x120, "sections address")?,
        init_flags: u32_at(data, 0x124, "initialization flags")?,
        entry_point: u32_at(data, 0x128, "entry point")?,
        tls_directory: u32_at(data, 0x12c, "TLS directory")?,
        stack_commit: u32_at(data, 0x130, "stack commit")?,
        heap_reserve: u32_at(data, 0x134, "heap reserve")?,
        heap_commit: u32_at(data, 0x138, "heap commit")?,
        pe_base_address: u32_at(data, 0x13c, "PE base address")?,
        pe_image_size: u32_at(data, 0x140, "PE image size")?,
        pe_checksum: u32_at(data, 0x144, "PE checksum")?,
        pe_timestamp: u32_at(data, 0x148, "PE timestamp")?,
        pc_exe_path: u32_at(data, 0x14c, "PC executable path")?,
        pc_exe_filename: u32_at(data, 0x150, "PC executable filename")?,
        pc_exe_filename_unicode: u32_at(data, 0x154, "Unicode PC executable filename")?,
        kernel_thunk_table: u32_at(data, 0x158, "kernel thunk table")?,
        debug_import_table: u32_at(data, 0x15c, "debug import table")?,
        library_count: u32_at(data, 0x160, "library count")?,
        libraries_address: u32_at(data, 0x164, "libraries address")?,
        kernel_library: u32_at(data, 0x168, "kernel library")?,
        xapi_library: u32_at(data, 0x16c, "XAPI library")?,
        logo_bitmap: u32_at(data, 0x170, "logo bitmap")?,
        logo_bitmap_size: u32_at(data, 0x174, "logo bitmap size")?,
    })
}

fn parse_certificate(data: &[u8], offset: usize) -> Result<Certificate> {
    range(data, offset, CERTIFICATE_LEN, "certificate")?;
    let size = u32_at(data, offset, "certificate size")?;
    let declared_size = count(size, "certificate size")?;
    range(data, offset, declared_size, "declared certificate")?;
    let mut title_units = Vec::new();
    for index in 0..40 {
        let unit = u16_at(data, offset + 0x0c + index * 2, "title name")?;
        if unit == 0 {
            break;
        }
        title_units.push(unit);
    }
    let mut alternate_title_ids = [0; 16];
    for (index, value) in alternate_title_ids.iter_mut().enumerate() {
        *value = u32_at(data, offset + 0x5c + index * 4, "alternate title ID")?;
    }
    let mut alternate_signature_keys = [[0; 16]; 16];
    for (index, key) in alternate_signature_keys.iter_mut().enumerate() {
        key.copy_from_slice(range(
            data,
            offset + 0xd0 + index * 16,
            16,
            "alternate signature key",
        )?);
    }
    Ok(Certificate {
        size,
        timestamp: u32_at(data, offset + 4, "certificate timestamp")?,
        title_id: u32_at(data, offset + 8, "title ID")?,
        title_name: String::from_utf16_lossy(&title_units),
        alternate_title_ids,
        media_types: u32_at(data, offset + 0x9c, "media types")?,
        game_region: u32_at(data, offset + 0xa0, "game region")?,
        game_rating: u32_at(data, offset + 0xa4, "game rating")?,
        disk_number: u32_at(data, offset + 0xa8, "disk number")?,
        version: u32_at(data, offset + 0xac, "version")?,
        lan_key: range(data, offset + 0xb0, 16, "LAN key")?
            .try_into()
            .expect("fixed range"),
        signature_key: range(data, offset + 0xc0, 16, "signature key")?
            .try_into()
            .expect("fixed range"),
        alternate_signature_keys,
    })
}

fn parse_section(data: &[u8], offset: usize, base: u32) -> Result<Section> {
    range(data, offset, SECTION_LEN, "section header")?;
    let file_address = u32_at(data, offset + 0x0c, "section file address")?;
    let file_size = u32_at(data, offset + 0x10, "section file size")?;
    let file_start = count(file_address, "section file address")?;
    let file_len = count(file_size, "section file size")?;
    range(data, file_start, file_len, "section data")?;
    let name_address = u32_at(data, offset + 0x14, "section name address")?;
    let name_offset = virtual_offset(name_address, base, "section name address")?;
    let name = c_string(data, name_offset, "section name")?;
    Ok(Section {
        flags: u32_at(data, offset, "section flags")?,
        virtual_address: u32_at(data, offset + 4, "section virtual address")?,
        virtual_size: u32_at(data, offset + 8, "section virtual size")?,
        file_address,
        file_size,
        name_address,
        name,
        reference_count: i32::from_le_bytes(
            range(data, offset + 0x18, 4, "section reference count")?
                .try_into()
                .expect("fixed range"),
        ),
        head_reference_count: u32_at(data, offset + 0x1c, "head reference count")?,
        tail_reference_count: u32_at(data, offset + 0x20, "tail reference count")?,
        sha1: range(data, offset + 0x24, 20, "section hash")?
            .try_into()
            .expect("fixed range"),
    })
}

fn parse_library(data: &[u8], offset: usize) -> Result<Library> {
    let name_bytes = range(data, offset, 8, "library name")?;
    let name_len = name_bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name_bytes.len());
    Ok(Library {
        name: String::from_utf8_lossy(&name_bytes[..name_len]).into_owned(),
        major_version: u16_at(data, offset + 8, "library major version")?,
        middle_version: u16_at(data, offset + 10, "library middle version")?,
        minor_version: u16_at(data, offset + 12, "library minor version")?,
        flags: u16_at(data, offset + 14, "library flags")?,
    })
}

fn virtual_offset(address: u32, base: u32, context: &'static str) -> Result<usize> {
    let relative = address.checked_sub(base).ok_or(Error::InvalidValue {
        context,
        value: address.into(),
    })?;
    count(relative, context)
}

fn count(value: u32, context: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::InvalidValue {
        context,
        value: value.into(),
    })
}

fn checked_table(
    data: &[u8],
    offset: usize,
    count: usize,
    width: usize,
    context: &'static str,
) -> Result<()> {
    let size = count.checked_mul(width).ok_or(Error::InvalidValue {
        context,
        value: count as u64,
    })?;
    range(data, offset, size, context).map(|_| ())
}

pub(crate) fn range<'a>(
    data: &'a [u8],
    offset: usize,
    size: usize,
    context: &'static str,
) -> Result<&'a [u8]> {
    let end = offset.checked_add(size).ok_or(Error::InvalidValue {
        context,
        value: offset as u64,
    })?;
    data.get(offset..end).ok_or(Error::Truncated { context })
}

fn u16_at(data: &[u8], offset: usize, context: &'static str) -> Result<u16> {
    Ok(u16::from_le_bytes(
        range(data, offset, 2, context)?
            .try_into()
            .expect("fixed range"),
    ))
}

fn u32_at(data: &[u8], offset: usize, context: &'static str) -> Result<u32> {
    Ok(u32::from_le_bytes(
        range(data, offset, 4, context)?
            .try_into()
            .expect("fixed range"),
    ))
}

fn put_u32(data: &mut [u8], offset: usize, value: u32) -> Result<()> {
    put_bytes(data, offset, &value.to_le_bytes(), "XBE field")
}

fn put_bytes(data: &mut [u8], offset: usize, bytes: &[u8], context: &'static str) -> Result<()> {
    let end = offset.checked_add(bytes.len()).ok_or(Error::InvalidValue {
        context,
        value: offset as u64,
    })?;
    let target = data
        .get_mut(offset..end)
        .ok_or(Error::Truncated { context })?;
    target.copy_from_slice(bytes);
    Ok(())
}

fn c_string(data: &[u8], offset: usize, context: &'static str) -> Result<String> {
    let tail = data.get(offset..).ok_or(Error::Truncated { context })?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Truncated { context })?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02X}");
    }
    output
}
