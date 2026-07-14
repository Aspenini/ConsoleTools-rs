use std::fmt;

use crate::{Error, error::slice};

pub(crate) const HEADER_SIZE: usize = 0x344;
pub(crate) const METADATA_OFFSET: usize = 0x344;
pub(crate) const INSTALLER_OFFSET: usize = 0x971A;

/// XContent package signature/magic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageKind {
    Con,
    Live,
    Pirs,
}

impl PackageKind {
    pub(crate) fn parse(value: [u8; 4]) -> Result<Self, Error> {
        match &value {
            b"CON " => Ok(Self::Con),
            b"LIVE" => Ok(Self::Live),
            b"PIRS" => Ok(Self::Pirs),
            _ => Err(Error::InvalidMagic(value)),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Con => "CON",
            Self::Live => "LIVE",
            Self::Pirs => "PIRS",
        }
    }

    pub fn is_live_or_pirs(self) -> bool {
        matches!(self, Self::Live | Self::Pirs)
    }
}

impl fmt::Display for PackageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One XContent license descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct License {
    pub licensee_id: u64,
    pub license_bits: u32,
    pub license_flags: u32,
}

impl License {
    pub fn is_valid(&self) -> bool {
        self.licensee_id != 0 || self.license_bits != 0 || self.license_flags != 0
    }

    pub fn kind(&self) -> &'static str {
        let tag = self.licensee_id >> 48;
        match tag {
            0x0003 => "WindowsId",
            0x0009 => "Xuid",
            0xB000 => "SerPrivileges",
            0xC000 => "HvFlags",
            0xD000 => "KeyVaultPrivileges",
            0xE000 => "MediaFlags",
            0xF000 => "ConsoleId",
            0xFFFF => "Unrestricted",
            _ => "Unknown",
        }
    }
}

/// Parsed console certificate fields embedded in a CON signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsoleCertificate {
    pub certificate_size: u16,
    pub console_id: [u8; 5],
    pub console_part_number: String,
    pub privileges: u16,
    pub console_type: u32,
    pub manufacturing_date: String,
}

impl ConsoleCertificate {
    pub fn is_structurally_valid(&self) -> bool {
        self.certificate_size == 0x1A8
    }

    pub fn console_type_name(&self) -> String {
        match self.console_type {
            1 => "DevKit".into(),
            2 => "Retail".into(),
            0x8000_0001 => "DevKit (recovered/generated)".into(),
            0x8000_0002 => "BetaKit".into(),
            value => format!("{value:08X}"),
        }
    }
}

/// XContent header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub kind: PackageKind,
    pub signature: Vec<u8>,
    pub licenses: Vec<License>,
    pub content_id: [u8; 20],
    pub size_of_headers: u32,
    pub console_certificate: Option<ConsoleCertificate>,
}

impl Header {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, Error> {
        let raw = slice(data, 0, HEADER_SIZE, "XContent header")?;
        let kind = PackageKind::parse(raw[0..4].try_into().expect("four-byte magic"))?;
        let signature = raw[4..0x22C].to_vec();
        let mut licenses = Vec::with_capacity(16);
        for descriptor in raw[0x22C..0x32C].chunks_exact(16) {
            licenses.push(License {
                licensee_id: u64::from_be_bytes(descriptor[0..8].try_into().unwrap()),
                license_bits: u32::from_be_bytes(descriptor[8..12].try_into().unwrap()),
                license_flags: u32::from_be_bytes(descriptor[12..16].try_into().unwrap()),
            });
        }
        let content_id = raw[0x32C..0x340].try_into().unwrap();
        let size_of_headers = u32::from_be_bytes(raw[0x340..0x344].try_into().unwrap());
        let console_certificate = (kind == PackageKind::Con).then(|| parse_certificate(&signature));
        Ok(Self {
            kind,
            signature,
            licenses,
            content_id,
            size_of_headers,
            console_certificate,
        })
    }
}

fn parse_certificate(signature: &[u8]) -> ConsoleCertificate {
    let bytes = |range: std::ops::Range<usize>| signature.get(range).unwrap_or(&[]);
    let be16 = |offset: usize| {
        signature
            .get(offset..offset + 2)
            .and_then(|value| value.try_into().ok())
            .map(u16::from_be_bytes)
            .unwrap_or(0)
    };
    let be32 = |offset: usize| {
        signature
            .get(offset..offset + 4)
            .and_then(|value| value.try_into().ok())
            .map(u32::from_be_bytes)
            .unwrap_or(0)
    };
    let mut console_id = [0; 5];
    console_id.copy_from_slice(bytes(2..7).get(..5).unwrap_or(&[0; 5]));
    ConsoleCertificate {
        certificate_size: be16(0),
        console_id,
        console_part_number: ascii(bytes(7..18)),
        privileges: be16(22),
        console_type: be32(24),
        manufacturing_date: ascii(bytes(28..36)),
    }
}

/// Four-part Xbox executable version.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub build: u16,
    pub qfe: u8,
}

impl Version {
    fn parse(raw: &[u8]) -> Self {
        Self {
            major: raw[0] >> 4,
            minor: raw[0] & 0x0F,
            build: u16::from_be_bytes([raw[1], raw[2]]),
            qfe: raw[3],
        }
    }

    pub fn is_valid(self) -> bool {
        self.major != 0 || self.minor != 0 || self.build != 0 || self.qfe != 0
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.qfe
        )
    }
}

/// XEX execution identity stored in XContent metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionId {
    pub media_id: u32,
    pub version: Version,
    pub base_version: Version,
    pub title_id: u32,
    pub platform: u8,
    pub executable_type: u8,
    pub disc_number: u8,
    pub discs_in_set: u8,
    pub save_game_id: u32,
}

impl ExecutionId {
    fn parse(raw: &[u8]) -> Self {
        Self {
            media_id: u32::from_be_bytes(raw[0..4].try_into().unwrap()),
            version: Version::parse(&raw[4..8]),
            base_version: Version::parse(&raw[8..12]),
            title_id: u32::from_be_bytes(raw[12..16].try_into().unwrap()),
            platform: raw[16],
            executable_type: raw[17],
            disc_number: raw[18],
            discs_in_set: raw[19],
            save_game_id: u32::from_be_bytes(raw[20..24].try_into().unwrap()),
        }
    }
}

/// STFS volume descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeDescriptor {
    pub descriptor_length: u8,
    pub version: u8,
    pub flags: u8,
    pub directory_allocation_blocks: u16,
    pub directory_first_block: u32,
    pub root_hash: [u8; 20],
    pub total_blocks: u32,
    pub free_blocks: u32,
}

impl VolumeDescriptor {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < 0x24 {
            return Err(Error::Truncated {
                context: "STFS volume descriptor",
                offset: 0,
                needed: 0x24,
                available: raw.len(),
            });
        }
        Ok(Self {
            descriptor_length: raw[0],
            version: raw[1],
            flags: raw[2],
            // This field is little-endian in the original on-disk structure.
            directory_allocation_blocks: u16::from_le_bytes([raw[3], raw[4]]),
            directory_first_block: u24_le(&raw[5..8]),
            root_hash: raw[8..28].try_into().unwrap(),
            total_blocks: u32::from_be_bytes(raw[28..32].try_into().unwrap()),
            free_blocks: u32::from_be_bytes(raw[32..36].try_into().unwrap()),
        })
    }

    pub fn read_only_format(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn root_active_index(&self) -> bool {
        self.flags & 2 != 0
    }
}

/// Parsed XContent metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub content_type: u32,
    pub content_metadata_version: u32,
    pub content_size: u64,
    pub execution_id: ExecutionId,
    pub console_id: [u8; 5],
    pub creator: u64,
    pub data_files: u32,
    pub data_files_size: u64,
    pub volume_type: u32,
    pub online_creator: u64,
    pub category: u32,
    pub device_id: [u8; 20],
    pub display_names: Vec<String>,
    pub descriptions: Vec<String>,
    pub publisher: String,
    pub title_name: String,
    pub flags: u8,
    pub thumbnail_size: u32,
    pub title_thumbnail_size: u32,
    pub display_names_extended: Vec<String>,
    pub descriptions_extended: Vec<String>,
}

impl Metadata {
    pub(crate) fn parse(data: &[u8]) -> Result<(Self, VolumeDescriptor), Error> {
        let raw = slice(data, METADATA_OFFSET, 0xCD, "XContent metadata")?;
        let execution_id = ExecutionId::parse(&raw[0x10..0x28]);
        let console_id = raw[0x28..0x2D].try_into().unwrap();
        let volume = VolumeDescriptor::parse(&raw[0x35..0x59])?;
        let device_id = raw[0xB9..0xCD].try_into().unwrap();

        let display_names = unicode_array(data, METADATA_OFFSET + 0xCD, 9, 0x100);
        let descriptions = unicode_array(data, METADATA_OFFSET + 0x9CD, 9, 0x100);
        let publisher = utf16_be_at(data, METADATA_OFFSET + 0x12CD, 0x80);
        let title_name = utf16_be_at(data, METADATA_OFFSET + 0x134D, 0x80);
        let display_names_extended = unicode_array(data, METADATA_OFFSET + 0x50D6, 3, 0x100);
        let descriptions_extended = unicode_array(data, METADATA_OFFSET + 0x90D6, 3, 0x100);

        let read_u32 = |relative: usize| {
            data.get(METADATA_OFFSET + relative..METADATA_OFFSET + relative + 4)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_be_bytes)
                .unwrap_or(0)
        };
        let read_u64 = |relative: usize| {
            data.get(METADATA_OFFSET + relative..METADATA_OFFSET + relative + 8)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_be_bytes)
                .unwrap_or(0)
        };

        Ok((
            Self {
                content_type: read_u32(0),
                content_metadata_version: read_u32(4),
                content_size: read_u64(8),
                execution_id,
                console_id,
                creator: read_u64(0x2D),
                data_files: read_u32(0x59),
                data_files_size: read_u64(0x5D),
                volume_type: read_u32(0x65),
                online_creator: read_u64(0x69),
                category: read_u32(0x71),
                device_id,
                display_names,
                descriptions,
                publisher,
                title_name,
                flags: data.get(METADATA_OFFSET + 0x13CD).copied().unwrap_or(0),
                thumbnail_size: read_u32(0x13CE),
                title_thumbnail_size: read_u32(0x13D2),
                display_names_extended,
                descriptions_extended,
            },
            volume,
        ))
    }
}

/// Optional installer metadata appended after the base metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallerMetadata {
    pub metadata_type: u32,
    pub current_version: Version,
    pub new_version: Version,
}

impl InstallerMetadata {
    pub(crate) fn parse(data: &[u8]) -> Option<Self> {
        let raw = data.get(INSTALLER_OFFSET..INSTALLER_OFFSET + 12)?;
        let metadata = Self {
            metadata_type: u32::from_be_bytes(raw[0..4].try_into().unwrap()),
            current_version: Version::parse(&raw[4..8]),
            new_version: Version::parse(&raw[8..12]),
        };
        metadata.is_valid().then_some(metadata)
    }

    pub fn is_valid(&self) -> bool {
        matches!(self.metadata_type, 0x5355_5044 | 0x5455_5044)
    }

    pub fn kind(&self) -> Option<&'static str> {
        match self.metadata_type {
            0x5355_5044 => Some("SystemUpdate"),
            0x5455_5044 => Some("TitleUpdate"),
            _ => None,
        }
    }
}

/// A raw 64-byte STFS directory entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub name: String,
    pub flags: u8,
    pub valid_data_blocks: u32,
    pub allocation_blocks: u32,
    pub first_block: u32,
    pub directory_index: i16,
    pub file_size: u32,
    pub creation_time_raw: u32,
    pub last_write_time_raw: u32,
}

impl DirectoryEntry {
    pub(crate) fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < 64 {
            return None;
        }
        let flags = raw[40];
        let name_length = usize::from(flags & 0x3F);
        if flags == 0 || name_length == 0 || name_length > 40 {
            return None;
        }
        let name = ascii(&raw[..name_length]);
        if name.chars().any(|character| {
            matches!(
                character,
                '>' | '<' | '=' | '?' | ':' | ';' | '"' | '*' | '+' | ',' | '/' | '\\' | '|'
            )
        }) {
            return None;
        }
        Some(Self {
            name,
            flags,
            valid_data_blocks: u24_le(&raw[41..44]),
            allocation_blocks: u24_le(&raw[44..47]),
            first_block: u24_le(&raw[47..50]),
            directory_index: i16::from_be_bytes(raw[50..52].try_into().unwrap()),
            file_size: u32::from_be_bytes(raw[52..56].try_into().unwrap()),
            creation_time_raw: u32::from_be_bytes(raw[56..60].try_into().unwrap()),
            last_write_time_raw: u32::from_be_bytes(raw[60..64].try_into().unwrap()),
        })
    }

    pub fn is_directory(&self) -> bool {
        self.flags & 0x80 != 0
    }

    pub fn is_contiguous(&self) -> bool {
        self.flags & 0x40 != 0
    }

    pub fn file_name_length(&self) -> u8 {
        self.flags & 0x3F
    }
}

pub(crate) fn u24_le(raw: &[u8]) -> u32 {
    u32::from(raw[0]) | (u32::from(raw[1]) << 8) | (u32::from(raw[2]) << 16)
}

pub(crate) fn u24_be(raw: &[u8]) -> u32 {
    (u32::from(raw[0]) << 16) | (u32::from(raw[1]) << 8) | u32::from(raw[2])
}

pub(crate) fn hex(bytes: &[u8], separator: &str) -> String {
    bytes
        .iter()
        .map(|value| format!("{value:02X}"))
        .collect::<Vec<_>>()
        .join(separator)
}

fn ascii(bytes: &[u8]) -> String {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..length]).into_owned()
}

fn utf16_be_at(data: &[u8], offset: usize, length: usize) -> String {
    let Some(raw) = data.get(offset..offset.saturating_add(length)) else {
        return String::new();
    };
    let words = raw
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .take_while(|word| *word != 0)
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&words)
}

fn unicode_array(data: &[u8], offset: usize, count: usize, width: usize) -> Vec<String> {
    (0..count)
        .map(|index| utf16_be_at(data, offset + index * width, width))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_match_xbox_display_format() {
        let version = Version::parse(&[0x21, 0x04, 0xD2, 7]);
        assert_eq!(version.to_string(), "2.1.1234.7");
    }

    #[test]
    fn volume_descriptor_keeps_mixed_endianness() {
        let mut raw = [0_u8; 0x24];
        raw[0] = 0x24;
        raw[3..5].copy_from_slice(&0x1234_u16.to_le_bytes());
        raw[5..8].copy_from_slice(&[0x56, 0x34, 0x12]);
        raw[28..32].copy_from_slice(&0x1020_3040_u32.to_be_bytes());
        let descriptor = VolumeDescriptor::parse(&raw).unwrap();
        assert_eq!(descriptor.directory_allocation_blocks, 0x1234);
        assert_eq!(descriptor.directory_first_block, 0x123456);
        assert_eq!(descriptor.total_blocks, 0x1020_3040);
    }
}
