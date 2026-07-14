use sha1::{Digest, Sha1};
use stfschk::{PackageKind, SignatureStatus, StfsPackage, is_package};

const HEADER_ALIGNED: usize = 0xA000;
const HASH_TABLE_OFFSET: usize = 0xA000;
const DATA_BLOCK_OFFSET: usize = 0xC000;

fn minimal_con() -> Vec<u8> {
    let mut package = vec![0_u8; 0xD000];
    package[0..4].copy_from_slice(b"CON ");
    package[0x340..0x344].copy_from_slice(&0x971A_u32.to_be_bytes());

    let metadata = 0x344;
    package[metadata + 8..metadata + 16].copy_from_slice(&0x1000_u64.to_be_bytes());
    let descriptor = metadata + 0x35;
    package[descriptor] = 0x24;
    package[descriptor + 3..descriptor + 5].copy_from_slice(&1_u16.to_le_bytes());
    package[descriptor + 28..descriptor + 32].copy_from_slice(&1_u32.to_be_bytes());

    let data_hash: [u8; 20] =
        Sha1::digest(&package[DATA_BLOCK_OFFSET..DATA_BLOCK_OFFSET + 0x1000]).into();
    package[HASH_TABLE_OFFSET..HASH_TABLE_OFFSET + 20].copy_from_slice(&data_hash);
    package[HASH_TABLE_OFFSET + 20] = 0x80;
    package[HASH_TABLE_OFFSET + 21..HASH_TABLE_OFFSET + 24].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    let root_hash: [u8; 20] =
        Sha1::digest(&package[HASH_TABLE_OFFSET..HASH_TABLE_OFFSET + 0x1000]).into();
    package[descriptor + 8..descriptor + 28].copy_from_slice(&root_hash);

    let content_id: [u8; 20] = Sha1::digest(&package[0x344..HEADER_ALIGNED]).into();
    package[0x32C..0x340].copy_from_slice(&content_id);
    package
}

#[test]
fn parses_and_verifies_a_minimal_con_package() {
    let bytes = minimal_con();
    assert!(is_package(&bytes));
    let package = StfsPackage::parse(bytes).unwrap();
    assert_eq!(package.header.kind, PackageKind::Con);
    assert!(package.content_id_valid);
    assert!(package.files.is_empty());
    assert_eq!(
        package.data_block_offset(0).unwrap(),
        DATA_BLOCK_OFFSET as u64
    );

    let report = package.verify().unwrap();
    assert!(report.valid, "{}", package.render_report(&report, false));
    assert_eq!(report.signature, SignatureStatus::ConsoleSigned);
    assert!(report.invalid_tables.is_empty());
    assert!(report.invalid_data_blocks.is_empty());
    assert!(report.missing_blocks.is_empty());
}

#[test]
fn reports_a_corrupted_data_block() {
    let mut bytes = minimal_con();
    bytes[DATA_BLOCK_OFFSET] = 1;
    let package = StfsPackage::parse(bytes).unwrap();
    let report = package.verify().unwrap();
    assert!(!report.valid);
    assert_eq!(report.invalid_data_blocks.len(), 1);
    assert_eq!(report.invalid_data_blocks[0].block, 0);
}

#[test]
fn reports_a_corrupted_hash_table_without_trusting_its_entries() {
    let mut bytes = minimal_con();
    bytes[HASH_TABLE_OFFSET + 100] = 1;
    let package = StfsPackage::parse(bytes).unwrap();
    let report = package.verify().unwrap();
    assert!(!report.valid);
    assert_eq!(report.invalid_tables, vec![HASH_TABLE_OFFSET as u64]);
    assert!(report.invalid_data_blocks.is_empty());
}
