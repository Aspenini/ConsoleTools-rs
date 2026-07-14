use std::fs;
use std::process::Command;

use xbedump::{DumpOptions, Error, KeyKind, RepairOptions, Xbe};

const BASE: u32 = 0x0001_0000;

#[test]
fn parses_structured_metadata_and_renders_dumps() {
    let xbe = Xbe::parse(fixture()).unwrap();
    assert_eq!(xbe.header().base_address, BASE);
    assert_eq!(xbe.certificate().title_id, 0x4d53_0001);
    assert_eq!(xbe.certificate().title_name, "Rust Test");
    assert_eq!(xbe.sections()[0].name, ".text");
    assert_eq!(xbe.libraries()[0].name, "XAPILIB");

    let dump = xbe.dump(&DumpOptions::all()).unwrap();
    assert!(dump.contains("XBE header"));
    assert!(dump.contains("Title name                          : \"Rust Test\""));
    assert!(dump.contains("Section Header 0"));
    assert!(dump.contains("Library 0"));

    let xbgs = xbe
        .dump(&DumpOptions {
            xbgs: true,
            ..DumpOptions::default()
        })
        .unwrap();
    assert!(xbgs.contains("[Game-4D530001]"));
    assert!(xbgs.contains("KEY_SIG="));
}

#[test]
fn test_key_repair_and_signature_round_trip() {
    let mut xbe = Xbe::parse(fixture()).unwrap();
    assert!(!xbe.validate(KeyKind::Test).unwrap().is_valid());

    let report = xbe
        .repair(RepairOptions {
            key: KeyKind::Test,
            patch_xor_keys: true,
            generate_signature: true,
            ..RepairOptions::default()
        })
        .unwrap();
    assert!(report.is_valid());
    assert_eq!(xbe.decoded_entry_point(KeyKind::Test), 0);
    assert_eq!(xbe.decoded_kernel_thunk_table(KeyKind::Test), 0);

    let reparsed = Xbe::parse(xbe.into_bytes()).unwrap();
    assert!(reparsed.validate(KeyKind::Test).unwrap().is_valid());
}

#[test]
fn habibi_repair_updates_certificate_and_signs() {
    let mut xbe = Xbe::parse(fixture()).unwrap();
    let report = xbe
        .repair(RepairOptions {
            key: KeyKind::Habibi,
            patch_xor_keys: true,
            allow_all_media_and_regions: true,
            generate_signature: true,
        })
        .unwrap();
    assert!(report.is_valid());
    assert_eq!(xbe.certificate().media_types, 0x8000_00ff);
    assert_eq!(xbe.certificate().game_region, 0x8000_0007);
}

#[test]
fn microsoft_key_cannot_sign() {
    let mut xbe = Xbe::parse(fixture()).unwrap();
    let error = xbe
        .repair(RepairOptions {
            generate_signature: true,
            ..RepairOptions::default()
        })
        .unwrap_err();
    assert_eq!(error, Error::MissingPrivateKey);
}

#[test]
fn truncated_images_are_rejected_without_panicking() {
    let error = Xbe::parse(vec![0; 32]).unwrap_err();
    assert!(matches!(
        error,
        Error::Truncated {
            context: "XBE header"
        }
    ));
}

#[test]
fn legacy_cli_is_a_working_write_back_wrapper() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.xbe");
    fs::write(&input, fixture()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_xbe"))
        .current_dir(directory.path())
        .arg(&input)
        .arg("-sign")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("File out.xbe created"));
    let written = Xbe::parse(fs::read(directory.path().join("out.xbe")).unwrap()).unwrap();
    assert!(written.validate(KeyKind::Test).unwrap().is_valid());
}

fn fixture() -> Vec<u8> {
    const CERTIFICATE: usize = 0x178;
    const SECTIONS: usize = 0x348;
    const SECTION_NAME: usize = 0x380;
    const LIBRARY: usize = 0x388;
    const SECTION_DATA: usize = 0x400;

    let mut data = vec![0u8; 0x420];
    let image_size = data.len() as u32;
    data[..4].copy_from_slice(b"XBEH");
    put32(&mut data, 0x104, BASE);
    put32(&mut data, 0x108, 0x400);
    put32(&mut data, 0x10c, image_size);
    put32(&mut data, 0x110, 0x178);
    put32(&mut data, 0x114, 1_000_000_000);
    put32(&mut data, 0x118, BASE + CERTIFICATE as u32);
    put32(&mut data, 0x11c, 1);
    put32(&mut data, 0x120, BASE + SECTIONS as u32);
    put32(&mut data, 0x124, 1);
    put32(&mut data, 0x128, 0xa8fc_57ab);
    put32(&mut data, 0x158, 0x5b6d_40b6);
    put32(&mut data, 0x160, 1);
    put32(&mut data, 0x164, BASE + LIBRARY as u32);

    put32(&mut data, CERTIFICATE, 0x1d0);
    put32(&mut data, CERTIFICATE + 4, 1_000_000_001);
    put32(&mut data, CERTIFICATE + 8, 0x4d53_0001);
    for (index, unit) in "Rust Test".encode_utf16().enumerate() {
        data[CERTIFICATE + 0x0c + index * 2..CERTIFICATE + 0x0e + index * 2]
            .copy_from_slice(&unit.to_le_bytes());
    }
    put32(&mut data, CERTIFICATE + 0x9c, 2);
    put32(&mut data, CERTIFICATE + 0xa0, 1);
    data[CERTIFICATE + 0xb0..CERTIFICATE + 0xc0].copy_from_slice(&[0x11; 16]);
    data[CERTIFICATE + 0xc0..CERTIFICATE + 0xd0].copy_from_slice(&[0x22; 16]);

    put32(&mut data, SECTIONS, 5);
    put32(&mut data, SECTIONS + 4, 0x0001_1000);
    put32(&mut data, SECTIONS + 8, 0x20);
    put32(&mut data, SECTIONS + 0x0c, SECTION_DATA as u32);
    put32(&mut data, SECTIONS + 0x10, 0x20);
    put32(&mut data, SECTIONS + 0x14, BASE + SECTION_NAME as u32);
    put32(&mut data, SECTIONS + 0x18, 1);
    data[SECTION_NAME..SECTION_NAME + 6].copy_from_slice(b".text\0");
    data[LIBRARY..LIBRARY + 8].copy_from_slice(b"XAPILIB\0");
    data[LIBRARY + 8..LIBRARY + 10].copy_from_slice(&1u16.to_le_bytes());
    data[LIBRARY + 10..LIBRARY + 12].copy_from_slice(&2u16.to_le_bytes());
    data[LIBRARY + 12..LIBRARY + 14].copy_from_slice(&3u16.to_le_bytes());
    data[SECTION_DATA..SECTION_DATA + 0x20].copy_from_slice(&[0x90; 0x20]);
    data
}

fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
