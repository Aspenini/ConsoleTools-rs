//! End-to-end tests: create an image from a fixture tree, inspect it,
//! extract it, and rewrite it, verifying the results at each step.

use std::fs;
use std::path::{Path, PathBuf};

use extract_xiso::{
    CreateOptions, Event, ExtractOptions, XisoImage, create_image, format, is_image_optimized,
};

/// A unique scratch directory under the system temp dir.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("extract-xiso-test-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Deterministic pseudo-random bytes.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

fn build_fixture(dir: &Path) {
    fs::create_dir_all(dir.join("sub/deeper")).unwrap();
    fs::create_dir_all(dir.join("emptydir")).unwrap();
    fs::write(dir.join("small.txt"), b"hello xiso\n").unwrap();
    fs::write(dir.join("zero.dat"), b"").unwrap();
    fs::write(dir.join("exact.bin"), noise(2048, 7)).unwrap();
    fs::write(dir.join("sub/data.bin"), noise(100_000, 11)).unwrap();
    fs::write(dir.join("sub/deeper/deep.txt"), b"deep file\n").unwrap();

    // A fake .xbe containing two media-check patterns.
    let mut xbe = noise(50_000, 13);
    xbe[1000..1008].copy_from_slice(format::MEDIA_ENABLE_PATTERN);
    xbe[40_000..40_008].copy_from_slice(format::MEDIA_ENABLE_PATTERN);
    fs::write(dir.join("default.xbe"), &xbe).unwrap();
}

#[test]
fn create_list_extract_rewrite_roundtrip() {
    let root = scratch("roundtrip");
    let fixture = root.join("fixture");
    build_fixture(&fixture);

    // Create.
    let iso = root.join("test.iso");
    let summary = create_image(&fixture, &iso, &CreateOptions::default(), &mut |_| {}).unwrap();
    assert_eq!(summary.files, 6);
    assert!(is_image_optimized(&iso).unwrap());

    // The image must be padded to the 64 KiB file modulus.
    let len = fs::metadata(&iso).unwrap().len();
    assert_eq!(len % format::FILE_MODULUS, 0);

    // List: all entries present, case-insensitive order within each dir.
    let mut image = XisoImage::open(&iso).unwrap();
    assert!(image.is_optimized());
    assert!(!image.is_empty());
    assert_eq!(image.disc_offset(), 0);
    let entries = image.entries().unwrap();
    let paths: Vec<String> = entries.iter().map(|e| e.path_with_separator('/')).collect();
    assert_eq!(
        paths,
        [
            "default.xbe",
            "emptydir",
            "exact.bin",
            "small.txt",
            "sub",
            "sub/data.bin",
            "sub/deeper",
            "sub/deeper/deep.txt",
            "zero.dat",
        ]
    );
    let deep = entries.iter().find(|e| e.name == "deep.txt").unwrap();
    assert_eq!(deep.dir_components, ["sub", "deeper"]);
    assert_eq!(deep.size, 10);
    assert!(!deep.is_directory);

    // Extract and compare with the fixture.
    let out = root.join("extracted");
    fs::create_dir_all(&out).unwrap();
    let mut events = 0usize;
    let summary = image
        .extract_to(&out, &ExtractOptions::default(), &mut |e| {
            if matches!(e, Event::ExtractFileEnd) {
                events += 1;
            }
        })
        .unwrap();
    assert_eq!(summary.files, 6);
    assert_eq!(events, 6);

    // Unpatched files round-trip exactly.
    for f in [
        "small.txt",
        "zero.dat",
        "exact.bin",
        "sub/data.bin",
        "sub/deeper/deep.txt",
    ] {
        assert_eq!(
            fs::read(out.join(f)).unwrap(),
            fs::read(fixture.join(f)).unwrap(),
            "{f} did not round-trip"
        );
    }
    assert!(out.join("emptydir").is_dir());

    // The .xbe media checks must be patched at both sites.
    let patched = fs::read(out.join("default.xbe")).unwrap();
    let original = fs::read(fixture.join("default.xbe")).unwrap();
    assert_eq!(patched.len(), original.len());
    assert_eq!(
        patched[1000 + format::MEDIA_ENABLE_BYTE_POS],
        format::MEDIA_ENABLE_BYTE
    );
    assert_eq!(
        patched[40_000 + format::MEDIA_ENABLE_BYTE_POS],
        format::MEDIA_ENABLE_BYTE
    );
    // ... and nothing else may differ.
    let diffs = patched
        .iter()
        .zip(&original)
        .filter(|(a, b)| a != b)
        .count();
    assert_eq!(diffs, 2);

    // Rewrite: the result must contain identical data.
    let rewritten = root.join("rewritten.iso");
    let summary = image
        .rewrite_to(&rewritten, &CreateOptions::default(), &mut |_| {})
        .unwrap();
    assert_eq!(summary.files, 6);

    let out2 = root.join("re-extracted");
    fs::create_dir_all(&out2).unwrap();
    let mut image2 = XisoImage::open(&rewritten).unwrap();
    image2
        .extract_to(&out2, &ExtractOptions::default(), &mut |_| {})
        .unwrap();
    for f in [
        "small.txt",
        "zero.dat",
        "exact.bin",
        "sub/data.bin",
        "sub/deeper/deep.txt",
        "default.xbe",
    ] {
        assert_eq!(
            fs::read(out2.join(f)).unwrap(),
            fs::read(out.join(f)).unwrap(),
            "{f} changed across rewrite"
        );
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn media_patching_can_be_disabled() {
    let root = scratch("no-patch");
    let fixture = root.join("fixture");
    fs::create_dir_all(&fixture).unwrap();
    let mut xbe = noise(10_000, 3);
    xbe[500..508].copy_from_slice(format::MEDIA_ENABLE_PATTERN);
    fs::write(fixture.join("default.xbe"), &xbe).unwrap();

    let iso = root.join("test.iso");
    create_image(
        &fixture,
        &iso,
        &CreateOptions::default().with_media_enable_patching(false),
        &mut |_| {},
    )
    .unwrap();

    let out = root.join("out");
    fs::create_dir_all(&out).unwrap();
    XisoImage::open(&iso)
        .unwrap()
        .extract_to(&out, &ExtractOptions::default(), &mut |_| {})
        .unwrap();
    assert_eq!(fs::read(out.join("default.xbe")).unwrap(), xbe);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn xbe_patching_across_chunk_boundary() {
    let root = scratch("straddle");
    let fixture = root.join("fixture");
    fs::create_dir_all(&fixture).unwrap();

    // Pattern straddling the 2 MiB copy-buffer boundary.
    let size = format::READWRITE_BUFFER_SIZE + 50_000;
    let mut xbe = noise(size, 17);
    let straddle = format::READWRITE_BUFFER_SIZE - 4;
    xbe[straddle..straddle + 8].copy_from_slice(format::MEDIA_ENABLE_PATTERN);
    fs::write(fixture.join("big.xbe"), &xbe).unwrap();

    let iso = root.join("test.iso");
    create_image(&fixture, &iso, &CreateOptions::default(), &mut |_| {}).unwrap();

    let out = root.join("out");
    fs::create_dir_all(&out).unwrap();
    XisoImage::open(&iso)
        .unwrap()
        .extract_to(&out, &ExtractOptions::default(), &mut |_| {})
        .unwrap();

    let patched = fs::read(out.join("big.xbe")).unwrap();
    assert_eq!(patched.len(), xbe.len());
    assert_eq!(
        patched[straddle + format::MEDIA_ENABLE_BYTE_POS],
        format::MEDIA_ENABLE_BYTE
    );
    let diffs = patched.iter().zip(&xbe).filter(|(a, b)| a != b).count();
    assert_eq!(diffs, 1);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn duplicate_names_are_rejected() {
    let root = scratch("dupes");
    let fixture = root.join("fixture");
    fs::create_dir_all(&fixture).unwrap();
    fs::write(fixture.join("File.dat"), b"a").unwrap();
    fs::write(fixture.join("fILE.DAT"), b"b").unwrap();

    let iso = root.join("test.iso");
    let result = create_image(&fixture, &iso, &CreateOptions::default(), &mut |_| {});

    // On case-insensitive filesystems the two names collapse into one
    // file and creation succeeds; on case-sensitive ones the collision
    // must be reported.
    if fs::read_dir(&fixture).unwrap().count() == 2 {
        assert!(matches!(
            result,
            Err(extract_xiso::Error::DuplicateFilename { .. })
        ));
        assert!(!iso.exists(), "failed create must remove its output");
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn open_rejects_non_images() {
    let root = scratch("notiso");
    let bogus = root.join("bogus.iso");
    fs::write(&bogus, noise(0x12000, 23)).unwrap();
    assert!(matches!(
        XisoImage::open(&bogus),
        Err(extract_xiso::Error::NotAnXiso { .. })
    ));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn rewrite_can_skip_system_update() {
    let root = scratch("rewrite-skip-update");
    let fixture = root.join("fixture");
    fs::create_dir_all(fixture.join("$SystemUpdate")).unwrap();
    fs::write(fixture.join("keep.txt"), b"keep").unwrap();
    fs::write(fixture.join("$SystemUpdate/remove.txt"), b"remove").unwrap();

    let original = root.join("original.iso");
    create_image(&fixture, &original, &CreateOptions::default(), &mut |_| {}).unwrap();

    let rewritten = root.join("rewritten.iso");
    XisoImage::open(&original)
        .unwrap()
        .rewrite_to(
            &rewritten,
            &CreateOptions::default().with_skip_system_update(true),
            &mut |_| {},
        )
        .unwrap();

    let paths: Vec<_> = XisoImage::open(&rewritten)
        .unwrap()
        .entries()
        .unwrap()
        .into_iter()
        .map(|entry| entry.path_with_separator('/'))
        .collect();
    assert_eq!(paths, ["keep.txt"]);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn rewrite_rejects_overwriting_its_source() {
    let root = scratch("same-rewrite-path");
    let fixture = root.join("fixture");
    fs::create_dir_all(&fixture).unwrap();
    fs::write(fixture.join("file.txt"), b"safe").unwrap();

    let iso = root.join("test.iso");
    create_image(&fixture, &iso, &CreateOptions::default(), &mut |_| {}).unwrap();
    let original = fs::read(&iso).unwrap();

    let result =
        XisoImage::open(&iso)
            .unwrap()
            .rewrite_to(&iso, &CreateOptions::default(), &mut |_| {});
    assert!(matches!(
        result,
        Err(extract_xiso::Error::SameInputAndOutput { .. })
    ));
    assert_eq!(fs::read(&iso).unwrap(), original);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn cyclic_directory_offsets_are_rejected() {
    let root = scratch("cyclic-directory");
    let fixture = root.join("fixture");
    fs::create_dir_all(&fixture).unwrap();
    fs::write(fixture.join("a.txt"), b"a").unwrap();
    fs::write(fixture.join("b.txt"), b"b").unwrap();

    let iso = root.join("test.iso");
    create_image(&fixture, &iso, &CreateOptions::default(), &mut |_| {}).unwrap();

    let mut bytes = fs::read(&iso).unwrap();
    let root_start = format::ROOT_DIRECTORY_SECTOR as usize * format::SECTOR_SIZE as usize;
    let left = u16::from_le_bytes([bytes[root_start], bytes[root_start + 1]]);
    let right = u16::from_le_bytes([bytes[root_start + 2], bytes[root_start + 3]]);
    let child = if left != 0 { left } else { right };
    assert_ne!(child, 0, "two entries should produce a child node");
    let child_start = root_start + child as usize * format::DWORD_SIZE as usize;
    bytes[child_start..child_start + 2].copy_from_slice(&child.to_le_bytes());
    fs::write(&iso, bytes).unwrap();

    let result = XisoImage::open(&iso).unwrap().entries();
    assert!(matches!(
        result,
        Err(extract_xiso::Error::CorruptDirectoryTree)
    ));

    let _ = fs::remove_dir_all(&root);
}
