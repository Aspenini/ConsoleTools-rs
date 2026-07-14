//! Smoke tests for the command-line frontend's library wiring.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use extract_xiso::format;

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("extract-xiso-cli-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_extract-xiso"))
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn create_list_extract_and_rewrite() {
    let root = scratch();
    let fixture = root.join("fixture");
    fs::create_dir_all(fixture.join("sub")).unwrap();
    fs::write(fixture.join("hello.txt"), b"hello\n").unwrap();
    fs::write(fixture.join("sub/data.bin"), [1, 2, 3, 4]).unwrap();

    let created = run(&root, &["-c", "fixture", "game.iso"]);
    assert!(
        created.status.success(),
        "create failed:\n{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(root.join("game.iso").is_file());

    let listed = run(&root, &["-l", "game.iso"]);
    assert!(listed.status.success());
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("hello.txt (6 bytes)"));
    assert!(listing.contains("data.bin (4 bytes)"));

    let extracted = run(&root, &["-x", "-d", "out", "game.iso"]);
    assert!(
        extracted.status.success(),
        "extract failed:\n{}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(fs::read(root.join("out/hello.txt")).unwrap(), b"hello\n");
    assert_eq!(
        fs::read(root.join("out/sub/data.bin")).unwrap(),
        [1, 2, 3, 4]
    );

    // Clear the optimized tag so the CLI exercises its rewrite path.
    let iso = root.join("game.iso");
    let mut bytes = fs::read(&iso).unwrap();
    bytes[format::OPTIMIZED_TAG_OFFSET as usize
        ..format::OPTIMIZED_TAG_OFFSET as usize + format::OPTIMIZED_TAG_LENGTH]
        .fill(0);
    fs::write(&iso, bytes).unwrap();

    let rewritten = run(&root, &["-r", "-D", "game.iso"]);
    assert!(
        rewritten.status.success(),
        "rewrite failed:\n{}",
        String::from_utf8_lossy(&rewritten.stderr)
    );
    assert!(root.join("game.iso").is_file());
    assert!(!root.join("game.iso.old").exists());

    let _ = fs::remove_dir_all(&root);
}
