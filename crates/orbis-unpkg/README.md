# orbis-unpkg

An unsafe-free Rust library and command-line tool for inspecting and extracting
PlayStation 4 PKG files.

## Features

- Displays PKG metadata and detects base games, updates, and DLC.
- Extracts one package or installs every package in a directory.
- Parses PFS and `param.sfo` data through the reusable `orbis_unpkg` library.
- Preserves the legacy extraction syntax and Windows drag-and-drop behavior.

## Usage

```text
orbis-unpkg <COMMAND>

Commands:
  extract     Extract a PKG file
  info        Display PKG metadata without extracting it
  check-type  Detect whether a PKG is a base game, update, or DLC
  install     Install one PKG, or every PKG directly inside a directory
  help        Print help for a command
```

```console
orbis-unpkg info game.pkg
orbis-unpkg extract game.pkg --output ./games
orbis-unpkg install ./packages --games-dir ./games --addons-dir ./addons
```

Run `orbis-unpkg help <command>` for all options. The legacy
`orbis-unpkg <file> [output]` extraction form remains supported.

The `orbis_unpkg` library provides PKG, PFS, PSF, file-type detection, and
progress-aware extraction APIs.

## Development

```console
cargo build -p orbis-unpkg --release
cargo test -p orbis-unpkg
```

Rust 1.85 or newer is required.

## Origin and license

This is a Rust rewrite of the standalone extractor derived from the ShadPS4
project. Portions are Copyright © 2024 shadPS4 Emulator Project; the Rust
rewrite is Copyright © 2026 Aspenini. See [LICENSE.txt](LICENSE.txt) for the
GPLv2 terms.
