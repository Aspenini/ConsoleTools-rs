# xbedump

`xbedump` is an unsafe-free Rust library and command-line tool for inspecting,
validating, repairing, and signing original Xbox XBE executables. The installed
command retains the historical `xbe` name and flags.

## Features

- Parses XBE headers, certificates, sections, and linked libraries.
- Validates signatures and section hashes with supported historical keys.
- Repairs hashes, media and region fields, and supported signatures.
- Produces traditional text dumps and XBGS configuration output.

## Usage

```text
xbe <file.xbe> [options]
```

Common options include `-da` to dump all structures, `-vh` to validate, `-wb`
to repair hashes, `-sign` or `-habibi` to sign, and `?` for help. The `xbedump`
library exposes the same parsing, validation, repair, and rendering operations.

## Development

```console
cargo build -p xbedump --release
cargo test -p xbedump
```

Rust 1.85 or newer is required.

## Origin and license

This is a Rust rewrite of the historical
[XboxDev/xbedump](https://github.com/XboxDev/xbedump) codebase. Its legacy
cryptography exists only for compatibility with the XBE format. See
[LICENSE.txt](LICENSE.txt) for the applicable license terms and exception
notice.
