# stfschk

`stfschk` is a Rust library and command-line verifier for Xbox 360 STFS/XContent
packages.

## Features

- Checks CON, LIVE, and PIRS headers, signatures, metadata, and hash tables.
- Validates block chains, allocation counts, truncation, and content paths.
- Accepts one package or recursively checks a directory.
- Exposes parsed metadata and structured verification results through a library.

## Usage

```text
stfschk [-h] <package-or-directory>
```

The `-h` flag includes parsed headers in the report. The checker is read-only;
invalid packages receive a sibling `.bad` report.

## Development

```console
cargo build -p stfschk --release
cargo test -p stfschk
```

Rust 1.85 or newer is required.

## Origin and license

This is a Rust rewrite of
[emoose/xbox-reversing's stfschk](https://github.com/emoose/xbox-reversing/tree/master/stfschk),
with format research and keys originating in that project and
[xbox-winfsp](https://github.com/emoose/xbox-winfsp). See
[LICENSE.txt](LICENSE.txt) for the BSD 3-Clause terms.
