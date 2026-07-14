# extract-xiso

An unsafe-free Rust library and command-line tool for working with the XDVDFS
images used by original Xbox discs.

## Features

- Creates, extracts, lists, and rewrites XISO images.
- Reads game-partition, redump-style, XGD1, and XGD3 dumps.
- Optionally patches XBE media flags while creating or rewriting an image.
- Rejects unsafe paths and malformed directory structures.

## Usage

```text
extract-xiso -c <directory> [output.iso]
extract-xiso -l <image.iso>...
extract-xiso -r <image.iso>...
extract-xiso -x <image.iso> [-d directory]
```

Extraction is the default when no mode flag is supplied. The `extract_xiso`
library exposes the same operations without printing to the terminal.

## Development

```console
cargo build -p extract-xiso --release
cargo test -p extract-xiso
```

Rust 1.85 or newer is required.

## Origin and license

This is a Rust rewrite of the original
[XboxDev/extract-xiso](https://github.com/XboxDev/extract-xiso), created by
*in* <in@fishtank.com>. See [LICENSE.TXT](LICENSE.TXT) for the modified BSD
terms and [NOTICE.txt](NOTICE.txt) for attribution.
