# ConsoleTools-rs

Rust libraries and command-line tools for various console formats.

| Package | Binary | Purpose |
|---------|--------|---------|
| `extract-xiso` | `extract-xiso` | Create, extract, list, and rewrite Xbox XISO images |
| `orbis-unpkg` | `orbis-unpkg` | Inspect and extract PlayStation 4 PKG files |
| `stfschk` | `stfschk` | Verify Xbox 360 STFS/XContent packages |
| `xbedump` | `xbe` | Inspect, validate, repair, and sign Xbox XBE files |

```console
cargo build --workspace --release
cargo test --workspace
```

Each crate has a short usage guide and its own license file under `crates/`.
