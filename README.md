# redr-rs

An earlier endpoint-protection prototype in Rust: a Windows minifilter plus the user-mode pieces
around it (scanner, detection, response, signatures, local database). Kept as history.

> **RAMON:** the `ramon/` minifilter in this repository is an earlier iteration. The maintained
> editions are [`radkum/ramon-rs`](https://github.com/radkum/ramon-rs) (2026, AI-assisted) and
> [`radkum/ramon-rs-legacy`](https://github.com/radkum/ramon-rs-legacy) (2025, hand-written). Use
> those for the driver; this repository is the broader endpoint prototype around it.

## Layout

| Path | What it is |
|---|---|
| `ramon/` | the Windows minifilter (kernel, `no_std`, WDK; own `.cargo` config) |
| `ramon-um/` | user-mode side of the minifilter |
| `scanner/` | scanning |
| `detection/` | detection logic |
| `response/` | response actions |
| `signatures/` | signature data and format |
| `database/` | local database |
| `shared/` | types shared between the user-mode crates |
| `arcom/` | archive components (unpackers) |
| `utils/` | helpers |
| `cli/` | command-line entry point |
| `book/` | design notes |

The Cargo workspace at the root builds the user-mode crates (`cli`, `scanner`, `detection`,
`response`, `arcom`, `database`, `shared`, `utils`); the driver is built from `ramon/` with the WDK.

## Build

User-mode workspace:

```
cargo build
```

Driver (Windows + Visual Studio Build Tools + WDK + nightly Rust):

```
cd ramon
cargo build
```

## Status

Prototype, not maintained. No policy engine, no signing, no installer. The TODO list is left as it
was when the prototype stopped.

## TODO (as of the prototype)

- `actions-um` / `actions-km`
- use `rade-rs` in the kernel and in user mode
- AMSI, YARA, ELAM
- an installer
- `ramon-um` as a service

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
