# redr-rs
Rust Endpoint, Detection and Response

> **RAMON:** the `ramon/` minifilter in this repository is an earlier iteration. The maintained
> editions are [adkum/ramon-rs](https://github.com/radkum/ramon-rs) (2026, AI-assisted) and
> [adkum/ramon-rs-legacy](https://github.com/radkum/ramon-rs-legacy) (2025, hand-written).

### Directory hierarchy
**redr-km** - kernel part of redr. Ramon minifilter and other drivers

**redr-um** - user mode part of redr. Signatures, scanner, unpacker, sandbox, etc

**common** - shared info between driver and client, like ioctl codes


###TODO
 - add crate: actions-um
 - add crate: actions-km
 - use rade-rs in the kernel
 - use rade-rs in the um
 - add amsi
 - add yara rules
 - ramon-um - convert to service
 - add elam
 - add installer