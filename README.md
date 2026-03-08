# redr-rs
Rust Endpoint, Detection and Response

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