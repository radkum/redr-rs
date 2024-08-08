# redr-rs
Rust Endpoint, Detection and Response

### Directory hierarchy
**redr-km** - kernel part of redr. Ramon minifilter and other drivers

**redr-um** - user mode part of redr. Signatures, scanner, unpacker, sandbox, etc

**common** - shared info between driver and client, like ioctl codes


###TODO
 - ramon-um - convert to service
 - create script to install a whole AV