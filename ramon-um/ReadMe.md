# REDR - Rust Endpoint, Detection and Response

TODO Description

### How to run:
##### HELP
###### cargo build
###### cargo run -- help
###### cargo run -- signature --help
###### cargo run -- evaluate --help

##### OTHER
###### cargo run -- signature compile  --dir signatures -o malset.sset
###### cargo run -- -lllll signature compile  --dir signatures -o malset.sset
###### cargo run -- evaluate -s .\malset.sset ..\malset\Watacat\
###### cargo run -- sandbox -s .\malset.sset ..\malset\Watacat\Wacatac_behavioral_detection.exe
###### cargo run -- start-detection -s .\malset.sset

todo:
- proper sandbox