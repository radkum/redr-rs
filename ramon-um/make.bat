set OUTPUT_PATH=..\\output
set EXE_NAME=ramon-client

cargo +nightly fmt
cargo b

IF not exist %OUTPUT_PATH% (mkdir %OUTPUT_PATH%)
COPY target\\debug\\%EXE_NAME%.exe %OUTPUT_PATH%
COPY malset.sset %OUTPUT_PATH%