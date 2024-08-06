pub mod error;
mod scanner;
pub mod simple_scanner;

use std::collections::VecDeque;

use common_um::redr::FileReaderAndInfo;
pub use scanner::Scanner;
use signatures::sig_store::SignatureStore;
pub use simple_scanner::simple_scan_files;

use crate::error::ScanError;

#[tokio::main]
pub async fn user_mode_async_scan_files(
    sig_store: SignatureStore,
    queue: VecDeque<FileReaderAndInfo>,
) -> Result<(), ScanError> {
    let mut scanner = Scanner::new(sig_store);

    for s in queue {
        scanner.process_file(s).await?;
    }
    scanner.scan_report().await?;
    Ok(())
}
