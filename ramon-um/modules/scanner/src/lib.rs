pub mod error;
pub mod simple_scanner;
mod scanner;

use std::collections::VecDeque;
use common_um::redr::FileReaderAndInfo;
pub use simple_scanner::simple_scan_files;

pub use scanner::Scanner;
use signatures::sig_store::SignatureStore;

#[tokio::main]
pub async fn user_mode_async_scan_files(sig_store: SignatureStore, queue: VecDeque<FileReaderAndInfo>) {
    let mut scanner = Scanner::new(sig_store);

    for s in queue {
        scanner.process_file(s).await.unwrap();
    }
    //scanner.scan_report().await.unwrap();
}