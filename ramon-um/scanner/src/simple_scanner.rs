use std::{collections::VecDeque, sync::Arc};

use ansi_term::{Colour::Red, Style};
use common_um::redr;
use signatures::sig_store::SignatureStore;

use crate::{error::ScanError, scan_one_file::scan_one_file, scan_result::ScanResult};

pub fn simple_scan_files(
    files_queue: VecDeque<redr::FileReaderAndInfo>,
    signature_store: SignatureStore,
) -> Result<(), ScanError> {
    let _ = ansi_term::enable_ansi_support();

    let sig_store = Arc::new(signature_store);

    for file in files_queue {
        log::debug!("Start scanning file");

        if let ScanResult::Malicious(info, _c) = scan_one_file(file, sig_store.clone())? {
            println!(
                "{} - {}",
                Red.paint("MALWARE"),
                Style::new().bold().paint(info.into_string())
            );
        }
    }
    Ok(())
}
