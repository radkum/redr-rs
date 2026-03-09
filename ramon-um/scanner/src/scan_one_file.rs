use std::{
    collections::VecDeque,
    io::{Seek, SeekFrom::Start},
    sync::Arc,
};

use cleaner::cleaner::Cleaner;
use common_um::redr;
use signatures::sig_store::SignatureStore;

use crate::{scan_result::ScanResult, ScanError};

pub(crate) fn scan_one_file(
    file: redr::FileReaderAndInfo,
    signature_store: Arc<SignatureStore>,
) -> Result<ScanResult, ScanError> {
    let (mut reader, file_scan_info) = file;
    let scan_result = signature_store.eval_file(&mut reader)?;

    if let Some(detection_report) = scan_result {
        let res = ScanResult::Malicious(
            file_scan_info.get_malware_info(detection_report),
            Cleaner::File(file_scan_info.get_path()),
        );
        return Ok(res);
    }

    //set file pointer to 0 to be sure we read from the file beginning
    reader.seek(Start(0))?;

    let mut files_queue = VecDeque::<redr::FileReaderAndInfo>::new();

    //unpack and add files to the scanning queue
    let res = arcom::unpack_file(reader, file_scan_info.get_origin_file(), &mut files_queue);
    if let Err(e) = res {
        log::warn!("{e}");
    }

    scan_embedded_files(&mut files_queue, signature_store)
}

fn scan_embedded_files(
    files_queue: &mut VecDeque<redr::FileReaderAndInfo>,
    signature_store: Arc<SignatureStore>,
) -> Result<ScanResult, ScanError> {
    const MAX_FILE_TO_SCAN: usize = 0x100;

    let _ = ansi_term::enable_ansi_support();

    for i in 1..MAX_FILE_TO_SCAN + 1 {
        if let Some((mut reader, file_scan_info)) = files_queue.pop_front() {
            log::debug!("Start scanning {i} file");

            let scan_result = signature_store.eval_file(&mut reader)?;

            if let Some(detection_info) = scan_result {
                let res = ScanResult::Malicious(
                    file_scan_info.get_malware_info(detection_info),
                    Cleaner::File(file_scan_info.get_path()),
                );
                return Ok(res);
            }

            //set file pointer to 0 to be sure we read from the file beginning
            reader.seek(Start(0))?;

            //unpack and add files to the scanning queue
            let res = arcom::unpack_file(reader, file_scan_info.get_origin_file(), files_queue);
            if let Err(e) = res {
                log::warn!("{e}");
            }
        }
    }
    Ok(ScanResult::Clean)
}
