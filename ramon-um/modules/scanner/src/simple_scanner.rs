use std::{
    collections::VecDeque,
    io::{Seek, SeekFrom::Start},
};

use ansi_term::Colour::Red;
use common_um::redr;
use signatures::sig_store::SignatureStore;

use crate::error::ScanError;

const MAX_FILE_TO_SCAN: usize = 0x100;

pub fn simple_scan_files(
    files_queue: &mut VecDeque<redr::FileReaderAndInfo>,
    signature_store: SignatureStore,
) -> Result<(), ScanError> {
    let _ = ansi_term::enable_ansi_support();

    for i in 1..MAX_FILE_TO_SCAN + 1 {
        if let Some((mut reader, file_scan_info)) = files_queue.pop_front() {
            log::debug!("Start scanning {i} file");

            let scan_result = signature_store.eval_file(&mut reader)?;

            if let Some(detection_info) = scan_result {
                //todo: do some action with detection info
                println!(
                    "{} - {}",
                    Red.paint("MALICIOUS"),
                    file_scan_info.get_malware_info(detection_info)
                );
                continue;
            }
            //println!("{} - \"{}\"", Green.paint("CLEAN"), file_scan_info.get_name());
            //let name = variant.get_name();
            //println!("{}", &name);
            //set.insert(name, detection);

            //set file pointer to 0 to be sure we read from the file beginning
            reader.seek(Start(0))?;

            //unpack and add files to the scanning queue
            let res = arcom::unpack_file(reader, file_scan_info.get_origin_file(), files_queue);
            if let Err(e) = res {
                log::warn!("{e}");
            }
        }
    }
    Ok(())
}
