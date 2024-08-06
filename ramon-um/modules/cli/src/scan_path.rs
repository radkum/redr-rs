use std::{collections::VecDeque, fs::File, path::Path};

use common_um::redr;
use scanner::user_mode_async_scan_files;

#[allow(unused)]
pub(super) fn scan_path(target_path: &str, store_path: String) -> anyhow::Result<()> {
    log::debug!("scan_path: {}", target_path);
    let sig_store = signatures::deserialize_sig_store_from_path(store_path.as_str())?;

    let path = std::path::Path::new(target_path);
    let mut queue = VecDeque::new();

    create_file_queue(path, &mut queue)?;

    scanner::simple_scan_files(&mut queue, sig_store)?;

    Ok(())
}

pub(super) fn async_scan_path(target_path: &str, store_path: String) -> anyhow::Result<()> {
    log::debug!("scan_path: {}", target_path);
    let sig_store = signatures::deserialize_sig_store_from_path(store_path.as_str())?;

    let path = std::path::Path::new(target_path);
    let mut queue = VecDeque::new();

    create_file_queue(path, &mut queue)?;

    user_mode_async_scan_files(sig_store, queue)?;

    Ok(())
}

fn create_file_queue(
    path: &Path,
    mut queue: &mut VecDeque<redr::FileReaderAndInfo>,
) -> anyhow::Result<()> {
    log::debug!("scan_path: {:?}", path);

    if path.is_file() {
        let file = File::open(path)?;
        let file_info = redr::FileScanInfo::real_file(path.into());
        let file_to_scan = (redr::FileReader::from_file(file), file_info);

        queue.push_back(file_to_scan);
    } else if path.is_dir() {
        let paths = std::fs::read_dir(path)?;

        for entry_res in paths {
            let entry = entry_res?;
            log::trace!("dir entry: {:?}", entry);

            create_file_queue(entry.path().as_path(), &mut queue)?;
        }
    } else {
        //other types are not supported
    }

    Ok(())
}
