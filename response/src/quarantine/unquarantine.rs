use std::fs::read_dir;
use std::path::{Path, PathBuf};

use log::{debug, info};
use shared::RedrResult;

use super::header::QuarantineHeader;

pub fn unquarantine_by_path<P: AsRef<Path>>(requested_path: P) -> RedrResult<bool> {
    let path_str = requested_path.as_ref().to_string_lossy();
    info!("Starting unquarantine by path: {}", path_str);

    let quarantine_dir = super::quarantine_dir()?;
    debug!("Scanning quarantine directory: {:?}", quarantine_dir);

    let mut files_checked = 0;
    let paths = read_dir(&quarantine_dir)
        .map_err(|err| format!("Failed to read quarantine directory: {err}"))?;

    for entry in paths.into_iter().flatten() {
        let quarantine_path = entry.path();
        files_checked += 1;
        debug!("Checking quarantine file: {:?}", quarantine_path);

        // Check if file has expected quarantine extension
        let has_ext = quarantine_path
            .extension()
            .map(|ext| ext.to_str() == Some(QuarantineHeader::ext()))
            .unwrap_or(false);

        if !has_ext {
            debug!(
                "File does not have expected quarantine extension, skipping: {:?}",
                quarantine_path
            );
            continue;
        }

        let header = match QuarantineHeader::read_from_path(&quarantine_path) {
            Ok(h) => h,
            Err(e) => {
                debug!(
                    "Failed to read header, skipping file: {:?} - {}",
                    quarantine_path, e
                );
                continue;
            }
        };

        let header_path = header.original_path();

        // Check if paths match
        if requested_path.as_ref() == header_path {
            info!("Path match found, starting unquarantine");
            return unquarantine_internal(quarantine_path, header);
        } else {
            debug!(
                "Path mismatch - requested: {:?}, header: {:?}",
                requested_path.as_ref(),
                header_path
            );
        }
    }

    info!(
        "No matching quarantine file found after checking {} files",
        files_checked
    );
    Ok(false)
}

fn unquarantine_internal(quarantine_path: PathBuf, header: QuarantineHeader) -> RedrResult<bool> {
    let original_path = header.original_path();
    info!("Restoring file to: {:?}", original_path);

    // Copy file back to original location
    std::fs::copy(&quarantine_path, original_path)
        .map_err(|e| format!("Failed to restore file: {e}"))?;

    // Delete quarantine file
    std::fs::remove_file(&quarantine_path)
        .map_err(|e| format!("Failed to delete quarantine file: {e}"))?;

    info!("Successfully unquarantined file: {:?}", original_path);
    Ok(true)
}
