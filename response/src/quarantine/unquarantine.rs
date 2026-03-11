use std::fs::File;
use std::io::Read;
use std::path::Path;

use log::info;
use rkyv::rancor::Error;
use shared::RedrResult;

use super::header::QuarantineHeader;
use shared::sha_buf::Sha256Buff;
/// Unquarantine a file, restoring it to the original path
/// 
/// # Arguments
/// * `quarantine_path` - Path to the quarantined file (.qrt file)
/// * `original_path` - Path where the restored file should be written
/// 
/// # Returns
/// * `Ok(true)` - File was successfully unquarantined
/// * `Ok(false)` - File could not be unquarantined (e.g., SHA mismatch)
/// * `Err` - An error occurred
pub fn unquarantine_file(quarantine_path: &Path, original_path: &Path, key: &Sha256Buff) -> RedrResult<bool> {
    info!(
        "Starting unquarantine: {} -> {}",
        quarantine_path.display(),
        original_path.display()
    );

    // Open the quarantine file
    let mut quar_file = File::open(quarantine_path)
        .map_err(|err| format!("Failed to open quarantine file: {err}"))?;

    // Read header - first we need to read the whole file to deserialize the header with rkyv
    let mut header_data = [0u8; QuarantineHeader::header_size()];
    quar_file.read_exact(&mut header_data)?;

    // Deserialize header from the beginning
    // rkyv serializes the header, so we need to figure out header size
    // For now, try to deserialize and then read remaining bytes as encrypted content
    let header = rkyv::from_bytes::<QuarantineHeader, Error>(&header_data)
        .map_err(|err| format!("Failed to deserialize quarantine header: {err}"))?;

    // Create output file
    let output_file = File::create(original_path)
        .map_err(|err| format!("Failed to create output file: {err}"))?;

    log::debug!("Header deserialized successfully");
    // Decrypt content and calculate SHA256
    let hasher = header.hasher();

    let calculated_sha = utils::encryption::decrypt_file(quar_file, output_file, header.key().as_ref(), Some(hasher))?;

    if calculated_sha.as_slice() != header.sha.as_ref() {
        // SHA mismatch - delete the output file and return false
        log::warn!(
            "SHA256 mismatch! Expected: {:?}, Got: {:?}",
            header.sha,
            calculated_sha
        );
        std::fs::remove_file(original_path).ok(); // Best effort cleanup
        return Ok(false);
    }

    info!(
        "Successfully unquarantined file: {} -> {}",
        quarantine_path.display(),
        original_path.display()
    );

    // Optionally delete the quarantine file after successful restore
    // Uncomment if desired:
    std::fs::remove_file(quarantine_path)?;

    Ok(true)
}