use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use log::{debug, info};
use rkyv::rancor::Error;
use sha2::{Digest, Sha256};
use shared::sha_buf::Sha256Buff;
use shared::RedrResult;

use super::header::QuarantineHeader;

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
pub fn unquarantine_file(quarantine_path: &Path, original_path: &Path) -> RedrResult<bool> {
    info!(
        "Starting unquarantine: {} -> {}",
        quarantine_path.display(),
        original_path.display()
    );

    // Open the quarantine file
    let mut quar_file = File::open(quarantine_path)
        .map_err(|err| format!("Failed to open quarantine file: {err}"))?;

    // Read header - first we need to read the whole file to deserialize the header with rkyv
    let mut header_data = [0u8; size_of::<QuarantineHeader>()];
    quar_file.read_exact(&mut header_data)?;

    // Deserialize header from the beginning
    // rkyv serializes the header, so we need to figure out header size
    // For now, try to deserialize and then read remaining bytes as encrypted content
    let header = rkyv::from_bytes::<QuarantineHeader, Error>(&header_data)
        .map_err(|err| format!("Failed to deserialize quarantine header: {err}"))?;

    // Create output file
    let mut output_file = File::create(original_path)
        .map_err(|err| format!("Failed to create output file: {err}"))?;

    // Decrypt content (XOR decryption is same as encryption) and calculate SHA256
    let mut hasher = Sha256::new();
    let hasher = header.hasher();

    let calculated_sha = utils::encryption::decrypt_file(quar_file, output_file, header.key().as_ref(), Some(&mut hasher))?;

    if calculated_sha != header.sha {
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