use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use log::{debug, info};
use sha2::{Digest, Sha256};
use shared::sha_buf::Sha256Buff;
use shared::RedrResult;

use super::header::QuarantineHeader;

impl QuarantineHeader {
    pub fn quarantine(path: &Path) -> RedrResult<Self> {
        let mut header = Self::new();
        if !path.exists() {
            return Err(format!("Path {} does not exist", path.display()).into());
        }
        info!("Starting quarantining file: {}", path.display());

        let mut input_file = File::open(path).map_err(|err| {
            format!("Failed to open original file {}: {err}", path.display())
        })?;

        // Check quarantine directory
        let quar_path = header.quarantine_path(path)?;
        info!("Creating quarantine file: {}", quar_path.display());
        let mut output_file = File::create(&quar_path)
            .map_err(|err| format!("Failed to create quarantine file: {err}"))?;

        debug!("Writing header");
        header
            .serialize_to_file(&mut output_file)
            .map_err(|err| format!("Could not write header to file: {err}"))?;

        debug!("Encrypting and hashing file content");
        // Simple XOR encryption with key and calculate SHA256 of original
        let mut hasher = Sha256::new();
        let key = header.key().as_ref();
        let mut buffer = [0u8; 4096];
        let mut key_idx = 0usize;

        loop {
            let bytes_read = input_file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            // Hash original data
            hasher.update(&buffer[..bytes_read]);

            // XOR encrypt
            for byte in &mut buffer[..bytes_read] {
                *byte ^= key[key_idx % key.len()];
                key_idx += 1;
            }

            output_file.write_all(&buffer[..bytes_read])?;
        }

        // Get the SHA256 hash
        let sha256_result = hasher.finalize();
        header.sha = Sha256Buff::from(sha256_result);

        // Delete the original file
        super::delete_file(path)?;

        log::info!("Successfully quarantined file: {}", path.display());
        Ok(header)
    }
}