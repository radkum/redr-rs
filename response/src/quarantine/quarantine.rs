use log::{debug, error, info};
use shared::RedrResult;
use std::fs::File;
use std::path::Path;

use super::header::QuarantineHeader;

impl QuarantineHeader {
    pub fn quarantine(path: &Path) -> RedrResult<Self> {
        let mut header = Self::new();
        if !path.exists() {
            return Err(format!("Path {} does not exist", path.display()).into());
        }
        info!("Starting quarantineing file: {}", path.display());

        let input_file = File::open(path).map_err(|err| {
            format!("Failed to open original file {}: {err}", path.display()).into()
        })?;

        // Check quarantine directory
        let quar_path = header.quarantine_path(path)?;
        info!("Creating quarantine file: {}", quar_path.display());
        let mut output_file = File::create(&quar_path)
            .map_err(|err| format!("Failed to create quarantine file: {err}").into())?;

        debug!("Starting file encryption and hashing");
        header
            .serialize_to_file(&mut output_file)
            .map_err(|err| format!("Could not write header to file: {err}").into())?;

        // Encrypt file and get sha256 hash of original file
        let hasher = self.hasher();
        let sha256 = shared::encryption::encrypt_file(
            input_file,
            output_file,
            header.key().as_bytes(),
            Some(hasher),
        )
        .map_err(|err| format!("Could not encrypt file: {err}").into())?;

        // Delete the original file
        super::delete_file(&path)?;

        header.sha = Sha256Buff::from_vec(sha256);

        log::info!("Successfully quarantined file: {}", path.display());
        Ok(header)
    }
}
