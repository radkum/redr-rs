use std::{
    fs::File,
    path::Path,
};

use log::{debug, info};
use shared::{RedrResult, quarantine::QuarantineInfo, sha_buf::Sha256Buff};

use super::header::QuarantineHeader;

pub async fn quarantine(path: &Path) -> RedrResult<QuarantineInfo> {
    let mut header = QuarantineHeader::new();
    if !path.exists() {
        return Err(format!("Path {} does not exist", path.display()).into());
    }
    info!("Starting quarantining file: {}", path.display());

    let input_file = File::open(path)
        .map_err(|err| format!("Failed to open original file {}: {err}", path.display()))?;

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
    let hasher = header.hasher();

    let sha = utils::encryption::encrypt_file(
        input_file,
        output_file,
        header.key().as_slice(),
        Some(hasher),
    )
    .await?;
    header.sha = Sha256Buff::from_vec(sha)
        .map_err(|err| format!("Failed to create SHA256 buffer: {err}"))?;

    // Delete the original file
    if let Err(err) = super::delete_file(path) {
        //if it fails, delete quarantine file
        super::delete_file(&quar_path)?;
        return Err(err);
    }

    log::info!(
        "Successfully quarantined file: {}\nsha: {}",
        path.display(),
        header.sha
    );
    Ok(header.quarantine_info(path, &quar_path))
}
