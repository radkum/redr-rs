mod header;
mod quarantine;
mod unquarantine;

use shared::{RedrResult, quarantine::QuarantineInfo, sha_buf::Sha256Buff};
use std::path::Path;

pub async fn quarantine_file(
    file_path: &std::path::Path,
    database: database::Database,
) -> shared::RedrResult<()> {
    let quarantine_info = quarantine::quarantine(file_path).await?;
    database.save_quarantine_entry(quarantine_info).await?;
    Ok(())
}

pub async fn unquarantine_file(
    file_sha: String,
    database: database::Database,
) -> shared::RedrResult<bool> {
    let file_sha = hex::decode(file_sha)?;
    let sha = Sha256Buff::from_vec(file_sha)?;
    let quarantine_info = database.get_quarantine_entry(&sha).await?;
    let result = unquarantine::unquarantine_file(quarantine_info)?;
    if result {
        database.delete_quarantine_entry(&sha).await?;
    }
    Ok(result)
}

pub fn delete_file(file_path: &Path) -> RedrResult<()> {
    std::fs::remove_file(file_path).map_err(|err| format!("Failed to delete file: {err}"))?;
    Ok(())
}
