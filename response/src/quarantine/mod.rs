mod header;
mod quarantine;
mod unquarantine;

use database::Database;
use shared::RedrResult;
use std::path::{Path, PathBuf};


pub async fn quarantine_file(file_path: &std::path::Path, database: database::Database) -> shared::RedrResult<()> {
    let quarantine_info = quarantine::quarantine(file_path).await?;
    database.save_quarantine_entry(quarantine_info).await?;
    Ok(())
}

pub async fn unquarantine_file(file_id: String, database: database::Database) -> shared::RedrResult<()> {
    let quarantine_info = database.get_quarantine_file(file_id).await?;
    let quarantine_info = unquarantine::unquarantine_file(quarantine_info).await?;
    database.save_quarantine_entry(quarantine_info).await?;
    Ok(())
}


pub fn delete_file(file_path: &Path) -> RedrResult<()> {
    std::fs::remove_file(file_path).map_err(|err| format!("Failed to delete file: {err}"))?;
    Ok(())
}
