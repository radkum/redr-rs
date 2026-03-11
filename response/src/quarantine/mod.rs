mod header;
mod quarantine;
mod unquarantine;

use database::Database;
use shared::RedrResult;
use std::path::{Path, PathBuf};

use header::QuarantineHeader;

pub async fn quarantine_file(file_path: &Path, database: Database) -> RedrResult<()> {
    let quarantine_info = quarantine::quarantine(file_path)?;
    database.save_quarantine_entry(quarantine_info).await?;
    Ok(())
}

fn quarantine_dir_name() -> RedrResult<PathBuf> {
    let exe_path =
        std::env::current_exe().map_err(|e| format!("Failed to get current exe path: {e}"))?;
    let quarantine_dir = exe_path
        .parent()
        .ok_or("Failed to get parent directory")?
        .join("quarantine");
    if !quarantine_dir.exists() {
        std::fs::create_dir_all(&quarantine_dir)
            .map_err(|err| format!("Failed to create quarantine directory: {err}"))?;
    }
    Ok(quarantine_dir)
}

pub fn delete_file(file_path: &Path) -> RedrResult<()> {
    std::fs::remove_file(file_path).map_err(|err| format!("Failed to delete file: {err}"))?;
    Ok(())
}
