mod header;
mod quarantine;
mod unquarantine;

use shared::RedrResult;
use std::path::{Path, PathBuf};

pub use header::QuarantineHeader;

fn quarantine_dir() -> RedrResult<PathBuf> {
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
