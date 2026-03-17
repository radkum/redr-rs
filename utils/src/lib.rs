pub mod detection_report;
pub mod encryption;
pub mod redr;
pub mod sha256_utils;
pub mod windows;

use std::{
    path::{Path, PathBuf},
    sync::LazyLock,
};

static REDR_PROGRAM_DATA_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    PathBuf::from(std::env::var("PROGRAMDATA").unwrap_or("C:\\ProgramData".to_string()))
        .join("redr")
});

static REDR_DATABASE_PATH: LazyLock<PathBuf> =
    LazyLock::new(|| REDR_PROGRAM_DATA_DIR.join("data.db"));

static REDR_QUARANTINE_DIR: LazyLock<PathBuf> =
    LazyLock::new(|| REDR_PROGRAM_DATA_DIR.join("quarantine"));

#[inline]
pub fn redr_program_data() -> &'static Path {
    if !REDR_PROGRAM_DATA_DIR.exists() {
        std::fs::create_dir_all(REDR_PROGRAM_DATA_DIR.as_path())
            .expect("Failed to create program data directory");
    }
    REDR_PROGRAM_DATA_DIR.as_ref()
}

#[inline]
pub fn redr_quarantine_dir() -> &'static Path {
    if !REDR_PROGRAM_DATA_DIR.exists() {
        std::fs::create_dir_all(REDR_PROGRAM_DATA_DIR.as_path())
            .expect("Failed to create program data directory");
    }
    if !REDR_QUARANTINE_DIR.exists() {
        std::fs::create_dir_all(REDR_QUARANTINE_DIR.as_path())
            .expect("Failed to create quarantine directory");
    }
    REDR_QUARANTINE_DIR.as_ref()
}

#[inline]
pub fn redr_database_path() -> &'static Path {
    if !REDR_PROGRAM_DATA_DIR.exists() {
        std::fs::create_dir_all(REDR_PROGRAM_DATA_DIR.as_path())
            .expect("Failed to create program data directory");
    }
    REDR_DATABASE_PATH.as_ref()
}
