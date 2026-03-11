pub mod detection_report;
pub mod encryption;
pub mod redr;
pub mod sha256_utils;
use std::path::Path;
use std::{path::PathBuf, sync::LazyLock};

static REDR_PROGRAM_DATA_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    PathBuf::from(std::env::var("PROGRAMDATA").unwrap_or("C:\\ProgramData".to_string())).join("redr")
});

static REDR_DATABASE_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    REDR_PROGRAM_DATA_DIR.join("data.db")
});

static REDR_QUARANTINE_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    REDR_PROGRAM_DATA_DIR.join("quarantine")
});

#[inline]
pub fn redr_program_data() -> &'static Path {
    REDR_PROGRAM_DATA_DIR.as_ref()
}

#[inline]
pub fn redr_quarantine_dir() -> &'static Path {
    REDR_QUARANTINE_DIR.as_ref()
}

#[inline]
pub fn redr_database_path() -> &'static Path {
    REDR_DATABASE_PATH.as_ref()
}